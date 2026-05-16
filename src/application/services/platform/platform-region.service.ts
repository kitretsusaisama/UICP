import { Injectable, NotFoundException, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { ulid } from 'ulid';

export interface Region {
  id: string; name: string; code: string; location: string;
  status: 'active' | 'inactive' | 'maintenance'; primaryEndpoint: string;
  isPrimary: boolean; capacity: number; currentLoad: number;
  createdAt: Date; updatedAt: Date;
}

export interface GeoRoutingRule {
  id: string; countryCodes: string[]; regionCode: string;
  priority: number; isActive: boolean; createdAt: Date;
}

export interface FailoverRecord {
  id: string; regionId: string; targetRegionId: string; type: 'manual' | 'automatic';
  status: 'pending' | 'in_progress' | 'completed' | 'failed'; triggeredBy: string;
  triggeredAt: Date; completedAt: Date | null; metadata: Record<string, any>;
}

@Injectable()
export class PlatformRegionService {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async createRegion(input: { name: string; code: string; location: string; primaryEndpoint: string; isPrimary?: boolean; capacity?: number }): Promise<Region> {
    const id = ulid();
    const now = new Date();

    await this.pool.execute(
      `INSERT INTO regions (id, name, code, location, status, primary_endpoint, is_primary, capacity, current_load, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
      [id, input.name, input.code, input.location, 'active', input.primaryEndpoint, input.isPrimary || false, input.capacity || 1000, now, now]
    );

    return this.getRegionById(id);
  }

  async getRegionById(id: string): Promise<Region> {
    const [rows]: any = await this.pool.execute('SELECT * FROM regions WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Region not found');
    return this.mapRegionRow(rows[0]);
  }

  async getRegionByCode(code: string): Promise<Region | null> {
    const [rows]: any = await this.pool.execute('SELECT * FROM regions WHERE code = ?', [code]);
    return rows.length > 0 ? this.mapRegionRow(rows[0]) : null;
  }

  async listRegions(options: { status?: string; isPrimary?: boolean; limit?: number; offset?: number } = {}): Promise<{ regions: Region[]; total: number }> {
    const { status, isPrimary, limit = 50, offset = 0 } = options;
    let where = '1=1';
    const params: any[] = [];

    if (status) { where += ' AND status = ?'; params.push(status); }
    if (isPrimary !== undefined) { where += ' AND is_primary = ?'; params.push(isPrimary); }

    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM regions WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM regions WHERE ${where} ORDER BY is_primary DESC, name LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return { regions: rows.map((r: any) => this.mapRegionRow(r)), total: count[0].total };
  }

  async updateRegion(id: string, updates: Partial<{ name: string; location: string; primaryEndpoint: string; status: string; capacity: number }>): Promise<Region> {
    await this.getRegionById(id);
    const sets: string[] = [];
    const params: any[] = [];

    if (updates.name) { sets.push('name = ?'); params.push(updates.name); }
    if (updates.location) { sets.push('location = ?'); params.push(updates.location); }
    if (updates.primaryEndpoint) { sets.push('primary_endpoint = ?'); params.push(updates.primaryEndpoint); }
    if (updates.status) { sets.push('status = ?'); params.push(updates.status); }
    if (updates.capacity) { sets.push('capacity = ?'); params.push(updates.capacity); }

    sets.push('updated_at = NOW()');
    params.push(id);

    await this.pool.execute(`UPDATE regions SET ${sets.join(', ')} WHERE id = ?`, params);
    return this.getRegionById(id);
  }

  async setPrimaryRegion(id: string): Promise<Region> {
    const region = await this.getRegionById(id);
    await this.pool.execute('UPDATE regions SET is_primary = false WHERE is_primary = true');
    await this.pool.execute('UPDATE regions SET is_primary = true, updated_at = NOW() WHERE id = ?', [id]);
    return this.getRegionById(id);
  }

  async triggerFailover(regionId: string, targetRegionId: string, type: 'manual' | 'automatic', triggeredBy: string): Promise<FailoverRecord> {
    const failoverId = ulid();
    const now = new Date();

    await this.pool.execute(
      `INSERT INTO failover_records (id, region_id, target_region_id, type, status, triggered_by, triggered_at) VALUES (?, ?, ?, ?, 'in_progress', ?, ?)`,
      [failoverId, regionId, targetRegionId, type, triggeredBy, now]
    );

    await this.logAudit('failover_triggered', { regionId, targetRegionId, type, failoverId });
    return this.getFailoverById(failoverId);
  }

  async getFailoverById(id: string): Promise<FailoverRecord> {
    const [rows]: any = await this.pool.execute('SELECT * FROM failover_records WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Failover record not found');
    return this.mapFailoverRow(rows[0]);
  }

  async listFailovers(regionId?: string, limit = 50, offset = 0): Promise<{ failovers: FailoverRecord[]; total: number }> {
    let where = '1=1';
    const params: any[] = [];

    if (regionId) { where += ' AND region_id = ?'; params.push(regionId); }

    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM failover_records WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM failover_records WHERE ${where} ORDER BY triggered_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return { failovers: rows.map((r: any) => this.mapFailoverRow(r)), total: count[0].total };
  }

  async completeFailover(id: string): Promise<FailoverRecord> {
    const now = new Date();
    await this.pool.execute(
      `UPDATE failover_records SET status = 'completed', completed_at = ? WHERE id = ?`,
      [now, id]
    );
    return this.getFailoverById(id);
  }

  async createGeoRoutingRule(input: { countryCodes: string[]; regionCode: string; priority?: number; isActive?: boolean }): Promise<GeoRoutingRule> {
    const id = ulid();
    const now = new Date();
    const priority = input.priority || 0;

    await this.pool.execute(
      `INSERT INTO geo_routing_rules (id, country_codes, region_code, priority, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
      [id, JSON.stringify(input.countryCodes), input.regionCode, priority, input.isActive !== false, now]
    );

    return this.getGeoRoutingById(id);
  }

  async getGeoRoutingById(id: string): Promise<GeoRoutingRule> {
    const [rows]: any = await this.pool.execute('SELECT * FROM geo_routing_rules WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Geo routing rule not found');
    return this.mapGeoRoutingRow(rows[0]);
  }

  async listGeoRoutingRules(isActive?: boolean): Promise<GeoRoutingRule[]> {
    let where = '1=1';
    const params: any[] = [];

    if (isActive !== undefined) { where += ' AND is_active = ?'; params.push(isActive); }

    const [rows]: any = await this.pool.execute(
      `SELECT * FROM geo_routing_rules WHERE ${where} ORDER BY priority DESC`,
      params
    );

    return rows.map((r: any) => this.mapGeoRoutingRow(r));
  }

  async updateGeoRoutingRule(id: string, updates: Partial<{ regionCode: string; priority: number; isActive: boolean }>): Promise<GeoRoutingRule> {
    await this.getGeoRoutingById(id);
    const sets: string[] = [];
    const params: any[] = [];

    if (updates.regionCode) { sets.push('region_code = ?'); params.push(updates.regionCode); }
    if (updates.priority !== undefined) { sets.push('priority = ?'); params.push(updates.priority); }
    if (updates.isActive !== undefined) { sets.push('is_active = ?'); params.push(updates.isActive); }

    params.push(id);
    await this.pool.execute(`UPDATE geo_routing_rules SET ${sets.join(', ')} WHERE id = ?`, params);

    return this.getGeoRoutingById(id);
  }

  async getGeoRoutingForCountry(countryCode: string): Promise<Region | null> {
    const [rows]: any = await this.pool.execute(
      `SELECT r.* FROM regions r JOIN geo_routing_rules g ON r.code = g.region_code WHERE JSON_CONTAINS(g.country_codes, ?) AND g.is_active = true ORDER BY g.priority DESC LIMIT 1`,
      [JSON.stringify(countryCode)]
    );

    return rows.length > 0 ? this.mapRegionRow(rows[0]) : null;
  }

  private async logAudit(action: string, metadata: Record<string, any>): Promise<void> {
    await this.pool.execute(
      `INSERT INTO platform_audit_logs (id, action, resource_type, resource_id, metadata, created_at) VALUES (?, ?, ?, ?, ?, NOW())`,
      [ulid(), action, 'region', 'platform', JSON.stringify(metadata)]
    );
  }

  private mapRegionRow(r: any): Region {
    return {
      id: r.id, name: r.name, code: r.code, location: r.location, status: r.status,
      primaryEndpoint: r.primary_endpoint, isPrimary: r.is_primary, capacity: r.capacity,
      currentLoad: r.current_load, createdAt: new Date(r.created_at), updatedAt: new Date(r.updated_at)
    };
  }

  private mapGeoRoutingRow(r: any): GeoRoutingRule {
    return {
      id: r.id, countryCodes: typeof r.country_codes === 'string' ? JSON.parse(r.country_codes) : [],
      regionCode: r.region_code, priority: r.priority, isActive: r.is_active,
      createdAt: new Date(r.created_at)
    };
  }

  private mapFailoverRow(r: any): FailoverRecord {
    return {
      id: r.id, regionId: r.region_id, targetRegionId: r.target_region_id,
      type: r.type, status: r.status, triggeredBy: r.triggered_by,
      triggeredAt: new Date(r.triggered_at),
      completedAt: r.completed_at ? new Date(r.completed_at) : null,
      metadata: typeof r.metadata === 'string' ? JSON.parse(r.metadata) : {}
    };
  }
}