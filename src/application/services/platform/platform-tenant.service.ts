import { Injectable, NotFoundException, BadRequestException, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { ulid } from 'ulid';

export interface CreateTenantInput { name: string; domain?: string; plan?: string; quota?: TenantQuota; metadata?: Record<string, any>; }
export interface TenantQuota { apiCalls: number; storage: number; users: number; domains: number; }
export interface Tenant { id: string; name: string; domain: string | null; status: 'active' | 'suspended' | 'deactivated'; plan: string; quota: TenantQuota; createdAt: Date; updatedAt: Date; metadata: Record<string, any>; }

@Injectable()
export class PlatformTenantService {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async create(input: CreateTenantInput): Promise<Tenant> {
    const id = ulid();
    const now = new Date();
    if (input.domain) {
      const [existing]: any = await this.pool.execute('SELECT id FROM tenants WHERE domain = ?', [input.domain]);
      if (existing.length > 0) throw new BadRequestException('Tenant domain already exists');
    }
    const query = `INSERT INTO tenants (id, name, domain, status, plan, quota, metadata, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    await this.pool.execute(query, [id, input.name, input.domain || null, 'active', input.plan || 'basic', JSON.stringify(input.quota || { apiCalls: 10000, storage: 1024, users: 10, domains: 1 }), JSON.stringify(input.metadata || {}), now, now]);
    return this.getById(id);
  }

  async getById(id: string): Promise<Tenant> {
    const [rows]: any = await this.pool.execute('SELECT * FROM tenants WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Tenant not found');
    return this.mapRowToTenant(rows[0]);
  }

  async getByDomain(domain: string): Promise<Tenant | null> {
    const [rows]: any = await this.pool.execute('SELECT * FROM tenants WHERE domain = ?', [domain]);
    return rows.length > 0 ? this.mapRowToTenant(rows[0]) : null;
  }

  async list(options: { status?: string; limit?: number; offset?: number } = {}): Promise<{ tenants: Tenant[]; total: number }> {
    const { status, limit = 50, offset = 0 } = options;
    let whereClause = status ? 'WHERE status = ?' : '';
    const [countResult]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM tenants ${whereClause}`, status ? [status] : []);
    const [rows]: any = await this.pool.execute(`SELECT * FROM tenants ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`, [status ? status : '', limit, offset]);
    return { tenants: rows.map((r: any) => this.mapRowToTenant(r)), total: countResult[0].total };
  }

  async update(id: string, updates: Partial<CreateTenantInput>): Promise<Tenant> {
    await this.getById(id);
    const query = `UPDATE tenants SET name = COALESCE(?, name), domain = COALESCE(?, domain), plan = COALESCE(?, plan), quota = COALESCE(?, quota), metadata = COALESCE(?, metadata), updated_at = NOW() WHERE id = ?`;
    await this.pool.execute(query, [updates.name || null, updates.domain || null, updates.plan || null, updates.quota ? JSON.stringify(updates.quota) : null, updates.metadata ? JSON.stringify(updates.metadata) : null, id]);
    return this.getById(id);
  }

  async suspend(id: string, reason: string): Promise<Tenant> {
    await this.getById(id);
    await this.logAudit('tenant_suspended', id, { reason });
    await this.pool.execute('UPDATE tenants SET status = ?, updated_at = NOW() WHERE id = ?', ['suspended', id]);
    return this.getById(id);
  }

  async reactivate(id: string): Promise<Tenant> {
    await this.getById(id);
    await this.logAudit('tenant_reactivated', id, {});
    await this.pool.execute('UPDATE tenants SET status = ?, updated_at = NOW() WHERE id = ?', ['active', id]);
    return this.getById(id);
  }

  async delete(id: string): Promise<void> {
    const tenant = await this.getById(id);
    await this.logAudit('tenant_deleted', id, { name: tenant.name });
    await this.pool.execute('UPDATE tenants SET status = ?, updated_at = NOW() WHERE id = ?', ['deactivated', id]);
  }

  async migrate(id: string, targetRegion: string): Promise<{ migrationId: string; status: string }> {
    const migrationId = ulid();
    await this.pool.execute(`INSERT INTO tenant_migrations (id, tenant_id, target_region, status, created_at) VALUES (?, ?, ?, ?, NOW())`, [migrationId, id, targetRegion, 'pending']);
    return { migrationId, status: 'pending' };
  }

  async clone(id: string, newName: string): Promise<Tenant> {
    const original = await this.getById(id);
    return this.create({ name: newName, domain: `${newName.toLowerCase().replace(/\s+/g, '-')}.platform.io`, plan: original.plan, quota: original.quota, metadata: { clonedFrom: original.id } });
  }

  async getUsage(id: string): Promise<{ tenantId: string; apiCalls: number; storage: number; users: number; domains: number }> {
    const [metrics]: any = await this.pool.execute(`SELECT SUM(api_calls) as api_calls, SUM(storage_mb) as storage, COUNT(DISTINCT user_id) as users, COUNT(DISTINCT domain_id) as domains FROM tenant_usage_metrics WHERE tenant_id = ? AND period >= DATE_SUB(NOW(), INTERVAL 30 DAY)`, [id]);
    return { tenantId: id, apiCalls: metrics[0]?.api_calls || 0, storage: metrics[0]?.storage || 0, users: metrics[0]?.users || 0, domains: metrics[0]?.domains || 0 };
  }

  async setQuota(id: string, quota: TenantQuota): Promise<Tenant> {
    await this.getById(id);
    await this.pool.execute('UPDATE tenants SET quota = ?, updated_at = NOW() WHERE id = ?', [JSON.stringify(quota), id]);
    return this.getById(id);
  }

  private async logAudit(action: string, tenantId: string, metadata: Record<string, any>): Promise<void> {
    await this.pool.execute(`INSERT INTO platform_audit_logs (id, action, resource_type, resource_id, metadata, created_at) VALUES (?, ?, ?, ?, ?, NOW())`, [ulid(), action, 'tenant', tenantId, JSON.stringify(metadata)]);
  }

  private mapRowToTenant(row: any): Tenant {
    return { id: row.id, name: row.name, domain: row.domain, status: row.status, plan: row.plan, quota: typeof row.quota === 'string' ? JSON.parse(row.quota) : row.quota, createdAt: new Date(row.created_at), updatedAt: new Date(row.updated_at), metadata: typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata || {} };
  }
}