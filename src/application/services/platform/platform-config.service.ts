import { Injectable, NotFoundException, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { ulid } from 'ulid';

export interface PlatformConfig {
  id: string; key: string; value: any; category: string;
  description: string | null; isEncrypted: boolean; isPublic: boolean;
  version: number; updatedAt: Date; updatedBy: string | null;
}

export interface CreateConfigInput {
  key: string; value: any; category: string; description?: string;
  isEncrypted?: boolean; isPublic?: boolean; updatedBy?: string;
}

export interface Announcement {
  id: string; title: string; content: string; type: 'info' | 'warning' | 'critical' | 'maintenance';
  targetTenants: string[] | null; startsAt: Date; endsAt: Date | null;
  createdBy: string; createdAt: Date; isActive: boolean;
}

@Injectable()
export class PlatformConfigService {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async set(input: CreateConfigInput): Promise<PlatformConfig> {
    const id = ulid();
    const now = new Date();
    const existing = await this.getByKey(input.key);

    if (existing) {
      return this.update(input.key, input.value, input.updatedBy);
    }

    await this.pool.execute(
      `INSERT INTO platform_config (id, key, value, category, description, is_encrypted, is_public, version, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, input.key, typeof input.value === 'string' ? input.value : JSON.stringify(input.value), input.category, input.description || null, input.isEncrypted || false, input.isPublic || false, 1, now, input.updatedBy || null]
    );

    const created = await this.getByKey(input.key);
    return created!;
  }

  async getByKey(key: string): Promise<PlatformConfig | null> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_config WHERE key = ?', [key]);
    if (rows.length === 0) return null;
    return this.mapRow(rows[0]);
  }

  async getPublicConfig(): Promise<Record<string, any>> {
    const [rows]: any = await this.pool.execute('SELECT key, value FROM platform_config WHERE is_public = true');
    const config: Record<string, any> = {};
    for (const row of rows) {
      try { config[row.key] = JSON.parse(row.value); } catch { config[row.key] = row.value; }
    }
    return config;
  }

  async update(key: string, value: any, updatedBy?: string): Promise<PlatformConfig> {
    const existing = await this.getByKey(key);
    if (!existing) throw new NotFoundException('Config not found');

    const now = new Date();
    await this.pool.execute(
      `UPDATE platform_config SET value = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE key = ?`,
      [typeof value === 'string' ? value : JSON.stringify(value), now, updatedBy || null, key]
    );

    return existing;
  }

  async delete(key: string): Promise<void> {
    const existing = await this.getByKey(key);
    if (!existing) throw new NotFoundException('Config not found');
    await this.pool.execute('DELETE FROM platform_config WHERE key = ?', [key]);
  }

  async list(options: { category?: string; isPublic?: boolean; limit?: number; offset?: number } = {}): Promise<{ configs: PlatformConfig[]; total: number }> {
    const { category, isPublic, limit = 50, offset = 0 } = options;
    let where = '1=1';
    const params: any[] = [];

    if (category) { where += ' AND category = ?'; params.push(category); }
    if (isPublic !== undefined) { where += ' AND is_public = ?'; params.push(isPublic); }

    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM platform_config WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM platform_config WHERE ${where} ORDER BY category, key LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return { configs: rows.map((r: any) => this.mapRow(r)), total: count[0].total };
  }

  async getByCategory(category: string): Promise<PlatformConfig[]> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_config WHERE category = ? ORDER BY key', [category]);
    return rows.map((r: any) => this.mapRow(r));
  }

  async exportConfig(): Promise<{ configs: PlatformConfig[]; exportedAt: Date }> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_config WHERE is_public = true');
    return { configs: rows.map((r: any) => this.mapRow(r)), exportedAt: new Date() };
  }

  async importConfig(configs: CreateConfigInput[], importedBy: string): Promise<{ imported: number; errors: string[] }> {
    let imported = 0;
    const errors: string[] = [];

    for (const config of configs) {
      try {
        await this.set({ ...config, updatedBy: importedBy });
        imported++;
      } catch (e: any) {
        errors.push(`Failed to import ${config.key}: ${e.message}`);
      }
    }

    await this.logAudit('config_imported', { count: imported, by: importedBy });
    return { imported, errors };
  }

  async createAnnouncement(input: { title: string; content: string; type: 'info' | 'warning' | 'critical' | 'maintenance'; targetTenants?: string[]; startsAt: Date; endsAt?: Date; createdBy: string }): Promise<Announcement> {
    const id = ulid();
    await this.pool.execute(
      `INSERT INTO platform_announcements (id, title, content, type, target_tenants, starts_at, ends_at, created_by, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, true)`,
      [id, input.title, input.content, input.type, input.targetTenants ? JSON.stringify(input.targetTenants) : null, input.startsAt, input.endsAt || null, input.createdBy]
    );
    return this.getAnnouncementById(id);
  }

  async getAnnouncementById(id: string): Promise<Announcement> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_announcements WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Announcement not found');
    return this.mapAnnouncementRow(rows[0]);
  }

  async listAnnouncements(options: { type?: string; activeOnly?: boolean; limit?: number; offset?: number } = {}): Promise<{ announcements: Announcement[]; total: number }> {
    const { type, activeOnly, limit = 50, offset = 0 } = options;
    let where = '1=1';
    const params: any[] = [];

    if (type) { where += ' AND type = ?'; params.push(type); }
    if (activeOnly) { where += ' AND is_active = true AND starts_at <= NOW() AND (ends_at IS NULL OR ends_at > NOW())'; }

    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM platform_announcements WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM platform_announcements WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return { announcements: rows.map((r: any) => this.mapAnnouncementRow(r)), total: count[0].total };
  }

  async deleteAnnouncement(id: string): Promise<void> {
    await this.getAnnouncementById(id);
    await this.pool.execute('UPDATE platform_announcements SET is_active = false WHERE id = ?', [id]);
  }

  private async logAudit(action: string, metadata: Record<string, any>): Promise<void> {
    await this.pool.execute(
      `INSERT INTO platform_audit_logs (id, action, resource_type, resource_id, metadata, created_at) VALUES (?, ?, ?, ?, ?, NOW())`,
      [ulid(), action, 'config', 'platform', JSON.stringify(metadata)]
    );
  }

  private mapRow(r: any): PlatformConfig {
    let value: any;
    try { value = JSON.parse(r.value); } catch { value = r.value; }
    return {
      id: r.id, key: r.key, value, category: r.category, description: r.description,
      isEncrypted: r.is_encrypted, isPublic: r.is_public, version: r.version,
      updatedAt: new Date(r.updated_at), updatedBy: r.updated_by
    };
  }

  private mapAnnouncementRow(r: any): Announcement {
    return {
      id: r.id, title: r.title, content: r.content, type: r.type,
      targetTenants: r.target_tenants ? JSON.parse(r.target_tenants) : null,
      startsAt: new Date(r.starts_at), endsAt: r.ends_at ? new Date(r.ends_at) : null,
      createdBy: r.created_by, createdAt: new Date(r.created_at), isActive: r.is_active
    };
  }
}