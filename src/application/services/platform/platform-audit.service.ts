import { Injectable, NotFoundException, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { ulid } from 'ulid';

export interface AuditLog {
  id: string; action: string; resourceType: string; resourceId: string | null;
  actorId: string | null; actorType: string | null; tenantId: string | null;
  metadata: Record<string, any>; ipAddress: string | null; userAgent: string | null;
  createdAt: Date;
}

export interface SignInLog {
  id: string; identityId: string; tenantId: string | null; method: string;
  ipAddress: string; userAgent: string; success: boolean; failureReason: string | null;
  mfaUsed: boolean; createdAt: Date;
}

export interface ComplianceReport {
  id: string; name: string; type: string; tenantId: string | null;
  status: 'generating' | 'ready' | 'failed'; format: string;
  fileUrl: string | null; generatedBy: string; generatedAt: Date | null;
  expiresAt: Date | null;
}

@Injectable()
export class PlatformAuditService {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async logAudit(input: { action: string; resourceType: string; resourceId?: string; actorId?: string; actorType?: string; tenantId?: string; metadata?: Record<string, any>; ipAddress?: string; userAgent?: string }): Promise<AuditLog> {
    const id = ulid();
    const now = new Date();

    await this.pool.execute(
      `INSERT INTO platform_audit_logs (id, action, resource_type, resource_id, actor_id, actor_type, tenant_id, metadata, ip_address, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, input.action, input.resourceType, input.resourceId || null, input.actorId || null, input.actorType || null, input.tenantId || null, JSON.stringify(input.metadata || {}), input.ipAddress || null, input.userAgent || null, now]
    );

    return this.getAuditById(id);
  }

  async getAuditById(id: string): Promise<AuditLog> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_audit_logs WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Audit log not found');
    return this.mapAuditRow(rows[0]);
  }

  async listAudit(options: { tenantId?: string; actorId?: string; resourceType?: string; action?: string; startDate?: Date; endDate?: Date; limit?: number; offset?: number } = {}): Promise<{ logs: AuditLog[]; total: number }> {
    const { tenantId, actorId, resourceType, action, startDate, endDate, limit = 50, offset = 0 } = options;
    let where = '1=1';
    const params: any[] = [];

    if (tenantId) { where += ' AND tenant_id = ?'; params.push(tenantId); }
    if (actorId) { where += ' AND actor_id = ?'; params.push(actorId); }
    if (resourceType) { where += ' AND resource_type = ?'; params.push(resourceType); }
    if (action) { where += ' AND action = ?'; params.push(action); }
    if (startDate) { where += ' AND created_at >= ?'; params.push(startDate); }
    if (endDate) { where += ' AND created_at <= ?'; params.push(endDate); }

    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM platform_audit_logs WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM platform_audit_logs WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return { logs: rows.map((r: any) => this.mapAuditRow(r)), total: count[0].total };
  }

  async exportAudit(options: { tenantId?: string; startDate: Date; endDate: Date; format?: string }): Promise<{ exportId: string; fileUrl: string }> {
    const exportId = ulid();
    const logs = await this.listAudit({ tenantId: options.tenantId, startDate: options.startDate, endDate: options.endDate, limit: 10000 });

    const data = logs.logs.map(l => ({ action: l.action, resourceType: l.resourceType, resourceId: l.resourceId, actorId: l.actorId, timestamp: l.createdAt, ipAddress: l.ipAddress }));
    const fileUrl = `/exports/audit/${exportId}.${options.format || 'json'}`;

    await this.pool.execute(
      `INSERT INTO audit_exports (id, tenant_id, start_date, end_date, format, file_url, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'completed', NOW())`,
      [exportId, options.tenantId || null, options.startDate, options.endDate, options.format || 'json', fileUrl]
    );

    return { exportId, fileUrl };
  }

  async logSignIn(input: { identityId: string; tenantId?: string; method: string; ipAddress: string; userAgent: string; success: boolean; failureReason?: string; mfaUsed?: boolean }): Promise<SignInLog> {
    const id = ulid();
    const now = new Date();

    await this.pool.execute(
      `INSERT INTO sign_in_logs (id, identity_id, tenant_id, method, ip_address, user_agent, success, failure_reason, mfa_used, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, input.identityId, input.tenantId || null, input.method, input.ipAddress, input.userAgent, input.success, input.failureReason || null, input.mfaUsed || false, now]
    );

    return this.getSignInById(id);
  }

  async getSignInById(id: string): Promise<SignInLog> {
    const [rows]: any = await this.pool.execute('SELECT * FROM sign_in_logs WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Sign-in log not found');
    return this.mapSignInRow(rows[0]);
  }

  async listSignIns(options: { tenantId?: string; identityId?: string; success?: boolean; limit?: number; offset?: number } = {}): Promise<{ logs: SignInLog[]; total: number }> {
    const { tenantId, identityId, success, limit = 50, offset = 0 } = options;
    let where = '1=1';
    const params: any[] = [];

    if (tenantId) { where += ' AND tenant_id = ?'; params.push(tenantId); }
    if (identityId) { where += ' AND identity_id = ?'; params.push(identityId); }
    if (success !== undefined) { where += ' AND success = ?'; params.push(success); }

    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM sign_in_logs WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM sign_in_logs WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return { logs: rows.map((r: any) => this.mapSignInRow(r)), total: count[0].total };
  }

  async generateReport(input: { name: string; type: string; tenantId?: string; format?: string; generatedBy: string }): Promise<ComplianceReport> {
    const id = ulid();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

    await this.pool.execute(
      `INSERT INTO compliance_reports (id, name, type, tenant_id, status, format, generated_by, expires_at) VALUES (?, ?, ?, ?, 'generating', ?, ?, ?)`,
      [id, input.name, input.type, input.tenantId || null, input.format || 'pdf', input.generatedBy, expiresAt]
    );

    return this.getReportById(id);
  }

  async getReportById(id: string): Promise<ComplianceReport> {
    const [rows]: any = await this.pool.execute('SELECT * FROM compliance_reports WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Report not found');
    return this.mapReportRow(rows[0]);
  }

  async listReports(options: { tenantId?: string; type?: string; status?: string; limit?: number; offset?: number } = {}): Promise<{ reports: ComplianceReport[]; total: number }> {
    const { tenantId, type, status, limit = 50, offset = 0 } = options;
    let where = '1=1';
    const params: any[] = [];

    if (tenantId) { where += ' AND tenant_id = ?'; params.push(tenantId); }
    if (type) { where += ' AND type = ?'; params.push(type); }
    if (status) { where += ' AND status = ?'; params.push(status); }

    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM compliance_reports WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM compliance_reports WHERE ${where} ORDER BY generated_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return { reports: rows.map((r: any) => this.mapReportRow(r)), total: count[0].total };
  }

  private mapAuditRow(r: any): AuditLog {
    return {
      id: r.id, action: r.action, resourceType: r.resource_type, resourceId: r.resource_id,
      actorId: r.actor_id, actorType: r.actor_type, tenantId: r.tenant_id,
      metadata: typeof r.metadata === 'string' ? JSON.parse(r.metadata) : {},
      ipAddress: r.ip_address, userAgent: r.user_agent, createdAt: new Date(r.created_at)
    };
  }

  private mapSignInRow(r: any): SignInLog {
    return {
      id: r.id, identityId: r.identity_id, tenantId: r.tenant_id, method: r.method,
      ipAddress: r.ip_address, userAgent: r.user_agent, success: r.success,
      failureReason: r.failure_reason, mfaUsed: r.mfa_used, createdAt: new Date(r.created_at)
    };
  }

  private mapReportRow(r: any): ComplianceReport {
    return {
      id: r.id, name: r.name, type: r.type, tenantId: r.tenant_id, status: r.status,
      format: r.format, fileUrl: r.file_url, generatedBy: r.generated_by,
      generatedAt: r.generated_at ? new Date(r.generated_at) : null, expiresAt: r.expires_at ? new Date(r.expires_at) : null
    };
  }
}