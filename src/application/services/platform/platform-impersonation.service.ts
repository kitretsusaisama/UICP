import { Injectable, NotFoundException, BadRequestException, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { ulid } from 'ulid';

export interface ImpersonationSession {
  id: string; platformIdentityId: string; tenantId: string; targetIdentityId: string;
  reason: string; status: 'pending' | 'approved' | 'active' | 'ended' | 'expired' | 'revoked';
  startedAt: Date; endedAt: Date | null; approvedBy: string | null; approvedAt: Date | null;
  expiresAt: Date; ipAddress: string | null; userAgent: string | null; actionsLog: any[];
}

@Injectable()
export class PlatformImpersonationService {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async start(input: { platformIdentityId: string; tenantId: string; targetIdentityId: string; reason: string; ipAddress?: string; userAgent?: string }): Promise<ImpersonationSession> {
    const id = ulid();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 4 * 60 * 60 * 1000);
    const requiresApproval = await this.checkRequiresApproval(input.platformIdentityId, input.tenantId);
    const status = requiresApproval ? 'pending' : 'active';
    await this.pool.execute(`INSERT INTO platform_impersonation_sessions (id, platform_identity_id, tenant_id, target_identity_id, reason, status, started_at, expires_at, ip_address, user_agent, actions_log) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [id, input.platformIdentityId, input.tenantId, input.targetIdentityId, input.reason, status, now, expiresAt, input.ipAddress || null, input.userAgent || null, JSON.stringify([])]);
    return this.getById(id);
  }

  async approve(sessionId: string, approvedBy: string): Promise<ImpersonationSession> {
    const session = await this.getById(sessionId);
    if (session.status !== 'pending') throw new BadRequestException('Session not pending');
    const now = new Date();
    const newExpiresAt = new Date(now.getTime() + 4 * 60 * 60 * 1000);
    await this.pool.execute(`UPDATE platform_impersonation_sessions SET status = ?, approved_by = ?, approved_at = ?, expires_at = ? WHERE id = ?`, ['active', approvedBy, now, newExpiresAt, sessionId]);
    return this.getById(sessionId);
  }

  async end(sessionId: string, reason?: string): Promise<ImpersonationSession> {
    const session = await this.getById(sessionId);
    if (session.status === 'ended') throw new BadRequestException('Session already ended');
    await this.pool.execute(`UPDATE platform_impersonation_sessions SET status = ?, ended_at = ? WHERE id = ?`, ['ended', new Date(), sessionId]);
    return this.getById(sessionId);
  }

  async getById(id: string): Promise<ImpersonationSession> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_impersonation_sessions WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Session not found');
    return this.mapRow(rows[0]);
  }

  async list(options: { tenantId?: string; status?: string; limit?: number; offset?: number } = {}): Promise<{ sessions: ImpersonationSession[]; total: number }> {
    const { tenantId, status, limit = 50, offset = 0 } = options;
    let where = '1=1'; const params: any[] = [];
    if (tenantId) { where += ' AND tenant_id = ?'; params.push(tenantId); }
    if (status) { where += ' AND status = ?'; params.push(status); }
    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM platform_impersonation_sessions WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(`SELECT * FROM platform_impersonation_sessions WHERE ${where} ORDER BY started_at DESC LIMIT ? OFFSET ?`, [...params, limit, offset]);
    return { sessions: rows.map((r: any) => this.mapRow(r)), total: count[0].total };
  }

  private async checkRequiresApproval(pid: string, tid: string): Promise<boolean> {
    const [s]: any = await this.pool.execute('SELECT impersonation_requires_approval FROM tenant_settings WHERE tenant_id = ?', [tid]);
    return s.length > 0 ? s[0].impersonation_requires_approval : true;
  }

  private mapRow(r: any): ImpersonationSession {
    return { id: r.id, platformIdentityId: r.platform_identity_id, tenantId: r.tenant_id, targetIdentityId: r.target_identity_id, reason: r.reason, status: r.status, startedAt: new Date(r.started_at), endedAt: r.ended_at ? new Date(r.ended_at) : null, approvedBy: r.approved_by, approvedAt: r.approved_at ? new Date(r.approved_at) : null, expiresAt: new Date(r.expires_at), ipAddress: r.ip_address, userAgent: r.user_agent, actionsLog: typeof r.actions_log === 'string' ? JSON.parse(r.actions_log) : [] };
  }
}