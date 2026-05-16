import { Injectable, NotFoundException, BadRequestException, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { ulid } from 'ulid';

export interface Consent {
  id: string; identityId: string; tenantId: string; consentType: string;
  granted: boolean; purpose: string; version: string; source: string;
  grantedAt: Date; withdrawnAt: Date | null; metadata: Record<string, any>;
}

export interface RetentionPolicy {
  id: string; tenantId: string; name: string; dataType: string;
  retentionDays: number; action: 'delete' | 'archive' | 'anonymize'; conditions: Record<string, any>;
  createdAt: Date; updatedAt: Date; createdBy: string;
}

export interface DSARRequest {
  id: string; requesterEmail: string; tenantId: string; requestType: 'access' | 'deletion' | 'portability' | 'correction';
  status: 'pending' | 'identity_verified' | 'processing' | 'completed' | 'rejected' | 'expired';
  identityVerified: boolean; verifiedAt: Date | null; dataCategories: string[];
  requestedAt: Date; completedAt: Date | null; completedBy: string | null; rejectionReason: string | null;
  metadata: Record<string, any>;
}

export interface CreateConsentInput {
  identityId: string; tenantId: string; consentType: string; granted: boolean;
  purpose: string; version: string; source?: string; metadata?: Record<string, any>;
}

export interface CreateRetentionPolicyInput {
  tenantId: string; name: string; dataType: string; retentionDays: number;
  action: 'delete' | 'archive' | 'anonymize'; conditions?: Record<string, any>; createdBy: string;
}

export interface CreateDSARInput {
  requesterEmail: string; tenantId: string; requestType: 'access' | 'deletion' | 'portability' | 'correction';
  identityId?: string; metadata?: Record<string, any>;
}

@Injectable()
export class PlatformDataGovService {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async recordConsent(input: CreateConsentInput): Promise<Consent> {
    const id = ulid();
    const now = new Date();

    await this.pool.execute(
      `INSERT INTO consents (id, identity_id, tenant_id, consent_type, granted, purpose, version, source, granted_at, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, input.identityId, input.tenantId, input.consentType, input.granted, input.purpose, input.version, input.source || 'system', now, JSON.stringify(input.metadata || {})]
    );

    return this.getConsentById(id);
  }

  async getConsentById(id: string): Promise<Consent> {
    const [rows]: any = await this.pool.execute('SELECT * FROM consents WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Consent not found');
    return this.mapConsentRow(rows[0]);
  }

  async getConsentsByIdentity(identityId: string, tenantId?: string): Promise<Consent[]> {
    const query = tenantId
      ? 'SELECT * FROM consents WHERE identity_id = ? AND tenant_id = ? ORDER BY granted_at DESC'
      : 'SELECT * FROM consents WHERE identity_id = ? ORDER BY granted_at DESC';
    const [rows]: any = await this.pool.execute(query, tenantId ? [identityId, tenantId] : [identityId]);
    return rows.map((r: any) => this.mapConsentRow(r));
  }

  async withdrawConsent(identityId: string, consentType: string): Promise<Consent> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM consents WHERE identity_id = ? AND consent_type = ? AND granted = true ORDER BY granted_at DESC LIMIT 1',
      [identityId, consentType]
    );
    if (rows.length === 0) throw new NotFoundException('Consent not found');

    const now = new Date();
    await this.pool.execute(
      'UPDATE consents SET granted = false, withdrawn_at = ? WHERE id = ?',
      [now, rows[0].id]
    );

    await this.logAudit('consent_withdrawn', { identityId, consentType });
    return this.getConsentById(rows[0].id);
  }

  async listConsents(tenantId: string, options: { granted?: boolean; consentType?: string; limit?: number; offset?: number } = {}): Promise<{ consents: Consent[]; total: number }> {
    const { granted, consentType, limit = 50, offset = 0 } = options;
    let where = 'tenant_id = ?';
    const params: any[] = [tenantId];

    if (granted !== undefined) { where += ' AND granted = ?'; params.push(granted); }
    if (consentType) { where += ' AND consent_type = ?'; params.push(consentType); }

    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM consents WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM consents WHERE ${where} ORDER BY granted_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return { consents: rows.map((r: any) => this.mapConsentRow(r)), total: count[0].total };
  }

  async createRetentionPolicy(input: CreateRetentionPolicyInput): Promise<RetentionPolicy> {
    const id = ulid();
    const now = new Date();

    await this.pool.execute(
      `INSERT INTO retention_policies (id, tenant_id, name, data_type, retention_days, action, conditions, created_at, updated_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, input.tenantId, input.name, input.dataType, input.retentionDays, input.action, JSON.stringify(input.conditions || {}), now, now, input.createdBy]
    );

    return this.getRetentionPolicyById(id);
  }

  async getRetentionPolicyById(id: string): Promise<RetentionPolicy> {
    const [rows]: any = await this.pool.execute('SELECT * FROM retention_policies WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Retention policy not found');
    return this.mapRetentionRow(rows[0]);
  }

  async listRetentionPolicies(tenantId: string): Promise<RetentionPolicy[]> {
    const [rows]: any = await this.pool.execute('SELECT * FROM retention_policies WHERE tenant_id = ? ORDER BY created_at DESC', [tenantId]);
    return rows.map((r: any) => this.mapRetentionRow(r));
  }

  async updateRetentionPolicy(id: string, updates: Partial<CreateRetentionPolicyInput>): Promise<RetentionPolicy> {
    await this.getRetentionPolicyById(id);
    const sets: string[] = [];
    const params: any[] = [];

    if (updates.name) { sets.push('name = ?'); params.push(updates.name); }
    if (updates.retentionDays) { sets.push('retention_days = ?'); params.push(updates.retentionDays); }
    if (updates.action) { sets.push('action = ?'); params.push(updates.action); }
    if (updates.conditions) { sets.push('conditions = ?'); params.push(JSON.stringify(updates.conditions)); }

    sets.push('updated_at = NOW()');
    params.push(id);

    await this.pool.execute(`UPDATE retention_policies SET ${sets.join(', ')} WHERE id = ?`, params);
    return this.getRetentionPolicyById(id);
  }

  async triggerPurge(tenantId: string, policyId?: string): Promise<{ purgeId: string; status: string; affectedRecords: number }> {
    const purgeId = ulid();
    const policies = policyId ? [await this.getRetentionPolicyById(policyId)] : await this.listRetentionPolicies(tenantId);

    let affectedRecords = 0;
    for (const policy of policies) {
      const cutoffDate = new Date(Date.now() - policy.retentionDays * 24 * 60 * 60 * 1000);
      const result: any = await this.pool.execute(
        `SELECT COUNT(*) as cnt FROM ${policy.dataType} WHERE tenant_id = ? AND created_at < ?`,
        [tenantId, cutoffDate]
      );
      affectedRecords += result[0][0]?.cnt || 0;
    }

    await this.pool.execute(
      `INSERT INTO retention_purges (id, tenant_id, policy_id, status, triggered_at) VALUES (?, ?, ?, 'running', NOW())`,
      [purgeId, tenantId, policyId || null]
    );

    await this.logAudit('purge_triggered', { purgeId, tenantId, policyId, affectedRecords });
    return { purgeId, status: 'running', affectedRecords };
  }

  async createDSARRequest(input: CreateDSARInput): Promise<DSARRequest> {
    const id = ulid();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

    await this.pool.execute(
      `INSERT INTO dsar_requests (id, requester_email, tenant_id, request_type, status, identity_verified, requested_at, expires_at, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, input.requesterEmail, input.tenantId, input.requestType, 'pending', false, now, expiresAt, JSON.stringify(input.metadata || {})]
    );

    await this.notifyDSARTeam(id, input.tenantId);
    return this.getDSARById(id);
  }

  async verifyDSARIdentity(id: string, verificationMethod: string): Promise<DSARRequest> {
    const request = await this.getDSARById(id);
    if (request.status !== 'pending') throw new BadRequestException('Request not pending verification');

    const now = new Date();
    await this.pool.execute(
      `UPDATE dsar_requests SET identity_verified = true, verified_at = ?, status = ?, metadata = JSON_SET(COALESCE(metadata, '{}'), '$.verification_method', ?) WHERE id = ?`,
      [now, 'identity_verified', verificationMethod, id]
    );

    return this.getDSARById(id);
  }

  async completeDSAR(id: string, completedBy: string, dataExport?: any): Promise<DSARRequest> {
    const request = await this.getDSARById(id);
    if (request.status !== 'identity_verified' && request.status !== 'processing') {
      throw new BadRequestException('Request not ready for completion');
    }

    const now = new Date();
    await this.pool.execute(
      `UPDATE dsar_requests SET status = ?, completed_at = ?, completed_by = ?, metadata = JSON_SET(COALESCE(metadata, '{}'), '$.data_export', ?) WHERE id = ?`,
      ['completed', now, completedBy, dataExport ? JSON.stringify(dataExport) : null, id]
    );

    await this.logAudit('dsar_completed', { requestId: id, requestType: request.requestType });
    return this.getDSARById(id);
  }

  async rejectDSAR(id: string, reason: string): Promise<DSARRequest> {
    const request = await this.getDSARById(id);
    if (request.status === 'completed' || request.status === 'rejected') {
      throw new BadRequestException('Request already finalized');
    }

    await this.pool.execute(
      `UPDATE dsar_requests SET status = ?, rejection_reason = ? WHERE id = ?`,
      ['rejected', reason, id]
    );

    return this.getDSARById(id);
  }

  async getDSARById(id: string): Promise<DSARRequest> {
    const [rows]: any = await this.pool.execute('SELECT * FROM dsar_requests WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('DSAR request not found');
    return this.mapDSARRow(rows[0]);
  }

  async listDSARRequests(tenantId: string, options: { status?: string; requestType?: string; limit?: number; offset?: number } = {}): Promise<{ requests: DSARRequest[]; total: number }> {
    const { status, requestType, limit = 50, offset = 0 } = options;
    let where = 'tenant_id = ?';
    const params: any[] = [tenantId];

    if (status) { where += ' AND status = ?'; params.push(status); }
    if (requestType) { where += ' AND request_type = ?'; params.push(requestType); }

    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM dsar_requests WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM dsar_requests WHERE ${where} ORDER BY requested_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return { requests: rows.map((r: any) => this.mapDSARRow(r)), total: count[0].total };
  }

  private async notifyDSARTeam(requestId: string, tenantId: string): Promise<void> {
    await this.logAudit('dsar_requested', { requestId, tenantId });
  }

  private async logAudit(action: string, metadata: Record<string, any>): Promise<void> {
    await this.pool.execute(
      `INSERT INTO platform_audit_logs (id, action, resource_type, resource_id, metadata, created_at) VALUES (?, ?, ?, ?, ?, NOW())`,
      [ulid(), action, 'datagov', 'platform', JSON.stringify(metadata)]
    );
  }

  private mapConsentRow(r: any): Consent {
    return {
      id: r.id, identityId: r.identity_id, tenantId: r.tenant_id, consentType: r.consent_type,
      granted: r.granted, purpose: r.purpose, version: r.version, source: r.source,
      grantedAt: new Date(r.granted_at), withdrawnAt: r.withdrawn_at ? new Date(r.withdrawn_at) : null,
      metadata: typeof r.metadata === 'string' ? JSON.parse(r.metadata) : {}
    };
  }

  private mapRetentionRow(r: any): RetentionPolicy {
    return {
      id: r.id, tenantId: r.tenant_id, name: r.name, dataType: r.data_type,
      retentionDays: r.retention_days, action: r.action,
      conditions: typeof r.conditions === 'string' ? JSON.parse(r.conditions) : {},
      createdAt: new Date(r.created_at), updatedAt: new Date(r.updated_at), createdBy: r.created_by
    };
  }

  private mapDSARRow(r: any): DSARRequest {
    return {
      id: r.id, requesterEmail: r.requester_email, tenantId: r.tenant_id, requestType: r.request_type,
      status: r.status, identityVerified: r.identity_verified, verifiedAt: r.verified_at ? new Date(r.verified_at) : null,
      dataCategories: r.data_categories ? JSON.parse(r.data_categories) : [],
      requestedAt: new Date(r.requested_at), completedAt: r.completed_at ? new Date(r.completed_at) : null,
      completedBy: r.completed_by, rejectionReason: r.rejection_reason,
      metadata: typeof r.metadata === 'string' ? JSON.parse(r.metadata) : {}
    };
  }
}