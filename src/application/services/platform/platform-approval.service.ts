import { Injectable, NotFoundException, BadRequestException, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { ulid } from 'ulid';

export interface ApprovalRequest {
  id: string; requesterId: string; requesterTenantId: string; resourceType: string;
  resourceId: string; action: string; justification: string; status: 'pending' | 'approved' | 'rejected' | 'escalated' | 'expired';
  priority: 'low' | 'medium' | 'high' | 'critical'; requestedAt: Date; expiresAt: Date;
  approvedBy: string | null; approvedAt: Date | null; rejectedBy: string | null; rejectedAt: Date | null;
  escalationLevel: number; approvers: ApprovalApprover[]; metadata: Record<string, any>;
}

export interface ApprovalApprover {
  approverId: string; approverEmail: string; status: 'pending' | 'approved' | 'rejected';
  respondedAt: Date | null; comments: string | null;
}

export interface CreateApprovalInput {
  requesterId: string; requesterTenantId: string; resourceType: string;
  resourceId: string; action: string; justification: string; priority?: 'low' | 'medium' | 'high' | 'critical';
  approverIds: string[]; expiresInHours?: number; metadata?: Record<string, any>;
}

@Injectable()
export class PlatformApprovalService {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async requestApproval(input: CreateApprovalInput): Promise<ApprovalRequest> {
    const id = ulid();
    const now = new Date();
    const expiresIn = input.expiresInHours || 72;
    const expiresAt = new Date(now.getTime() + expiresIn * 60 * 60 * 1000);
    const priority = input.priority || 'medium';

    const approvers: ApprovalApprover[] = input.approverIds.map(aid => ({
      approverId: aid, approverEmail: '', status: 'pending', respondedAt: null, comments: null
    }));

    await this.pool.execute(
      `INSERT INTO platform_approval_requests (id, requester_id, requester_tenant_id, resource_type, resource_id, action, justification, status, priority, requested_at, expires_at, escalation_level, approvers, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, input.requesterId, input.requesterTenantId, input.resourceType, input.resourceId, input.action, input.justification, 'pending', priority, now, expiresAt, 0, JSON.stringify(approvers), JSON.stringify(input.metadata || {})]
    );

    await this.notifyApprovers(id, input.approverIds, input.action, input.justification);
    return this.getById(id);
  }

  async approve(requestId: string, approverId: string, comments?: string): Promise<ApprovalRequest> {
    const request = await this.getById(requestId);
    if (request.status !== 'pending') throw new BadRequestException('Request not pending');
    if (request.expiresAt < new Date()) throw new BadRequestException('Request expired');

    const approver = request.approvers.find(a => a.approverId === approverId);
    if (!approver) throw new BadRequestException('Not authorized to approve this request');

    const now = new Date();
    approver.status = 'approved';
    approver.respondedAt = now;
    approver.comments = comments || null;

    const allApproved = request.approvers.every(a => a.status === 'approved' || a.approverId === approverId);
    const newStatus = allApproved ? 'approved' : 'pending';

    await this.pool.execute(
      `UPDATE platform_approval_requests SET status = ?, approved_by = ?, approved_at = ?, approvers = ? WHERE id = ?`,
      [newStatus, approverId, now, JSON.stringify(request.approvers), requestId]
    );

    if (newStatus === 'approved') {
      await this.executeApprovedAction(request);
    }

    return this.getById(requestId);
  }

  async reject(requestId: string, approverId: string, reason: string): Promise<ApprovalRequest> {
    const request = await this.getById(requestId);
    if (request.status !== 'pending') throw new BadRequestException('Request not pending');

    const approver = request.approvers.find(a => a.approverId === approverId);
    if (!approver) throw new BadRequestException('Not authorized to reject this request');

    const now = new Date();
    approver.status = 'rejected';
    approver.respondedAt = now;
    approver.comments = reason;

    await this.pool.execute(
      `UPDATE platform_approval_requests SET status = ?, rejected_by = ?, rejected_at = ?, approvers = ? WHERE id = ?`,
      ['rejected', approverId, now, JSON.stringify(request.approvers), requestId]
    );

    await this.notifyRequesterOfRejection(request, reason);
    return this.getById(requestId);
  }

  async escalate(requestId: string, escalatorId: string, reason: string): Promise<ApprovalRequest> {
    const request = await this.getById(requestId);
    if (request.status !== 'pending') throw new BadRequestException('Request not pending');

    const now = new Date();
    const newEscalationLevel = request.escalationLevel + 1;

    await this.pool.execute(
      `UPDATE platform_approval_requests SET status = ?, escalation_level = ?, metadata = JSON_SET(COALESCE(metadata, '{}'), '$.escalation', JSON_OBJECT('by', ?, 'at', ?, 'reason', ?)) WHERE id = ?`,
      ['escalated', newEscalationLevel, escalatorId, now.toISOString(), reason, requestId]
    );

    await this.notifyEscalation(request, reason);
    return this.getById(requestId);
  }

  async getById(id: string): Promise<ApprovalRequest> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_approval_requests WHERE id = ?', [id]);
    if (rows.length === 0) throw new NotFoundException('Approval request not found');
    return this.mapRow(rows[0]);
  }

  async list(options: { tenantId?: string; status?: string; resourceType?: string; limit?: number; offset?: number } = {}): Promise<{ requests: ApprovalRequest[]; total: number }> {
    const { tenantId, status, resourceType, limit = 50, offset = 0 } = options;
    let where = '1=1';
    const params: any[] = [];

    if (tenantId) { where += ' AND requester_tenant_id = ?'; params.push(tenantId); }
    if (status) { where += ' AND status = ?'; params.push(status); }
    if (resourceType) { where += ' AND resource_type = ?'; params.push(resourceType); }

    const [count]: any = await this.pool.execute(`SELECT COUNT(*) as total FROM platform_approval_requests WHERE ${where}`, params);
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM platform_approval_requests WHERE ${where} ORDER BY requested_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return { requests: rows.map((r: any) => this.mapRow(r)), total: count[0].total };
  }

  async getPendingForApprover(approverId: string): Promise<ApprovalRequest[]> {
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM platform_approval_requests WHERE status = 'pending' AND JSON_CONTAINS(approvers, JSON_OBJECT('approver_id', ?)) ORDER BY priority DESC, requested_at ASC`,
      [approverId]
    );
    return rows.map((r: any) => this.mapRow(r));
  }

  private async executeApprovedAction(request: ApprovalRequest): Promise<void> {
    await this.logAudit('action_executed', request.id, {
      resourceType: request.resourceType,
      resourceId: request.resourceId,
      action: request.action,
      requesterId: request.requesterId
    });
  }

  private async notifyApprovers(requestId: string, approverIds: string[], action: string, justification: string): Promise<void> {
    await this.logAudit('approval_requested', requestId, { approverIds, action, justification });
  }

  private async notifyRequesterOfRejection(request: ApprovalRequest, reason: string): Promise<void> {
    await this.logAudit('approval_rejected', request.id, { reason });
  }

  private async notifyEscalation(request: ApprovalRequest, reason: string): Promise<void> {
    await this.logAudit('approval_escalated', request.id, { reason, level: request.escalationLevel + 1 });
  }

  private async logAudit(action: string, requestId: string, metadata: Record<string, any>): Promise<void> {
    await this.pool.execute(
      `INSERT INTO platform_audit_logs (id, action, resource_type, resource_id, metadata, created_at) VALUES (?, ?, ?, ?, ?, NOW())`,
      [ulid(), action, 'approval_request', requestId, JSON.stringify(metadata)]
    );
  }

  private mapRow(r: any): ApprovalRequest {
    const approvers = typeof r.approvers === 'string' ? JSON.parse(r.approvers) : r.approvers;
    const metadata = typeof r.metadata === 'string' ? JSON.parse(r.metadata) : r.metadata || {};
    return {
      id: r.id, requesterId: r.requester_id, requesterTenantId: r.requester_tenant_id,
      resourceType: r.resource_type, resourceId: r.resource_id, action: r.action,
      justification: r.justification, status: r.status, priority: r.priority,
      requestedAt: new Date(r.requested_at), expiresAt: new Date(r.expires_at),
      approvedBy: r.approved_by, approvedAt: r.approved_at ? new Date(r.approved_at) : null,
      rejectedBy: r.rejected_by, rejectedAt: r.rejected_at ? new Date(r.rejected_at) : null,
      escalationLevel: r.escalation_level, approvers, metadata
    };
  }
}