/**
 * Platform Service — Super admin / platform-level operations
 * Handles tenant management, security incidents, threat intel, audit logs, regions, health, approvals
 */

import { getApiUrl, normalizeError } from '@/lib/api-client';
import { authService } from './auth.service';
import type { ApiResponse } from '@/types';

// ── Tenant Types ────────────────────────────────────────────────────────────────

export interface PlatformTenant {
  id: string;
  name: string;
  slug: string;
  type: 'DEDICATED' | 'ISOLATED' | 'SHARED';
  status: 'active' | 'suspended' | 'pending' | 'archived';
  isolationTier: string;
  createdAt: string;
  plan: string;
  metadata?: Record<string, unknown>;
}

// ── Security Incident Types ─────────────────────────────────────────────────────

export type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';

export interface SecurityIncident {
  id: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  tenantId?: string;
  principalId?: string;
  indicators: string[];
  mitigationSteps?: string[];
  createdAt: string;
  updatedAt: string;
  resolvedAt?: string;
  createdBy?: string;
}

export interface CreateIncidentRequest {
  title: string;
  description: string;
  severity: IncidentSeverity;
  tenantId?: string;
  principalId?: string;
  indicators?: string[];
  mitigationSteps?: string[];
}

// ── Threat Intel Types ─────────────────────────────────────────────────────────

export type ThreatIntelType = 'indicator' | 'campaign' | 'actor' | 'vulnerability';

export interface ThreatIntelItem {
  id: string;
  type: ThreatIntelType;
  value: string;
  source: string;
  confidence: number;
  severity: IncidentSeverity;
  tags: string[];
  firstSeen: string;
  lastSeen: string;
  metadata?: Record<string, unknown>;
}

// ── Risk Score Types ───────────────────────────────────────────────────────────

export interface RiskScore {
  entityType: 'tenant' | 'principal' | 'ip';
  entityId: string;
  score: number;
  factors: {
    factor: string;
    contribution: number;
    description: string;
  }[];
  lastUpdated: string;
}

export interface RiskScoreSummary {
  overallScore: number;
  tenantScores: RiskScore[];
  principalScores: RiskScore[];
  criticalAlerts: number;
  trend: 'up' | 'down' | 'stable';
}

// ── Platform Audit Types ───────────────────────────────────────────────────────

export type PlatformAuditEventType =
  | 'platform.tenant_created'
  | 'platform.tenant_suspended'
  | 'platform.tenant_archived'
  | 'platform.admin_login'
  | 'platform.admin_action'
  | 'platform.settings_changed'
  | 'platform.incident_created'
  | 'platform.incident_resolved';

export interface PlatformAuditLog {
  id: string;
  eventType: PlatformAuditEventType;
  tenantId?: string;
  principalId?: string;
  actorId: string;
  actorEmail?: string;
  timestamp: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
  correlationId?: string;
}

// ── Region Types ────────────────────────────────────────────────────────────────

export interface Region {
  id: string;
  code: string;
  name: string;
  continent?: string;
  cloudProvider?: string;
  availabilityZones: string[];
  status: 'active' | 'maintenance' | 'degraded';
}

// ── Health Status Types ─────────────────────────────────────────────────────────

export interface ServiceHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'unavailable';
  latencyMs?: number;
  uptimePercent?: number;
  lastCheck: string;
  errorMessage?: string;
}

export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'unavailable';
  version: string;
  timestamp: string;
  services: ServiceHealth[];
  summary: {
    total: number;
    healthy: number;
    degraded: number;
    unavailable: number;
  };
}

// ── Approval Types ─────────────────────────────────────────────────────────────

export type ApprovalStatus = 'pending' | 'approved' | 'rejected';
export type ApprovalType = 'tenant_onboarding' | 'tier_upgrade' | 'feature_access' | 'security_override';

export interface Approval {
  id: string;
  type: ApprovalType;
  status: ApprovalStatus;
  requesterId: string;
  requesterEmail: string;
  tenantId?: string;
  reason: string;
  metadata?: Record<string, unknown>;
  createdAt: string;
  reviewedAt?: string;
  reviewedBy?: string;
  reviewerEmail?: string;
}

export interface CreateApprovalRequest {
  type: ApprovalType;
  tenantId?: string;
  reason: string;
  metadata?: Record<string, unknown>;
}

// ── Pagination ─────────────────────────────────────────────────────────────────

export interface PaginationParams {
  limit?: number;
  offset?: number;
  page?: number;
  pageSize?: number;
}

// ── Platform Service ───────────────────────────────────────────────────────────

export class PlatformService {
  private authHeaders(): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  // ── Tenant Management ────────────────────────────────────────────────────────

  async listTenants(params?: {
    status?: PlatformTenant['status'];
    type?: PlatformTenant['type'];
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<ApiResponse<{ items: PlatformTenant[]; total: number }>> {
    const searchParams = new URLSearchParams();
    if (params?.status) searchParams.set('status', params.status);
    if (params?.type) searchParams.set('type', params.type);
    if (params?.search) searchParams.set('search', params.search);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));

    const query = searchParams.toString();
    const response = await fetch(getApiUrl(`platform/v1/tenants${query ? `?${query}` : ''}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // ── Security Incidents ───────────────────────────────────────────────────────

  async listSecurityIncidents(params?: {
    severity?: IncidentSeverity;
    status?: IncidentStatus;
    tenantId?: string;
    since?: string;
    until?: string;
    limit?: number;
    offset?: number;
  }): Promise<ApiResponse<{ items: SecurityIncident[]; total: number }>> {
    const searchParams = new URLSearchParams();
    if (params?.severity) searchParams.set('severity', params.severity);
    if (params?.status) searchParams.set('status', params.status);
    if (params?.tenantId) searchParams.set('tenantId', params.tenantId);
    if (params?.since) searchParams.set('since', params.since);
    if (params?.until) searchParams.set('until', params.until);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));

    const query = searchParams.toString();
    const response = await fetch(getApiUrl(`platform/v1/security/incidents${query ? `?${query}` : ''}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async createSecurityIncident(
    incident: CreateIncidentRequest
  ): Promise<ApiResponse<SecurityIncident>> {
    const response = await fetch(getApiUrl('platform/v1/security/incidents'), {
      method: 'POST',
      headers: this.authHeaders(),
      body: JSON.stringify(incident),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // ── Threat Intel ─────────────────────────────────────────────────────────────

  async listThreatIntel(params?: {
    type?: ThreatIntelType;
    severity?: IncidentSeverity;
    source?: string;
    search?: string;
    confidence?: number;
    limit?: number;
    offset?: number;
  }): Promise<ApiResponse<{ items: ThreatIntelItem[]; total: number }>> {
    const searchParams = new URLSearchParams();
    if (params?.type) searchParams.set('type', params.type);
    if (params?.severity) searchParams.set('severity', params.severity);
    if (params?.source) searchParams.set('source', params.source);
    if (params?.search) searchParams.set('search', params.search);
    if (params?.confidence) searchParams.set('confidence', String(params.confidence));
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));

    const query = searchParams.toString();
    const response = await fetch(getApiUrl(`platform/v1/security/threat-intel${query ? `?${query}` : ''}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // ── Risk Scores ─────────────────────────────────────────────────────────────

  async getRiskScores(params?: {
    entityType?: 'tenant' | 'principal' | 'ip';
    entityId?: string;
    tenantId?: string;
  }): Promise<ApiResponse<RiskScoreSummary>> {
    const searchParams = new URLSearchParams();
    if (params?.entityType) searchParams.set('entityType', params.entityType);
    if (params?.entityId) searchParams.set('entityId', params.entityId);
    if (params?.tenantId) searchParams.set('tenantId', params.tenantId);

    const query = searchParams.toString();
    const response = await fetch(getApiUrl(`platform/v1/security/risk-scores${query ? `?${query}` : ''}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // ── Platform Audit ─────────────────────────────────────────────────────────

  async listAuditLogs(params?: {
    eventType?: PlatformAuditEventType;
    tenantId?: string;
    principalId?: string;
    actorId?: string;
    since?: string;
    until?: string;
    limit?: number;
    offset?: number;
  }): Promise<ApiResponse<{ items: PlatformAuditLog[]; total: number }>> {
    const searchParams = new URLSearchParams();
    if (params?.eventType) searchParams.set('eventType', params.eventType);
    if (params?.tenantId) searchParams.set('tenantId', params.tenantId);
    if (params?.principalId) searchParams.set('principalId', params.principalId);
    if (params?.actorId) searchParams.set('actorId', params.actorId);
    if (params?.since) searchParams.set('since', params.since);
    if (params?.until) searchParams.set('until', params.until);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));

    const query = searchParams.toString();
    const response = await fetch(getApiUrl(`platform/v1/audit${query ? `?${query}` : ''}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // ── Regions ─────────────────────────────────────────────────────────────────

  async listRegions(params?: {
    status?: Region['status'];
    cloudProvider?: string;
  }): Promise<ApiResponse<{ items: Region[] }>> {
    const searchParams = new URLSearchParams();
    if (params?.status) searchParams.set('status', params.status);
    if (params?.cloudProvider) searchParams.set('cloudProvider', params.cloudProvider);

    const query = searchParams.toString();
    const response = await fetch(getApiUrl(`platform/v1/regions${query ? `?${query}` : ''}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // ── Resilience / Health ───────────────────────────────────────────────────

  async getHealthStatus(): Promise<ApiResponse<SystemHealth>> {
    const response = await fetch(getApiUrl('platform/v1/resilience/health'), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // ── Approvals ───────────────────────────────────────────────────────────────

  async listApprovals(params?: {
    status?: ApprovalStatus;
    type?: ApprovalType;
    requesterId?: string;
    tenantId?: string;
    limit?: number;
    offset?: number;
  }): Promise<ApiResponse<{ items: Approval[]; total: number }>> {
    const searchParams = new URLSearchParams();
    if (params?.status) searchParams.set('status', params.status);
    if (params?.type) searchParams.set('type', params.type);
    if (params?.requesterId) searchParams.set('requesterId', params.requesterId);
    if (params?.tenantId) searchParams.set('tenantId', params.tenantId);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));

    const query = searchParams.toString();
    const response = await fetch(getApiUrl(`platform/v1/approvals${query ? `?${query}` : ''}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async reviewApproval(
    approvalId: string,
    decision: 'approved' | 'rejected',
    reason?: string
  ): Promise<ApiResponse<Approval>> {
    const response = await fetch(getApiUrl(`platform/v1/approvals/${approvalId}/review`), {
      method: 'POST',
      headers: this.authHeaders(),
      body: JSON.stringify({ decision, reason }),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }
}

export const platformService = new PlatformService();