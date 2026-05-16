/**
 * UICP Frontend — Shared Type Definitions
 * Aligned with backend DTOs and domain models
 */

// ── Auth Types ────────────────────────────────────────────────────────────────

export type IdentityType = 'EMAIL' | 'PHONE';
export type OtpPurpose = 'IDENTITY_VERIFICATION' | 'MFA' | 'PASSWORD_RESET';
export type OtpChannel = 'EMAIL' | 'SMS' | 'WHATSAPP' | 'VOICE';

export interface LoginRequest {
  identity: string;
  password: string;
  identityType?: IdentityType;
  deviceFingerprint?: string;
}

export interface LoginResponse {
  data: {
    principal: {
      id: string;
      status: string;
      authMethodsSummary: string[];
    };
    membership: {
      id: string;
      tenantId: string;
      status: string;
      tenantType: string;
      isolationTier: string;
    } | undefined;
    actor: {
      id: string;
      type: string;
      displayName: string;
      isDefault: boolean;
    } | undefined;
    session: {
      id: string;
      recentAuthAt: string;
      expiresAt: string;
      deviceSummary: {
        browser: string;
        os: string;
        deviceType: string;
      };
    };
    accessToken: string;
    refreshToken?: string;
    policyVersion: string;
    manifestVersion: string;
  };
}

export interface SignupRequest {
  email?: string;
  phone?: string;
  password: string;
  identityType?: IdentityType;
}

export interface OtpSendRequest {
  userId: string;
  purpose: OtpPurpose;
  channel?: OtpChannel;
  recipient?: string;
  email?: string;
  phone?: string;
  tenantName?: string;
}

export interface OtpVerifyRequest {
  userId: string;
  code: string;
  purpose: OtpPurpose;
  identityId?: string;
  sessionId?: string;
}

// ── User Types ────────────────────────────────────────────────────────────────

export interface UserProfile {
  id: string;
  displayName: string;
  email?: string;
  phone?: string;
  status: string;
  createdAt: string;
  metadata?: Record<string, unknown>;
  identities: IdentityRecord[];
}

export interface IdentityRecord {
  id: string;
  type: 'email' | 'phone';
  value: string;
  verified: boolean;
  linkedAt: string;
}

// ── Session Types ─────────────────────────────────────────────────────────────

export interface SessionInfo {
  id: string;
  userId: string;
  principalId: string;
  status: 'active' | 'revoked' | 'expired' | 'invalidated';
  createdAt: string;
  expiresAt: string;
  lastActiveAt: string;
  ipHash: string;
  userAgent: string;
  uaBrowser: string;
  uaOs: string;
  uaDeviceType: string;
  threatScore: number;
  isCurrent?: boolean;
}

export interface DeviceInfo {
  fingerprint: string;
  addedAt: string;
  lastSeen: string;
  browser: string;
  os: string;
}

// ── Tenant Types ──────────────────────────────────────────────────────────────

export type TenantType = 'DEDICATED' | 'ISOLATED' | 'SHARED';
export type TenantStatus = 'active' | 'suspended' | 'pending';

export interface Tenant {
  id: string;
  name: string;
  type: TenantType;
  status: TenantStatus;
  isolationTier: string;
  createdAt: string;
  plan: string;
}

export interface TenantContext {
  tenantId: string;
  tenantName: string;
  tenantType: TenantType;
  role: string;
}

// ── Provider Types ─────────────────────────────────────────────────────────────

export type ProviderStatus = 'healthy' | 'degraded' | 'unavailable' | 'pending';

export interface Provider {
  id: string;
  name: string;
  type: 'SMS' | 'EMAIL' | 'WHATSAPP' | 'VOICE';
  status: ProviderStatus;
  priority: number;
  successRate: number;
  avgLatencyMs: number;
  fallbackChain: string[];
  config: Record<string, unknown>;
}

export interface ProviderHealth {
  providerId: string;
  status: ProviderStatus;
  successRate: number;
  latencyMs: number;
  lastHealthCheck: string;
  failures24h: number;
}

// ── Queue Types ───────────────────────────────────────────────────────────────

export type JobStatus = 'active' | 'delayed' | 'completed' | 'failed' | 'waiting';

export interface QueueJob {
  id: string;
  name: string;
  status: JobStatus;
  attempts: number;
  maxAttempts: number;
  progress: number;
  data: Record<string, unknown>;
  createdAt: string;
  processedAt?: string;
  failedAt?: string;
  error?: string;
}

export interface QueueMetrics {
  name: string;
  waiting: number;
  active: number;
  completed: number;
  failed: number;
  delayed: number;
  paused: boolean;
}

// ── Audit Types ───────────────────────────────────────────────────────────────

export type AuditEventType =
  | 'auth.login'
  | 'auth.logout'
  | 'auth.signup'
  | 'auth.otp_sent'
  | 'auth.otp_verified'
  | 'session.revoked'
  | 'user.updated'
  | 'provider.fallback'
  | 'queue.job_failed'
  | 'security.threat_detected';

export interface AuditLog {
  id: string;
  eventType: AuditEventType;
  tenantId: string;
  principalId: string;
  actorId?: string;
  sessionId?: string;
  timestamp: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
  correlationId?: string;
}

// ── Security Types ────────────────────────────────────────────────────────────

export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low';
export type ThreatType = 'credential_stuffing' | 'brute_force' | 'replay_attack' | 'anomaly';

export interface ThreatEvent {
  id: string;
  type: ThreatType;
  severity: ThreatSeverity;
  timestamp: string;
  principalId: string;
  sessionId?: string;
  ipHash: string;
  userAgent: string;
  score: number;
  indicators: string[];
  mitigated: boolean;
  mitigatedAt?: string;
}

// ── API Response Wrapper ──────────────────────────────────────────────────────

export interface ApiResponse<T> {
  data: T;
  error?: {
    code: string;
    message: string;
  };
}

export interface PaginatedResponse<T> {
  data: {
    items: T[];
    total: number;
    page: number;
    pageSize: number;
    hasMore: boolean;
  };
}

// ── Navigation / RBAC ─────────────────────────────────────────────────────────

export type UserRole = 'super_admin' | 'tenant_admin' | 'security_admin' | 'support_admin' | 'member';

export interface NavItem {
  label: string;
  path: string;
  icon: string;
  roles?: UserRole[];
  badge?: string | number;
  children?: NavItem[];
}

// ── Command Palette ───────────────────────────────────────────────────────────

export interface CommandItem {
  id: string;
  label: string;
  description?: string;
  path?: string;
  action?: string;
  icon?: string;
  category?: string;
  shortcut?: string[];
}

// ── Notification ──────────────────────────────────────────────────────────────

export type NotificationType = 'info' | 'success' | 'warning' | 'error' | 'security';

export interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
  actionUrl?: string;
}