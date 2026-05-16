export type SecurityEventType =
  | 'login_success'
  | 'login_failed'
  | 'login_blocked'
  | 'mfa_success'
  | 'mfa_failed'
  | 'password_changed'
  | 'password_reset_requested'
  | 'password_reset_completed'
  | 'account_locked'
  | 'account_unlocked'
  | 'account_suspended'
  | 'account_reactivated'
  | 'credential_stuffed'
  | 'brute_force_attempt'
  | 'anomalous_ip'
  | 'anomalous_geo'
  | 'session_hijack_suspected'
  | 'token_reused'
  | 'jwt_invalid'
  | 'refresh_token_rotated'
  | 'rate_limit_exceeded'
  | 'api_key_rotated'
  | 'oauth_token_refreshed'
  | 'oauth_revoked'
  | 'impersonation_detected'
  | 'privilege_escalation'
  | 'permission_denied'
  | 'admin_action';

export type SecurityEventSeverity = 'info' | 'warning' | 'medium' | 'high' | 'critical';
export type SecurityEventDetectionMethod = 'rules' | 'ml_model' | 'heuristic' | 'manual';

export interface SecurityEvent {
  id: string;
  tenantId: string;
  userId?: string;
  principalId?: string;
  sessionId?: string;
  eventType: SecurityEventType;
  severity: SecurityEventSeverity;
  ipHash?: string;
  ipCountry?: string;
  ipCity?: string;
  userAgent?: string;
  deviceFingerprint?: string;
  geoDeltaSeconds?: number;
  ipChangeDetected: boolean;
  timeDeltaFromLast?: number;
  failureCountWindow?: number;
  detailsJson?: Record<string, unknown>;
  threatScore?: number;
  detectedBy: SecurityEventDetectionMethod;
  createdAt: Date;
}

export interface ISecurityEventsPort {
  log(event: Omit<SecurityEvent, 'id' | 'createdAt'>): Promise<void>;
  logBatch(events: Omit<SecurityEvent, 'id' | 'createdAt'>[]): Promise<void>;
  findByTenant(tenantId: string, options?: {
    eventTypes?: SecurityEventType[];
    severities?: SecurityEventSeverity[];
    from?: Date;
    to?: Date;
    limit?: number;
    offset?: number;
  }): Promise<SecurityEvent[]>;
  findByUser(userId: string, options?: {
    eventTypes?: SecurityEventType[];
    from?: Date;
    to?: Date;
    limit?: number;
  }): Promise<SecurityEvent[]>;
}