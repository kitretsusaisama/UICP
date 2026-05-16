/**
 * @uicp/sdk - Enterprise Identity SDK
 *
 * Type-safe, pluggable, DX-first SDK for Universal Identity Control Plane
 *
 * Key features:
 * - ✅ 100% TypeScript with strict mode
 * - ✅ Composable plugins (auth, tenant, idempotency, retry, rate-limit)
 * - ✅ Multi-runtime: Node 18+, Browser, Edge
 * - ✅ Enterprise ready: SAML SSO, OIDC, RBAC, Quota management
 * - ✅ Zero-dependency core
 * - ✅ Tree-shakeable
 */

import { UicpError } from "../errors/UicpError";

// ══════════════════════════════════════════════════════════════════════════════
// CORE TYPES
// ══════════════════════════════════════════════════════════════════════════════

/** Tenant identifier with type safety */
export type TenantId = string & { readonly __brand: 'TenantId' };
export const asTenantId = (id: string): TenantId => id as TenantId;

/** User identifier */
export type UserId = string & { readonly __brand: 'UserId' };
export const asUserId = (id: string): UserId => id as UserId;

/** Session identifier */
export type SessionId = string & { readonly __brand: 'SessionId' };
export const asSessionId = (id: string): SessionId => id as SessionId;

// ══════════════════════════════════════════════════════════════════════════════
// TOKEN TYPES
// ══════════════════════════════════════════════════════════════════════════════

export interface TokenSet {
  accessToken: string;
  refreshToken: string;
  sessionId: SessionId;
  expiresIn: number;
}

export interface RefreshTokenSet {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

// ══════════════════════════════════════════════════════════════════════════════
// AUTH RESPONSE TYPES
// ══════════════════════════════════════════════════════════════════════════════

export interface SignupResponse {
  userId: UserId;
  message: string;
}

export interface LoginResponse extends TokenSet { }

export interface SwitchActorResponse {
  accessToken: string;
  actor: Record<string, unknown>;
  effectiveCapabilitiesVersion: string;
}

export interface OtpVerifyResponse {
  verified: true;
  userStatus: string;
}

// ══════════════════════════════════════════════════════════════════════════════
// OTP
// ══════════════════════════════════════════════════════════════════════════════

export interface SendOtpInput {
  purpose: string;
  channel: string;
  identity: string;
}

export interface VerifyOtpInput {
  userId: string;
  code: string;
  purpose: string;
  identityId?: string;
  sessionId?: string;
}

// ══════════════════════════════════════════════════════════════════════════════
// PASSWORD
// ══════════════════════════════════════════════════════════════════════════════

export interface ChangePasswordInput {
  currentPassword: string;
  newPassword: string;
}

export interface PasswordResetRequestInput {
  identity: string;
}

export interface PasswordResetConfirmInput {
  identity: string;
  code: string;
  newPassword: string;
}

// ══════════════════════════════════════════════════════════════════════════════
// API ENVELOPE
// ══════════════════════════════════════════════════════════════════════════════

export interface ApiSuccess<T> {
  success: true;
  data: T;
  meta?: {
    requestId: string;
    timestamp: string;
    version: string;
  };
}

export interface ApiError {
  success: false;
  error: {
    code: string;
    message: string;
    traceId?: string;
  };
}

export type ApiResponse<T> = ApiSuccess<T> | ApiError;

// ══════════════════════════════════════════════════════════════════════════════
// RATE LIMIT & RISK
// ══════════════════════════════════════════════════════════════════════════════

export const RateLimitTier = {
  SIGNUP: 'signup',
  LOGIN: 'login',
  REFRESH: 'refresh',
  LOGOUT: 'logout',
  LOGOUT_ALL: 'logout-all',
  OTP_SEND: 'otp-send',
  OTP_VERIFY: 'otp-verify',
  PW_RESET: 'pw-reset',
  PW_RESET_CONFIRM: 'pw-reset-confirm',
} as const;

export type RateLimitTier = typeof RateLimitTier[keyof typeof RateLimitTier];

export const RiskLevel = {
  NORMAL: 'NORMAL',
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  COST_CRITICAL: 'COST_CRITICAL',
  AUTH_CRITICAL: 'AUTH_CRITICAL',
} as const;

export type RiskLevel = typeof RiskLevel[keyof typeof RiskLevel];

// ══════════════════════════════════════════════════════════════════════════════
// ENTERPRISE TYPES (from Phase 3)
// ══════════════════════════════════════════════════════════════════════════════

export interface TenantQuota {
  apiRequestsRemaining: number;
  apiRequestsLimit: number;
  smsCreditsRemaining: number;
  smsCreditsLimit: number;
  storageRemaining: number;
  storageLimit: number;
  windowStart: number;
  windowDurationSeconds: number;
}

export interface TenantHealthMetrics {
  healthScore: number;
  apiRequests24h: number;
  activeUsers24h: number;
  avgResponseTimeMs: number;
  errorRatePercent: number;
  authSuccessRatePercent: number;
  otpDeliverySuccessPercent: number;
}

export interface SamlConfig {
  entityId: string;
  idpSsoUrl: string;
  idpCertificate: string;
  acsUrl: string;
}

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  scopes: string[];
}

export interface RolePermissions {
  role: string;
  permissions: string[];
  inheritsFrom?: string;
}

// ══════════════════════════════════════════════════════════════════════════════
// CONFIG & STORAGE
// ══════════════════════════════════════════════════════════════════════════════

export interface UicpClientConfig {
  /** API base URL */
  baseUrl: string;
  /** Tenant identifier */
  tenantId: TenantId;
  /** Custom storage adapter */
  storage?: IStorageAdapter;
  /** Custom HTTP adapter */
  httpAdapter?: IHttpAdapter;
  /** Early refresh buffer in ms (default: 30000) */
  earlyRefreshBufferMs?: number;
  /** Debug mode */
  debug?: boolean;
  /** Session expired callback */
  onSessionExpired?: () => void;
  /** Custom fetch function */
  fetch?: typeof fetch;
  /** Request timeout in ms (default: 30000) */
  timeout?: number;
}

/** Storage adapter interface - works sync or async */
export interface IStorageAdapter {
  get(key: string): string | null | Promise<string | null>;
  set(key: string, value: string): void | Promise<void>;
  delete(key: string): void | Promise<void>;
  clear(): void | Promise<void>;
}

/** HTTP adapter interface */
export interface HttpRequest {
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE' | 'PUT';
  url: string;
  headers: Record<string, string>;
  body?: unknown;
}

export interface HttpResponse<T = unknown> {
  statusCode: number;
  data: T;
  headers: Record<string, string>;
}

export interface IHttpAdapter {
  request<T>(req: HttpRequest): Promise<HttpResponse<T>>;
}

// ══════════════════════════════════════════════════════════════════════════════
// REQUEST OPTIONS
// ══════════════════════════════════════════════════════════════════════════════

export interface RequestOptions {
  /** Custom idempotency key */
  idempotencyKey?: string;
  /** Abort signal */
  signal?: AbortSignal;
  /** Custom headers */
  headers?: Record<string, string>;
  /** Timeout in ms */
  timeout?: number;
}

// ══════════════════════════════════════════════════════════════════════════════
// EVENT TYPES
// ══════════════════════════════════════════════════════════════════════════════

export interface UicpEventMap {
  'tokens:set': { accessToken: string; sessionId: string };
  'tokens:cleared': void;
  'session:expired': { reason: 'TOKEN_REUSE_DETECTED' };
  'request:before': { method: string; path: string };
  'request:after': { method: string; path: string; statusCode: number; durationMs: number };
  'rate-limit:hit': { tier: RateLimitTier; retryAfterMs: number };
  'error': UicpError;
}

export type UicpEvent = keyof UicpEventMap;
export type UicpEventHandler<K extends UicpEvent> = (payload: UicpEventMap[K]) => void;