import { TenantId } from '../value-objects/tenant-id.vo';

export type DevicePlatform = 'web' | 'ios' | 'android' | 'desktop' | 'unknown';
export type AuthMethod = 'password' | 'otp_email' | 'otp_sms' | 'magic_link' | 'passkey' | 'oauth' | 'unknown';

/**
 * Auth Context - captures device, network, and behavioral context
 * Used for risk assessment and session resumption security
 */
export interface AuthContext {
  /** Tenant ID */
  tenantId: TenantId;

  /** Device fingerprint (hashed) */
  deviceFingerprint?: string;

  /** Device platform */
  platform: DevicePlatform;

  /** User agent string (can be hashed for storage) */
  userAgent?: string;

  /** IP address (hashed for storage - never store raw IP) */
  ipHash?: string;

  /** Autonomous System Number */
  asn?: number;

  /** Geographic location */
  geo?: {
    country?: string;
    city?: string;
    lat?: number;
    lng?: number;
  };

  /** Network properties */
  network?: {
    isProxy: boolean;
    isVPN: boolean;
    isTor: boolean;
    isCloudProvider: boolean;
  };

  /** Timestamp when context was captured */
  capturedAt: Date;
}

/**
 * Compare two auth contexts to detect changes
 * Used for security checks on session resumption
 */
export interface ContextDiff {
  deviceChanged: boolean;
  ipChanged: boolean;
  platformChanged: boolean;
  locationChanged: boolean;
}

/**
 * Compare two auth contexts and return differences
 */
export function compareContexts(original: AuthContext, current: AuthContext): ContextDiff {
  return {
    deviceChanged: original.deviceFingerprint !== current.deviceFingerprint,
    ipChanged: original.ipHash !== current.ipHash,
    platformChanged: original.platform !== current.platform,
    locationChanged: original.geo?.country !== current.geo?.country,
  };
}

/**
 * Create a new AuthContext from request data
 */
export function createAuthContext(params: {
  tenantId: TenantId;
  deviceFingerprint?: string;
  platform?: DevicePlatform;
  userAgent?: string;
  ipHash?: string;
  asn?: number;
  country?: string;
  city?: string;
  lat?: number;
  lng?: number;
  isProxy?: boolean;
  isVPN?: boolean;
  isTor?: boolean;
  isCloudProvider?: boolean;
}): AuthContext {
  return {
    tenantId: params.tenantId,
    deviceFingerprint: params.deviceFingerprint,
    platform: params.platform ?? 'unknown',
    userAgent: params.userAgent,
    ipHash: params.ipHash,
    asn: params.asn,
    geo: params.country
      ? {
          country: params.country,
          city: params.city,
          lat: params.lat,
          lng: params.lng,
        }
      : undefined,
    network: params.isProxy !== undefined
      ? {
          isProxy: params.isProxy ?? false,
          isVPN: params.isVPN ?? false,
          isTor: params.isTor ?? false,
          isCloudProvider: params.isCloudProvider ?? false,
        }
      : undefined,
    capturedAt: new Date(),
  };
}