import { BadRequestException } from '@nestjs/common';

/**
 * API-Key-Centric Tenant Resolution (Auth0/Clerk/Firebase style)
 *
 * NO explicit tenant IDs in APIs - tenant context is derived entirely from credentials:
 * - API Key auth → tenant from validated key
 * - JWT auth → tenant from token's tid claim
 * - Session auth → tenant from session data
 *
 * This is a multi-tenant platform where tenant is implicit in the credential.
 */

export const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// API Key prefixes
const API_KEY_PREFIXES = ['uF', 'pB', 'sF', 'tB'];

/**
 * Check if a token looks like an API key
 */
export function isApiKeyFormat(token: string | undefined): boolean {
  if (!token) return false;
  return API_KEY_PREFIXES.some(prefix => token.startsWith(prefix));
}

/**
 * Get header value from headers object (case-insensitive)
 */
export function getHeaderValue(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const value = headers[name.toLowerCase()] ?? headers[name];
  return Array.isArray(value) ? value[0] : value;
}

/**
 * Extract subdomain from hostname
 */
export function extractSubdomain(hostname: string | undefined): string | undefined {
  if (!hostname) return undefined;

  const host = hostname.split(':')[0]?.toLowerCase();
  if (!host || host === 'localhost' || host === '127.0.0.1' || host === '::1') {
    return undefined;
  }

  const [firstLabel] = host.split('.');
  if (!firstLabel || firstLabel === 'www') return undefined;

  return firstLabel;
}

/**
 * Parse and validate tenant ID from various sources
 */
export function parseTenantId(raw: string | undefined): string {
  if (!raw) {
    throw new BadRequestException({
      error: { code: 'MISSING_TENANT_ID', message: 'X-Tenant-ID header is required' },
    });
  }
  if (!UUID_V4_REGEX.test(raw)) {
    throw new BadRequestException({
      error: { code: 'INVALID_TENANT_ID', message: `Invalid tenant ID format: ${raw}` },
    });
  }
  return raw;
}

/**
 * Parse tenant ID with optional fallback to request context
 */
export function resolveTenantId(raw: string | undefined, fallback?: string): string {
  if (raw) return parseTenantId(raw);
  if (fallback) return parseTenantId(fallback);
  throw new BadRequestException({
    error: { code: 'MISSING_TENANT_ID', message: 'Tenant ID is required' },
  });
}

/**
 * Extract tenant ID from credentials ONLY (Auth0/Clerk style - no header fallback)
 * Priority: API Key > JWT > Session
 */
export function extractTenantIdFromRequest(req: Record<string, unknown>): string | undefined {
  // Priority 1: API Key tenantId (set by UnifiedAuthGuard)
  const apiKey = req['apiKey'] as { tenantId?: string } | undefined;
  if (apiKey?.tenantId && UUID_V4_REGEX.test(apiKey.tenantId)) {
    return apiKey.tenantId;
  }

  // Priority 2: tenantId from auth guard (JWT or session)
  const authTenantId = req['tenantId'] as string | undefined;
  if (authTenantId && UUID_V4_REGEX.test(authTenantId)) {
    return authTenantId;
  }

  // Priority 3: JWT tid claim
  const jwtTid = req['jwtTid'] as string | undefined;
  if (jwtTid && UUID_V4_REGEX.test(jwtTid)) {
    return jwtTid;
  }

  // No header fallback - tenant must come from credentials
  return undefined;
}

/**
 * Get tenant ID or throw if not found
 */
export function getTenantIdOrThrow(req: Record<string, unknown>): string {
  const tenantId = extractTenantIdFromRequest(req);
  if (!tenantId) {
    throw new BadRequestException({
      error: { code: 'MISSING_TENANT_ID', message: 'Tenant ID could not be resolved from credentials or context' },
    });
  }
  return tenantId;
}

/**
 * Get API key info from request (if authenticated via API key)
 */
export function getApiKeyFromRequest(req: Record<string, unknown>): { ulid: string; tenantId: string; env: string; scopes: string[] } | undefined {
  const apiKey = req['apiKey'] as { ulid?: string; tenantId?: string; env?: string; scopes?: string[] } | undefined;
  if (!apiKey?.ulid) return undefined;
  return {
    ulid: apiKey.ulid,
    tenantId: apiKey.tenantId || '',
    env: apiKey.env || 'live',
    scopes: apiKey.scopes || [],
  };
}

/**
 * Check if request is authenticated via API key
 */
export function isApiKeyAuth(req: Record<string, unknown>): boolean {
  return !!req['apiKey'];
}

/**
 * Check if request is authenticated via JWT
 */
export function isJwtAuth(req: Record<string, unknown>): boolean {
  return !!req['jwtTid'] && !req['apiKey'];
}

/**
 * Check if request is authenticated via session
 */
export function isSessionAuth(req: Record<string, unknown>): boolean {
  return !!req['sessionId'] && !req['apiKey'] && !req['jwtTid'];
}

/**
 * Get authentication method used
 */
export function getAuthMethod(req: Record<string, unknown>): string {
  if (req['apiKey']) return 'api_key';
  if (req['jwtTid']) return 'jwt';
  if (req['sessionId']) return 'session';
  if (req['isInternalService']) return 'internal_service';
  return 'unknown';
}