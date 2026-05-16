/**
 * API Client — Base configuration for all UICP API calls
 * Handles tenant scoping, auth tokens, and error normalization
 */

export const API_CONFIG = {
  baseUrl: process.env.NEXT_PUBLIC_API_BASE_URL ?? '',
  version: 'v1',
  timeout: 30000,
} as const;

export function getApiUrl(path: string): string {
  const normalizedPath = path.replace(/^\/+/, '');
  if (!API_CONFIG.baseUrl) {
    return `/${normalizedPath}`;
  }
  return `${API_CONFIG.baseUrl.replace(/\/+$/, '')}/${normalizedPath}`;
}

export function resolveTenantKey(): string {
  if (typeof window === 'undefined') {
    return process.env.NEXT_PUBLIC_DEV_TENANT_SLUG ?? '';
  }

  const strategy = process.env.NEXT_PUBLIC_TENANT_STRATEGY ?? 'subdomain';
  if (strategy === 'subdomain') {
    const [firstLabel] = window.location.hostname.split('.');
    if (firstLabel && !['localhost', '127', 'www'].includes(firstLabel)) {
      return firstLabel;
    }
  }

  return process.env.NEXT_PUBLIC_DEV_TENANT_SLUG ?? '';
}

function tenantHeaderName(tenantKey: string): 'X-Tenant-ID' | 'X-Tenant-Slug' {
  const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRe.test(tenantKey) ? 'X-Tenant-ID' : 'X-Tenant-Slug';
}

/**
 * Build headers for tenant-scoped API requests
 */
export function buildHeaders(tenantKey = resolveTenantKey(), accessToken?: string): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (tenantKey) headers[tenantHeaderName(tenantKey)] = tenantKey;
  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }
  return headers;
}

/**
 * Normalize API error responses
 */
export function normalizeError(error: unknown): { code: string; message: string } {
  if (error && typeof error === 'object') {
    const e = error as Record<string, unknown>;
    if (e.error && typeof e.error === 'object') {
      const errObj = e.error as Record<string, unknown>;
      return {
        code: String(errObj.code ?? 'UNKNOWN_ERROR'),
        message: String(errObj.message ?? 'An unexpected error occurred'),
      };
    }
    if (e.message) {
      return { code: 'CLIENT_ERROR', message: String(e.message) };
    }
  }
  return { code: 'NETWORK_ERROR', message: 'Network request failed' };
}

/**
 * Parse ISO date string safely
 */
export function parseDate(dateStr: string | undefined): Date | null {
  if (!dateStr) return null;
  const d = new Date(dateStr);
  return isNaN(d.getTime()) ? null : d;
}

/**
 * Build auth headers from token
 */
export function getAuthHeaders(accessToken?: string, tenantKey = resolveTenantKey()): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (tenantKey) headers[tenantHeaderName(tenantKey)] = tenantKey;
  if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;
  return headers;
}

/**
 * Format relative time (e.g., "2 minutes ago")
 */
export function timeAgo(dateStr: string | undefined): string {
  const date = parseDate(dateStr);
  if (!date) return 'unknown';
  const diff = Date.now() - date.getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

/**
 * Format duration in ms to human readable
 */
export function formatLatency(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

/**
 * Format percentage
 */
export function formatPercent(value: number, decimals = 1): string {
  return `${value.toFixed(decimals)}%`;
}
