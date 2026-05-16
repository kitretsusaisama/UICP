/**
 * API Key Service — Manage API keys for user and tenant
 * Connects to /v1/api-keys and /v1/tenant/api-keys endpoints
 */

import { getApiUrl, normalizeError } from '@/lib/api-client';
import { authService } from './auth.service';

// ============== Types ==============

export type ApiKeyScope = 'read' | 'write' | 'admin' | 'identity:read' | 'identity:write' | 'identity:admin' | 'tenant:read' | 'tenant:write' | 'tenant:admin' | 'api:read' | 'api:write' | 'api:admin' | 'resource:read' | 'resource:write' | 'resource:delete';

export type ApiKeyEnv = 'live' | 'dev' | 'staging';

export type ApiKeyType = 'publishable' | 'secret' | 'service_account' | 'temporary';

export interface ApiKeyResponse {
  id: string;
  ulid: string;
  type: ApiKeyType;
  env: ApiKeyEnv;
  scopes: ApiKeyScope[];
  rateLimit: number;
  createdAt: string;
  expiresAt: string;
  isActive: boolean;
  metadata: Record<string, unknown>;
}

export interface CreateApiKeyRequest {
  name?: string;
  scopes?: ApiKeyScope[];
  ipAllowlist?: string[];
  rateLimit?: number;
  expiresInDays?: number;
  env?: ApiKeyEnv;
}

export interface CreateApiKeyResponse {
  publishableKey: string;
  secretKey: string;
  key: ApiKeyResponse;
}

export interface TenantApiKeyRequest {
  name: string;
  scope?: 'read' | 'write' | 'admin' | 'fullaccess';
  tier?: 'free' | 'standard' | 'premium' | 'enterprise';
  ipAllowlist?: string[];
  rateLimit?: number;
  allowedOrigins?: string[];
  expiresInDays?: number;
}

export interface TenantApiKeyUpdateRequest {
  name?: string;
  scope?: 'read' | 'write' | 'admin' | 'fullaccess';
  tier?: 'free' | 'standard' | 'premium' | 'enterprise';
  ipAllowlist?: string[];
  rateLimit?: number;
  allowedOrigins?: string[];
}

export interface TenantApiKeyResponse {
  id: string;
  name: string;
  scope: string;
  tier: string;
  createdAt: string;
  expiresAt: string;
  isActive: boolean;
  lastUsedAt?: string;
  rateLimit: number;
  allowedOrigins?: string[];
  ipAllowlist?: string[];
}

// ============== API Key Service (User-scoped) ==============

export class ApiKeyService {
  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  /**
   * Create a new API key pair
   * POST /v1/api-keys
   */
  async create(input: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
    const response = await fetch(getApiUrl('v1/api-keys'), {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(input),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * List all API keys for the current user/tenant
   * GET /v1/api-keys
   */
  async list(): Promise<{ data: ApiKeyResponse[] }> {
    const response = await fetch(getApiUrl('v1/api-keys'), {
      method: 'GET',
      headers: this.getHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Get API key details by ID
   * GET /v1/api-keys/:id
   */
  async get(id: string): Promise<{ data: ApiKeyResponse }> {
    const response = await fetch(getApiUrl(`v1/api-keys/${id}`), {
      method: 'GET',
      headers: this.getHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Rotate an API key (revokes old, creates new)
   * POST /v1/api-keys/:id/rotate
   */
  async rotate(id: string): Promise<CreateApiKeyResponse> {
    const response = await fetch(getApiUrl(`v1/api-keys/${id}/rotate`), {
      method: 'POST',
      headers: this.getHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Revoke an API key
   * DELETE /v1/api-keys/:id
   */
  async revoke(id: string): Promise<void> {
    const response = await fetch(getApiUrl(`v1/api-keys/${id}`), {
      method: 'DELETE',
      headers: this.getHeaders(),
    });
    if (!response.ok) {
      const data = await response.json();
      throw normalizeError(data);
    }
  }
}

// ============== Tenant API Key Service ==============

export class TenantApiKeyService {
  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  /**
   * Create a new API key for the tenant
   * POST /v1/tenant/api-keys
   */
  async create(input: TenantApiKeyRequest): Promise<{ data: TenantApiKeyResponse }> {
    const response = await fetch(getApiUrl('v1/tenant/api-keys'), {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(input),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * List all API keys for the tenant
   * GET /v1/tenant/api-keys
   */
  async list(): Promise<{ data: TenantApiKeyResponse[] }> {
    const response = await fetch(getApiUrl('v1/tenant/api-keys'), {
      method: 'GET',
      headers: this.getHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Get a specific API key by ID
   * GET /v1/tenant/api-keys/:id
   */
  async get(id: string): Promise<{ data: TenantApiKeyResponse }> {
    const response = await fetch(getApiUrl(`v1/tenant/api-keys/${id}`), {
      method: 'GET',
      headers: this.getHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Rotate an API key (deprecates old, creates new)
   * POST /v1/tenant/api-keys/:id/rotate
   */
  async rotate(id: string): Promise<{ data: TenantApiKeyResponse }> {
    const response = await fetch(getApiUrl(`v1/tenant/api-keys/${id}/rotate`), {
      method: 'POST',
      headers: this.getHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Deprecate an API key (grace period before revocation)
   * POST /v1/tenant/api-keys/:id/deprecate
   */
  async deprecate(id: string, gracePeriodSeconds?: number): Promise<void> {
    const url = gracePeriodSeconds
      ? getApiUrl(`v1/tenant/api-keys/${id}/deprecate?gracePeriodSeconds=${gracePeriodSeconds}`)
      : getApiUrl(`v1/tenant/api-keys/${id}/deprecate`);
    const response = await fetch(url, {
      method: 'POST',
      headers: this.getHeaders(),
    });
    if (!response.ok) {
      const data = await response.json();
      throw normalizeError(data);
    }
  }

  /**
   * Revoke an API key immediately
   * POST /v1/tenant/api-keys/:id/revoke
   */
  async revoke(id: string): Promise<void> {
    const response = await fetch(getApiUrl(`v1/tenant/api-keys/${id}/revoke`), {
      method: 'POST',
      headers: this.getHeaders(),
    });
    if (!response.ok) {
      const data = await response.json();
      throw normalizeError(data);
    }
  }

  /**
   * Update an API key
   * PUT /v1/tenant/api-keys/:id
   */
  async update(id: string, updates: TenantApiKeyUpdateRequest): Promise<{ data: TenantApiKeyResponse }> {
    const response = await fetch(getApiUrl(`v1/tenant/api-keys/${id}`), {
      method: 'PUT',
      headers: this.getHeaders(),
      body: JSON.stringify(updates),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Delete an API key (only deprecated or revoked keys can be deleted)
   * DELETE /v1/tenant/api-keys/:id
   */
  async delete(id: string): Promise<void> {
    const response = await fetch(getApiUrl(`v1/tenant/api-keys/${id}`), {
      method: 'DELETE',
      headers: this.getHeaders(),
    });
    if (!response.ok) {
      const data = await response.json();
      throw normalizeError(data);
    }
  }
}

// ============== Exports ==============

export const apiKeyService = new ApiKeyService();
export const tenantApiKeyService = new TenantApiKeyService();