/**
 * Tenant Service — Platform tenant management operations
 * Connects to /platform/v1/tenants/*
 */

import { getApiUrl, normalizeError, resolveTenantKey, buildHeaders } from '@/lib/api-client';
import { authService } from './auth.service';

// ============= Types =============

export interface TenantQuota {
  apiCalls: number;
  storage: number;
  users: number;
  domains: number;
}

export interface Tenant {
  id: string;
  name: string;
  domain?: string;
  plan?: string;
  status: 'active' | 'suspended' | 'pending';
  quota?: TenantQuota;
  metadata?: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface TenantCreateInput {
  name: string;
  domain?: string;
  plan?: string;
  quota?: TenantQuota;
  metadata?: Record<string, unknown>;
}

export interface TenantUpdateInput {
  name?: string;
  domain?: string;
  plan?: string;
  quota?: TenantQuota;
  metadata?: Record<string, unknown>;
}

export interface TenantStatusInput {
  status: 'suspended' | 'active';
  reason?: string;
}

export interface TenantMigrateInput {
  targetRegion: string;
}

export interface TenantCloneInput {
  newName: string;
}

export interface TenantUsage {
  apiCalls: {
    current: number;
    limit: number;
    percentage: number;
  };
  storage: {
    current: number;
    limit: number;
    percentage: number;
  };
  users: {
    current: number;
    limit: number;
    percentage: number;
  };
  domains: {
    current: number;
    limit: number;
    percentage: number;
  };
  period: {
    start: string;
    end: string;
  };
}

export interface TenantListParams {
  status?: string;
  limit?: number;
  offset?: number;
}

export interface TenantListResponse {
  tenants: Tenant[];
  total: number;
  page: number;
  perPage: number;
  totalPages: number;
}

export interface ApiResponse<T> {
  data: T;
  meta?: {
    total: number;
    page: number;
    per_page: number;
    total_pages: number;
  };
  links?: {
    self: string;
    next?: string;
    prev?: string;
  };
}

// ============= Service Class =============

export class TenantService {
  private getHeaders(): Record<string, string> {
    const token = authService.getAccessToken();
    const tenantKey = resolveTenantKey();
    return buildHeaders(tenantKey, token);
  }

  /**
   * Create a new tenant
   * POST /platform/v1/tenants
   */
  async create(input: TenantCreateInput): Promise<ApiResponse<Tenant>> {
    const response = await fetch(getApiUrl('platform/v1/tenants'), {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(input),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * List all tenants
   * GET /platform/v1/tenants
   */
  async list(params?: TenantListParams): Promise<ApiResponse<TenantListResponse>> {
    const queryParams = new URLSearchParams();
    if (params?.status) queryParams.set('status', params.status);
    if (params?.limit) queryParams.set('limit', String(params.limit));
    if (params?.offset) queryParams.set('offset', String(params.offset));

    const queryString = queryParams.toString();
    const url = queryString
      ? `platform/v1/tenants?${queryString}`
      : 'platform/v1/tenants';

    const response = await fetch(getApiUrl(url), {
      method: 'GET',
      headers: this.getHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Get tenant details by ID
   * GET /platform/v1/tenants/:id
   */
  async getById(id: string): Promise<ApiResponse<Tenant>> {
    const response = await fetch(getApiUrl(`platform/v1/tenants/${id}`), {
      method: 'GET',
      headers: this.getHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Update a tenant
   * PATCH /platform/v1/tenants/:id
   */
  async update(id: string, input: TenantUpdateInput): Promise<ApiResponse<Tenant>> {
    const response = await fetch(getApiUrl(`platform/v1/tenants/${id}`), {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify(input),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Update tenant status (suspend/reactivate)
   * PATCH /platform/v1/tenants/:id/status
   */
  async updateStatus(id: string, input: TenantStatusInput): Promise<ApiResponse<Tenant>> {
    const response = await fetch(getApiUrl(`platform/v1/tenants/${id}/status`), {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify(input),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Delete a tenant
   * DELETE /platform/v1/tenants/:id
   */
  async delete(id: string): Promise<ApiResponse<{ id: string; status: string }>> {
    const response = await fetch(getApiUrl(`platform/v1/tenants/${id}`), {
      method: 'DELETE',
      headers: this.getHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Migrate a tenant to a new region
   * POST /platform/v1/tenants/:id/migrate
   */
  async migrate(id: string, input: TenantMigrateInput): Promise<ApiResponse<{ id: string; status: string; targetRegion: string }>> {
    const response = await fetch(getApiUrl(`platform/v1/tenants/${id}/migrate`), {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(input),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Clone a tenant
   * POST /platform/v1/tenants/:id/clone
   */
  async clone(id: string, input: TenantCloneInput): Promise<ApiResponse<{ id: string; clonedFrom: string; name: string }>> {
    const response = await fetch(getApiUrl(`platform/v1/tenants/${id}/clone`), {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(input),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Get tenant usage statistics
   * GET /platform/v1/tenants/:id/usage
   */
  async getUsage(id: string): Promise<ApiResponse<TenantUsage>> {
    const response = await fetch(getApiUrl(`platform/v1/tenants/${id}/usage`), {
      method: 'GET',
      headers: this.getHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  /**
   * Set tenant quota
   * POST /platform/v1/tenants/:id/quota
   */
  async setQuota(id: string, quota: TenantQuota): Promise<ApiResponse<{ tenantId: string; quota: TenantQuota }>> {
    const response = await fetch(getApiUrl(`platform/v1/tenants/${id}/quota`), {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(quota),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }
}

// ============= Singleton Instance =============

export const tenantService = new TenantService();