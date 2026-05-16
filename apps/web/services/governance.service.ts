/**
 * Governance Service — RBAC, policies, permissions
 * All governance flows connect to /v1/roles/* and /v1/policies/* endpoints
 */

import { getApiUrl, normalizeError } from '@/lib/api-client';
import { authService } from './auth.service';
import type { ApiResponse } from '@/types';

// ── Permission Types ────────────────────────────────────────────────────────────

export type PermissionAction =
  | 'create'
  | 'read'
  | 'update'
  | 'delete'
  | 'execute'
  | 'admin'
  | 'manage';

export type PermissionResource =
  | 'users'
  | 'roles'
  | 'policies'
  | 'sessions'
  | 'tenants'
  | 'providers'
  | 'queues'
  | 'audit'
  | 'api_keys'
  | 'extensions'
  | 'identities';

export interface Permission {
  id: string;
  name: string;
  action: PermissionAction;
  resource: PermissionResource;
  description?: string;
  createdAt: string;
}

// ── Role Types ──────────────────────────────────────────────────────────────────

export type RoleStatus = 'active' | 'suspended' | 'deprecated';

export interface Role {
  id: string;
  name: string;
  description?: string;
  status: RoleStatus;
  permissions: Permission[];
  memberCount: number;
  tenantId: string;
  createdAt: string;
  updatedAt: string;
  createdBy?: string;
}

export interface CreateRoleRequest {
  name: string;
  description?: string;
  permissions?: string[];
}

export interface AssignRoleRequest {
  userId: string;
  roleId: string;
  expiresAt?: string;
}

export interface RoleAssignment {
  id: string;
  userId: string;
  roleId: string;
  assignedAt: string;
  expiresAt?: string;
  assignedBy?: string;
}

// ── Policy Types ────────────────────────────────────────────────────────────────

export type PolicyType = 'allow' | 'deny';
export type PolicyStatus = 'active' | 'suspended' | 'draft';

export interface PolicyEffect {
  type: PolicyType;
  priority: number;
}

export interface PolicyCondition {
  field: string;
  operator: 'eq' | 'neq' | 'in' | 'not_in' | 'contains' | 'regex' | 'gt' | 'gte' | 'lt' | 'lte';
  value: unknown;
}

export interface PolicyRule {
  actions: string[];
  resources: string[];
  conditions?: PolicyCondition[];
}

export interface Policy {
  id: string;
  name: string;
  description?: string;
  type: PolicyType;
  status: PolicyStatus;
  effect: PolicyEffect;
  rules: PolicyRule[];
  tenantId: string;
  createdAt: string;
  updatedAt: string;
  createdBy?: string;
}

export interface CreatePolicyRequest {
  name: string;
  description?: string;
  type: PolicyType;
  effect?: {
    type: PolicyType;
    priority?: number;
  };
  rules: PolicyRule[];
}

export interface TestPolicyRequest {
  actorId?: string;
  action: string;
  resource: string;
  context?: Record<string, unknown>;
}

export interface TestPolicyResponse {
  allowed: boolean;
  matchedRule?: number;
  conditions?: Record<string, boolean>;
  reasons?: string[];
}

// ── Paginated Types ────────────────────────────────────────────────────────────

export interface PaginatedRoles {
  items: Role[];
  total: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
}

export interface PaginatedPolicies {
  items: Policy[];
  total: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
}

// ── Governance Service ──────────────────────────────────────────────────────────

export class GovernanceService {
  private getAuthHeaders(): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  // ── Role Endpoints ───────────────────────────────────────────────────────────

  // POST /v1/roles - Create role
  async createRole(body: CreateRoleRequest): Promise<ApiResponse<Role>> {
    const response = await fetch(getApiUrl('v1/roles'), {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // GET /v1/roles - List roles
  async listRoles(params?: {
    page?: number;
    pageSize?: number;
    status?: RoleStatus;
    search?: string;
  }): Promise<ApiResponse<PaginatedRoles>> {
    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.set('page', String(params.page));
    if (params?.pageSize) queryParams.set('pageSize', String(params.pageSize));
    if (params?.status) queryParams.set('status', params.status);
    if (params?.search) queryParams.set('search', params.search);

    const query = queryParams.toString();
    const url = query ? `v1/roles?${query}` : 'v1/roles';

    const response = await fetch(getApiUrl(url), {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // GET /v1/roles/:id - Get role details
  async getRole(roleId: string): Promise<ApiResponse<Role>> {
    const response = await fetch(getApiUrl(`v1/roles/${roleId}`), {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // DELETE /v1/roles/:id - Delete role
  async deleteRole(roleId: string): Promise<ApiResponse<{ deleted: boolean }>> {
    const response = await fetch(getApiUrl(`v1/roles/${roleId}`), {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // POST /v1/roles/assign - Assign role to user
  async assignRole(body: AssignRoleRequest): Promise<ApiResponse<RoleAssignment>> {
    const response = await fetch(getApiUrl('v1/roles/assign'), {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // DELETE /v1/roles/:id/assign/:assignmentId - Revoke role assignment
  async revokeRoleAssignment(
    roleId: string,
    assignmentId: string
  ): Promise<ApiResponse<{ revoked: boolean }>> {
    const response = await fetch(getApiUrl(`v1/roles/${roleId}/assign/${assignmentId}`), {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // GET /v1/roles/:id/assignments - List role assignments
  async getRoleAssignments(roleId: string): Promise<ApiResponse<RoleAssignment[]>> {
    const response = await fetch(getApiUrl(`v1/roles/${roleId}/assignments`), {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // ── Policy Endpoints ─────────────────────────────────────────────────────────

  // POST /v1/policies - Create policy
  async createPolicy(body: CreatePolicyRequest): Promise<ApiResponse<Policy>> {
    const response = await fetch(getApiUrl('v1/policies'), {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // GET /v1/policies - List policies
  async listPolicies(params?: {
    page?: number;
    pageSize?: number;
    status?: PolicyStatus;
    type?: PolicyType;
    search?: string;
  }): Promise<ApiResponse<PaginatedPolicies>> {
    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.set('page', String(params.page));
    if (params?.pageSize) queryParams.set('pageSize', String(params.pageSize));
    if (params?.status) queryParams.set('status', params.status);
    if (params?.type) queryParams.set('type', params.type);
    if (params?.search) queryParams.set('search', params.search);

    const query = queryParams.toString();
    const url = query ? `v1/policies?${query}` : 'v1/policies';

    const response = await fetch(getApiUrl(url), {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // GET /v1/policies/:id - Get policy details
  async getPolicy(policyId: string): Promise<ApiResponse<Policy>> {
    const response = await fetch(getApiUrl(`v1/policies/${policyId}`), {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // DELETE /v1/policies/:id - Delete policy
  async deletePolicy(policyId: string): Promise<ApiResponse<{ deleted: boolean }>> {
    const response = await fetch(getApiUrl(`v1/policies/${policyId}`), {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // POST /v1/policies/:id/test - Test policy
  async testPolicy(policyId: string, body: TestPolicyRequest): Promise<ApiResponse<TestPolicyResponse>> {
    const response = await fetch(getApiUrl(`v1/policies/${policyId}/test`), {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // POST /v1/policies/test - Test all active policies (bulk test)
  async testPolicies(body: TestPolicyRequest): Promise<ApiResponse<{ allowed: boolean; matchedPolicies: string[] }>> {
    const response = await fetch(getApiUrl('v1/policies/test'), {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // PATCH /v1/policies/:id - Update policy
  async updatePolicy(
    policyId: string,
    body: Partial<CreatePolicyRequest>
  ): Promise<ApiResponse<Policy>> {
    const response = await fetch(getApiUrl(`v1/policies/${policyId}`), {
      method: 'PATCH',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // PATCH /v1/roles/:id - Update role
  async updateRole(
    roleId: string,
    body: Partial<CreateRoleRequest>
  ): Promise<ApiResponse<Role>> {
    const response = await fetch(getApiUrl(`v1/roles/${roleId}`), {
      method: 'PATCH',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // ── Permission Endpoints ─────────────────────────────────────────────────────

  // GET /v1/permissions - List all permissions
  async listPermissions(): Promise<ApiResponse<Permission[]>> {
    const response = await fetch(getApiUrl('v1/permissions'), {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }
}

export const governanceService = new GovernanceService();