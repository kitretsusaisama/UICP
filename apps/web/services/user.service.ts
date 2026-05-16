/**
 * User Service — Profile, identities, audit logs
 * Connects to /v1/users/me/*
 */

import { getApiUrl, normalizeError } from '@/lib/api-client';
import { authService } from './auth.service';
import type { UserProfile, AuditLog, ApiResponse } from '@/types';

export class UserService {
  async getProfile(): Promise<ApiResponse<UserProfile>> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(getApiUrl('v1/users/me'), {
      method: 'GET',
      headers,
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async updateProfile(updates: { displayName?: string; metadata?: Record<string, unknown> }): Promise<ApiResponse<{ updated: boolean }>> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(getApiUrl('v1/users/me'), {
      method: 'PATCH',
      headers,
      body: JSON.stringify(updates),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async getIdentities(): Promise<ApiResponse<{ id: string; type: string; value: string; verified: boolean }[]>> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(getApiUrl('v1/users/me/identities'), {
      method: 'GET',
      headers,
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async addIdentity(type: 'email' | 'phone', value: string): Promise<ApiResponse<{ linked: boolean; verificationRequired: boolean }>> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(getApiUrl('v1/users/me/identities'), {
      method: 'POST',
      headers,
      body: JSON.stringify({ type, value }),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async removeIdentity(identityId: string): Promise<ApiResponse<{ unlinked: boolean }>> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(getApiUrl(`v1/users/me/identities/${identityId}`), {
      method: 'DELETE',
      headers,
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async getPermissions(): Promise<ApiResponse<{ roles: string[]; permissions: string[] }>> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(getApiUrl('v1/users/me/permissions'), {
      method: 'GET',
      headers,
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async getAuditLogs(limit = 50): Promise<ApiResponse<AuditLog[]>> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(getApiUrl('v1/users/me/audit-logs'), {
      method: 'GET',
      headers,
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }
}

export const userService = new UserService();