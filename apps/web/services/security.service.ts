/**
 * Security Service — UECA threat detection, SOC alerts, incidents
 */

import { getApiUrl, normalizeError } from '@/lib/api-client';
import { authService } from './auth.service';
import type { ThreatEvent, ApiResponse } from '@/types';

export class SecurityService {
  private authHeaders(): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  async getThreatHistory(params?: {
    severity?: string;
    limit?: number;
    since?: string;
  }): Promise<ApiResponse<ThreatEvent[]>> {
    const searchParams = new URLSearchParams();
    if (params?.severity) searchParams.set('severity', params.severity);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.since) searchParams.set('since', params.since);

    const query = searchParams.toString();
    const response = await fetch(getApiUrl(`v1/security/threats${query ? `?${query}` : ''}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async getReplayEvents(params?: {
    sessionId?: string;
    limit?: number;
  }): Promise<ApiResponse<{ events: unknown[]; count: number }>> {
    const searchParams = new URLSearchParams();
    if (params?.sessionId) searchParams.set('sessionId', params.sessionId);
    if (params?.limit) searchParams.set('limit', String(params.limit));

    const query = searchParams.toString();
    const response = await fetch(getApiUrl(`v1/security/replay${query ? `?${query}` : ''}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async getBruteForceAttempts(limit = 50): Promise<ApiResponse<{ ip: string; attempts: number; blocked: boolean }[]>> {
    const response = await fetch(getApiUrl(`v1/security/brute-force?limit=${limit}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async blockIp(ipHash: string): Promise<ApiResponse<{ blocked: boolean }>> {
    const response = await fetch(getApiUrl('v1/security/block-ip'), {
      method: 'POST',
      headers: this.authHeaders(),
      body: JSON.stringify({ ipHash }),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async investigateIncident(incidentId: string): Promise<ApiResponse<{ timeline: unknown[]; indicators: string[] }>> {
    const response = await fetch(getApiUrl(`v1/security/incidents/${incidentId}/investigate`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }
}

export const securityService = new SecurityService();