/**
 * Audit Service — Log querying, export, lineage
 */

import { getApiUrl, normalizeError } from '@/lib/api-client';
import { authService } from './auth.service';
import type { AuditLog, ApiResponse, AuditEventType } from '@/types';

export class AuditService {
  private authHeaders(): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  async listLogs(params?: {
    eventType?: AuditEventType;
    principalId?: string;
    sessionId?: string;
    since?: string;
    until?: string;
    limit?: number;
    offset?: number;
  }): Promise<ApiResponse<{ items: AuditLog[]; total: number }>> {
    const searchParams = new URLSearchParams();
    if (params?.eventType) searchParams.set('eventType', params.eventType);
    if (params?.principalId) searchParams.set('principalId', params.principalId);
    if (params?.since) searchParams.set('since', params.since);
    if (params?.until) searchParams.set('until', params.until);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));

    const query = searchParams.toString();
    const response = await fetch(getApiUrl(`v1/audit/logs${query ? `?${query}` : ''}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async exportLogs(params?: {
    format: 'json' | 'csv';
    since?: string;
    until?: string;
    eventType?: AuditEventType;
  }): Promise<Blob> {
    const searchParams = new URLSearchParams();
    searchParams.set('format', params?.format ?? 'json');
    if (params?.since) searchParams.set('since', params.since);
    if (params?.until) searchParams.set('until', params.until);
    if (params?.eventType) searchParams.set('eventType', params.eventType);

    const response = await fetch(getApiUrl(`v1/audit/export?${searchParams}`), {
      method: 'GET',
      headers: {
        ...this.authHeaders(),
        Accept: params?.format === 'csv' ? 'text/csv' : 'application/json',
      },
    });
    if (!response.ok) {
      const data = await response.json();
      throw normalizeError(data);
    }
    return response.blob();
  }

  async getEventLineage(eventId: string): Promise<ApiResponse<{ events: AuditLog[]; correlationId: string }>> {
    const response = await fetch(getApiUrl(`v1/audit/lineage/${eventId}`), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }
}

export const auditService = new AuditService();