/**
 * Session Service — Active sessions, devices, revocation
 * Connects to /v1/users/me/sessions and /v1/users/me/devices
 */

import { getApiUrl, normalizeError } from '@/lib/api-client';
import { authService } from './auth.service';
import type { SessionInfo, DeviceInfo, ApiResponse } from '@/types';

export class SessionService {
  private authHeaders(): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  async listSessions(): Promise<ApiResponse<SessionInfo[]>> {
    const response = await fetch(getApiUrl('v1/users/me/sessions'), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async revokeSession(sessionId: string): Promise<ApiResponse<{ revoked: boolean; sessionId: string }>> {
    const response = await fetch(getApiUrl(`v1/users/me/sessions/${sessionId}`), {
      method: 'DELETE',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async listDevices(): Promise<ApiResponse<DeviceInfo[]>> {
    const response = await fetch(getApiUrl('v1/users/me/devices'), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async removeDevice(fingerprint: string): Promise<ApiResponse<{ removed: boolean }>> {
    const response = await fetch(getApiUrl(`v1/users/me/devices/${encodeURIComponent(fingerprint)}`), {
      method: 'DELETE',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }
}

export const sessionService = new SessionService();