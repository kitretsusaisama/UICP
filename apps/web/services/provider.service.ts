/**
 * Provider Service — SMS/Email provider health, fallback chains
 */

import { getApiUrl, normalizeError } from '@/lib/api-client';
import { authService } from './auth.service';
import type { Provider, ProviderHealth, ApiResponse } from '@/types';

export class ProviderService {
  private authHeaders(): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = authService.getAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  async listProviders(): Promise<ApiResponse<Provider[]>> {
    const response = await fetch(getApiUrl('v1/providers'), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async getProviderHealth(providerId?: string): Promise<ApiResponse<ProviderHealth | ProviderHealth[]>> {
    const url = providerId ? `v1/providers/${providerId}/health` : 'v1/providers/health';
    const response = await fetch(getApiUrl(url), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async getFallbackChains(): Promise<ApiResponse<{ type: string; chain: string[] }[]>> {
    const response = await fetch(getApiUrl('v1/providers/fallback-chains'), {
      method: 'GET',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async rotateApiKey(providerId: string): Promise<ApiResponse<{ rotated: boolean; newKey: string }>> {
    const response = await fetch(getApiUrl(`v1/providers/${providerId}/rotate-key`), {
      method: 'POST',
      headers: this.authHeaders(),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }
}

export const providerService = new ProviderService();