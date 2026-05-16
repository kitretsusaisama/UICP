/**
 * Auth Service — Login, OTP, OAuth, token management
 * All auth flows connect to /v1/auth/* endpoints
 */

import { getApiUrl, buildHeaders, normalizeError, API_CONFIG, resolveTenantKey } from '@/lib/api-client';
import type {
  LoginRequest,
  LoginResponse,
  SignupRequest,
  OtpSendRequest,
  OtpVerifyRequest,
  ApiResponse,
} from '@/types';

export class AuthService {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;

  setTokens(accessToken: string, refreshToken?: string) {
    this.accessToken = accessToken;
    if (refreshToken) this.refreshToken = refreshToken;
  }

  clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
  }

  getAccessToken(): string | null {
    return this.accessToken;
  }

  getRefreshToken(): string | null {
    return this.refreshToken;
  }

  isAuthenticated(): boolean {
    return !!this.accessToken;
  }

  // POST /v1/auth/signup
  async signup(tenantId: string, body: SignupRequest): Promise<ApiResponse<{ pending: boolean; principalId: string; challenge: { purpose: string; channel: string } }>> {
    const response = await fetch(getApiUrl('v1/auth/signup'), {
      method: 'POST',
      headers: buildHeaders(tenantId),
      credentials: 'include',
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // POST /v1/auth/login
  async login(tenantId: string, body: LoginRequest): Promise<LoginResponse> {
    const response = await fetch(getApiUrl('v1/auth/login'), {
      method: 'POST',
      headers: buildHeaders(tenantId),
      credentials: 'include',
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    this.setTokens(data.data.accessToken, data.data.refreshToken);
    return data;
  }

  // POST /v1/auth/refresh
  async refresh(tenantId: string): Promise<{ data: { accessToken: string; refreshToken?: string } }> {
    if (!this.refreshToken) throw new Error('No refresh token');
    const response = await fetch(getApiUrl('v1/auth/refresh'), {
      method: 'POST',
      headers: buildHeaders(tenantId),
      credentials: 'include',
      body: JSON.stringify({ refreshToken: this.refreshToken }),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    this.setTokens(data.data.accessToken, data.data.refreshToken);
    return data;
  }

  // POST /v1/auth/logout
  async logout(tenantId: string): Promise<void> {
    if (!this.accessToken) return;
    const response = await fetch(getApiUrl('v1/auth/logout'), {
      method: 'POST',
      headers: buildHeaders(tenantId, this.accessToken),
      credentials: 'include',
    });
    this.clearTokens();
    if (!response.ok) {
      const data = await response.json();
      throw normalizeError(data);
    }
  }

  // POST /v1/auth/logout-all
  async logoutAll(tenantId: string): Promise<void> {
    if (!this.accessToken) return;
    const response = await fetch(getApiUrl('v1/auth/logout-all'), {
      method: 'POST',
      headers: buildHeaders(tenantId, this.accessToken),
      credentials: 'include',
    });
    this.clearTokens();
    if (!response.ok) {
      const data = await response.json();
      throw normalizeError(data);
    }
  }

  // POST /v1/auth/otp/send
  async sendOtp(tenantId: string, body: OtpSendRequest): Promise<ApiResponse<{ sent: boolean; channel: string }>> {
    const response = await fetch(getApiUrl('v1/auth/otp/send'), {
      method: 'POST',
      headers: buildHeaders(tenantId),
      credentials: 'include',
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // POST /v1/auth/otp/verify
  async verifyOtp(tenantId: string, body: OtpVerifyRequest): Promise<ApiResponse<{ verified: boolean; accessToken?: string; refreshToken?: string }>> {
    const response = await fetch(getApiUrl('v1/auth/otp/verify'), {
      method: 'POST',
      headers: buildHeaders(tenantId),
      credentials: 'include',
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // Password reset flows
  async requestPasswordReset(tenantId: string, identity: string, identityType?: 'EMAIL' | 'PHONE') {
    const response = await fetch(getApiUrl('v1/auth/password/reset/request'), {
      method: 'POST',
      headers: buildHeaders(tenantId),
      credentials: 'include',
      body: JSON.stringify({ identity, identityType }),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  async confirmPasswordReset(tenantId: string, resetToken: string, newPassword: string) {
    const response = await fetch(getApiUrl('v1/auth/password/reset/confirm'), {
      method: 'POST',
      headers: buildHeaders(tenantId),
      credentials: 'include',
      body: JSON.stringify({ resetToken, newPassword }),
    });
    const data = await response.json();
    if (!response.ok) throw normalizeError(data);
    return data;
  }

  // OAuth redirect
  getOAuthRedirect(provider: 'google' | 'github', tenantId: string, redirectUri?: string): string {
    const params = new URLSearchParams({
      provider,
      tenantKey: tenantId || resolveTenantKey(),
      redirect_uri: redirectUri || `${window.location.origin}/auth/oauth/callback`,
    });
    return `${API_CONFIG.baseUrl}/v1/auth/oauth2/authorize?${params}`;
  }
}

export const authService = new AuthService();
