/**
 * Driven port - OTP Provider Repository
 * Manages per-tenant SMS/OTP provider configurations with circuit breaker state
 */

export interface CircuitState {
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  failureCount: number;
  lastFailure?: Date;
}

export interface RateLimitResult {
  allowed: boolean;
  current: number;
  limit: number;
  remaining: number;
}

export interface TenantOtpProvider {
  id: string;
  tenantId: string;
  providerName: string;
  providerType: string;
  credentialsRef: string;
  senderId: string | null;
  templateId: string | null;
  region: string | null;
  priority: number;
  isPrimary: boolean;
  isEnabled: boolean;
  circuitState: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  circuitFailureCount: number;
  circuitSuccessCount: number;
  circuitLastFailureAt: Date | null;
  circuitLastSuccessAt: Date | null;
  circuitResetAt: Date | null;
  tenantRateLimitPerMin: number;
  tenantDailyLimit: number;
  fallbackChain: string[] | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ITenantOtpProviderRepository {
  findByTenantId(tenantId: string): Promise<TenantOtpProvider[]>;
  findPrimaryByTenantId(tenantId: string): Promise<TenantOtpProvider | null>;
  findByTenantAndProvider(tenantId: string, providerName: string): Promise<TenantOtpProvider | null>;
  create(provider: Omit<TenantOtpProvider, 'id' | 'createdAt' | 'updatedAt'>): Promise<TenantOtpProvider>;
  update(tenantId: string, providerName: string, data: Partial<TenantOtpProvider>): Promise<TenantOtpProvider>;
  updateCircuitState(tenantId: string, providerName: string, state: 'CLOSED' | 'OPEN' | 'HALF_OPEN'): Promise<void>;
  incrementFailureCount(tenantId: string, providerName: string): Promise<void>;
  incrementSuccessCount(tenantId: string, providerName: string): Promise<void>;
  checkRateLimit(tenantId: string, providerName: string): Promise<{ current: number; limit: number }>;
  incrementRateLimit(tenantId: string, providerName: string): Promise<number>;
}