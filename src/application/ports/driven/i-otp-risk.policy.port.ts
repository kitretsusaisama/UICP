/**
 * Driven port - OTP Risk Policy Repository
 * Manages per-tenant risk policies for OTP verification
 */

export interface TenantOtpRiskPolicy {
  id: string;
  tenantId: string;
  maxAttemptsPerHour: number;
  maxAttemptsPerDay: number;
  maxAttemptsPerIdentity: number;
  allowedCountries: string[];
  blockedCountries: string[];
  blockUnknownGeo: boolean;
  requireDeviceFingerprint: boolean;
  blockUnknownDevices: boolean;
  maxDevicesPerIdentity: number;
  trustedProviders: string[];
  requireProviderVerification: boolean;
  riskThresholdLow: number;
  riskThresholdHigh: number;
  blockOnHighRisk: boolean;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface ITenantOtpRiskPolicyRepository {
  findByTenantId(tenantId: string): Promise<TenantOtpRiskPolicy | null>;
  create(policy: Omit<TenantOtpRiskPolicy, 'id' | 'createdAt' | 'updatedAt'>): Promise<TenantOtpRiskPolicy>;
  update(tenantId: string, policy: Partial<TenantOtpRiskPolicy>): Promise<TenantOtpRiskPolicy>;
  delete(tenantId: string): Promise<void>;
}