/**
 * Driven port - OTP Adaptive Model Repository
 * Stores per-tenant ML model data for adaptive delivery
 */

export interface TenantOtpAdaptiveModel {
  id: string;
  tenantId: string;
  channelSuccessRates: Record<string, number>;
  providerSuccessRates: Record<string, number>;
  hourlyPatterns: Record<string, string>;
  userSegmentPatterns: Record<string, string>;
  modelVersion: number;
  lastTrainedAt: Date | null;
  trainingDataPoints: number;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface ITenantOtpAdaptiveModelRepository {
  findByTenantId(tenantId: string): Promise<TenantOtpAdaptiveModel | null>;
  create(model: Omit<TenantOtpAdaptiveModel, 'id' | 'createdAt' | 'updatedAt'>): Promise<TenantOtpAdaptiveModel>;
  update(tenantId: string, model: Partial<TenantOtpAdaptiveModel>): Promise<TenantOtpAdaptiveModel>;
  upsert(tenantId: string, model: Partial<TenantOtpAdaptiveModel>): Promise<TenantOtpAdaptiveModel>;
}