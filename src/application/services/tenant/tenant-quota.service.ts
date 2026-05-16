/**
 * Tenant Quota Service
 *
 * Manages per-tenant API quota tracking and spend limits.
 * Provides data for tenant health dashboard.
 */

import { Inject, Injectable, Logger } from '@nestjs/common';
import { ICachePort } from '../../ports/driven/i-cache.port';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';

export interface TenantQuota {
  tenantId: string;
  /** API requests remaining this window */
  apiRequestsRemaining: number;
  /** Total API requests allowed per window */
  apiRequestsLimit: number;
  /** SMS credits remaining */
  smsCreditsRemaining: number;
  /** Total SMS credits allowed */
  smsCreditsLimit: number;
  /** Storage bytes remaining */
  storageRemaining: number;
  /** Total storage bytes allowed */
  storageLimit: number;
  /** Window start timestamp (UTC) */
  windowStart: number;
  /** Window duration in seconds */
  windowDurationSeconds: number;
}

export interface QuotaUsage {
  tenantId: string;
  apiRequests: { used: number; limit: number; percentage: number };
  sms: { used: number; limit: number; percentage: number };
  storage: { used: number; limit: number; percentage: number };
}

export enum QuotaCheckResult {
  ALLOWED = 'ALLOWED',
  API_LIMIT_EXCEEDED = 'API_LIMIT_EXCEEDED',
  SMS_LIMIT_EXCEEDED = 'SMS_LIMIT_EXCEEDED',
  STORAGE_LIMIT_EXCEEDED = 'STORAGE_LIMIT_EXCEEDED',
}

@Injectable()
export class TenantQuotaService {
  private readonly logger = new Logger(TenantQuotaService.name);

  constructor(
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
  ) {}

  /**
   * Check if tenant has quota for requested resource.
   */
  async checkQuota(
    tenantId: string,
    resource: 'api' | 'sms' | 'storage',
    amount: number = 1,
  ): Promise<{ allowed: boolean; result: QuotaCheckResult; remaining: number }> {
    const quota = await this.getQuota(tenantId);

    switch (resource) {
      case 'api':
        if (quota.apiRequestsRemaining < amount) {
          return { allowed: false, result: QuotaCheckResult.API_LIMIT_EXCEEDED, remaining: 0 };
        }
        return { allowed: true, result: QuotaCheckResult.ALLOWED, remaining: quota.apiRequestsRemaining - amount };

      case 'sms':
        if (quota.smsCreditsRemaining < amount) {
          return { allowed: false, result: QuotaCheckResult.SMS_LIMIT_EXCEEDED, remaining: 0 };
        }
        return { allowed: true, result: QuotaCheckResult.ALLOWED, remaining: quota.smsCreditsRemaining - amount };

      case 'storage':
        if (quota.storageRemaining < amount) {
          return { allowed: false, result: QuotaCheckResult.STORAGE_LIMIT_EXCEEDED, remaining: 0 };
        }
        return { allowed: true, result: QuotaCheckResult.ALLOWED, remaining: quota.storageRemaining - amount };
    }
  }

  /**
   * Consume quota for a resource.
   */
  async consumeQuota(tenantId: string, resource: 'api' | 'sms' | 'storage', amount: number): Promise<void> {
    const quota = await this.getQuota(tenantId);
    const key = `tenant-quota:${tenantId}`;

    switch (resource) {
      case 'api':
        quota.apiRequestsRemaining = Math.max(0, quota.apiRequestsRemaining - amount);
        break;
      case 'sms':
        quota.smsCreditsRemaining = Math.max(0, quota.smsCreditsRemaining - amount);
        break;
      case 'storage':
        quota.storageRemaining = Math.max(0, quota.storageRemaining - amount);
        break;
    }

    await this.cache.set(key, JSON.stringify(quota), quota.windowDurationSeconds);
  }

  /**
   * Get current quota usage for a tenant.
   */
  async getUsage(tenantId: string): Promise<QuotaUsage | null> {
    const quota = await this.getQuota(tenantId);
    if (!quota) return null;

    return {
      tenantId,
      apiRequests: {
        used: quota.apiRequestsLimit - quota.apiRequestsRemaining,
        limit: quota.apiRequestsLimit,
        percentage: ((quota.apiRequestsLimit - quota.apiRequestsRemaining) / quota.apiRequestsLimit) * 100,
      },
      sms: {
        used: quota.smsCreditsLimit - quota.smsCreditsRemaining,
        limit: quota.smsCreditsLimit,
        percentage: ((quota.smsCreditsLimit - quota.smsCreditsRemaining) / quota.smsCreditsLimit) * 100,
      },
      storage: {
        used: quota.storageLimit - quota.storageRemaining,
        limit: quota.storageLimit,
        percentage: ((quota.storageLimit - quota.storageRemaining) / quota.storageLimit) * 100,
      },
    };
  }

  /**
   * Reset quota for a tenant (admin action).
   */
  async resetQuota(tenantId: string): Promise<void> {
    const key = `tenant-quota:${tenantId}`;
    await this.cache.del(key);
    this.logger.log({ tenantId }, 'Tenant quota reset');
  }

  private async getQuota(tenantId: string): Promise<TenantQuota> {
    const key = `tenant-quota:${tenantId}`;
    const cached = await this.cache.get(key);

    if (cached) {
      return JSON.parse(cached) as TenantQuota;
    }

    // Return default quota for new tenants
    const quota: TenantQuota = {
      tenantId,
      apiRequestsRemaining: 10000,
      apiRequestsLimit: 10000,
      smsCreditsRemaining: 1000,
      smsCreditsLimit: 1000,
      storageRemaining: 1024 * 1024 * 1024, // 1GB
      storageLimit: 1024 * 1024 * 1024,
      windowStart: this.getWindowStart(),
      windowDurationSeconds: 86400, // 24 hours
    };

    await this.cache.set(key, JSON.stringify(quota), quota.windowDurationSeconds);
    return quota;
  }

  private getWindowStart(): number {
    const now = new Date();
    now.setHours(0, 0, 0, 0);
    return Math.floor(now.getTime() / 1000);
  }
}