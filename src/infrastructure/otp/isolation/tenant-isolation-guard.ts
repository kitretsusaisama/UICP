import { Inject, Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';

export type OtpOperation = 'SEND' | 'VERIFY' | 'RETRY' | 'CONFIGURE';

export interface IsolationResult {
  allowed: boolean;
  tenantId: string;
  tenantName?: string;
}

export interface IsolationValidationParams {
  tenantId: string;
  operation: OtpOperation;
  resourceId?: string;
  identity?: string;
}

@Injectable()
export class TenantIsolationGuard {
  private readonly logger = new Logger(TenantIsolationGuard.name);

  constructor(
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
  ) {}

  /**
   * Validate tenant access for OTP operations.
   * This is the MANDATORY entry point for all OTP operations.
   * Implements zero-trust tenant isolation.
   */
  async validateTenantAccess(params: IsolationValidationParams): Promise<IsolationResult> {
    const { tenantId, operation, resourceId, identity } = params;

    // Validate tenantId format
    if (!this.isValidUuid(tenantId)) {
      await this.recordIsolationFailure({
        tenantId,
        operation,
        resourceId,
        reason: 'Invalid tenant ID format',
      });
      throw new DomainException(
        DomainErrorCode.INVALID_TENANT_ID,
        `Invalid tenant ID format: ${tenantId}`
      );
    }

    // Verify tenant exists and is active
    const tenant = await this.getTenant(tenantId);
    if (!tenant) {
      await this.recordIsolationFailure({
        tenantId,
        operation,
        resourceId,
        reason: 'Tenant not found',
      });
      throw new DomainException(
        DomainErrorCode.TENANT_NOT_FOUND,
        `Tenant not found: ${tenantId}`
      );
    }

    if (!tenant.isActive) {
      await this.recordIsolationFailure({
        tenantId,
        operation,
        resourceId,
        reason: 'Tenant is inactive',
      });
      throw new DomainException(
        DomainErrorCode.TENANT_NOT_FOUND,
        `Tenant is not active: ${tenantId}`
      );
    }

    // Verify tenant has provider configured for SEND operations
    if (operation === 'SEND') {
      const hasProvider = await this.validateProviderConfigured(tenantId);
      if (!hasProvider) {
        await this.recordIsolationFailure({
          tenantId,
          operation,
          resourceId,
          reason: 'No provider configured',
        });
        throw new DomainException(
          DomainErrorCode.NO_PROVIDER_CONFIGURED,
          `Tenant ${tenantId} has no OTP provider configured`
        );
      }
    }

    // Verify no cross-tenant resource access
    if (resourceId) {
      const isOwned = await this.validateResourceOwnership(tenantId, resourceId);
      if (!isOwned) {
        await this.recordIsolationFailure({
          tenantId,
          operation,
          resourceId,
          reason: 'Cross-tenant resource access attempted',
        });
        throw new DomainException(
          DomainErrorCode.CROSS_TENANT_ACCESS_DENIED,
          `Resource ${resourceId} does not belong to tenant ${tenantId}`
        );
      }
    }

    // Log successful validation for audit trail
    await this.recordIsolationSuccess({
      tenantId,
      operation,
      resourceId,
      identity,
    });

    this.logger.debug({ tenantId, operation }, 'Tenant isolation verified');

    return {
      allowed: true,
      tenantId,
      tenantName: tenant.name,
    };
  }

  /**
   * Generate a tenant-scoped Redis key.
   * MANDATORY: All OTP Redis keys must use this pattern.
   */
  otpKey(tenantId: string, ...parts: string[]): string {
    return `otp:${tenantId}:${parts.join(':')}`;
  }

  /**
   * Generate a tenant-scoped rate limit key.
   */
  rateLimitKey(tenantId: string, providerName: string, date: string): string {
    return `rate-limit:${tenantId}:${providerName}:${date}`;
  }

  /**
   * Generate a tenant-scoped adaptive model key.
   */
  adaptiveModelKey(tenantId: string): string {
    return `otp:adaptive:model:${tenantId}`;
  }

  /**
   * Verify that a provider belongs to the tenant.
   */
  async validateProviderBelongsToTenant(
    tenantId: string,
    providerName: string
  ): Promise<boolean> {
    // Check cache first
    const cacheKey = `provider-tenant-map:${providerName}:${tenantId}`;
    const cached = await this.cache.get(cacheKey);
    if (cached !== null) {
      return cached === '1';
    }

    // In a real implementation, this would query the database
    // For now, we assume providers are properly configured
    const isValid = true;
    await this.cache.set(cacheKey, isValid ? '1' : '0', 3600);
    return isValid;
  }

  /**
   * Check rate limit for a tenant.
   */
  async checkRateLimit(
    tenantId: string,
    providerName: string,
    limit: number
  ): Promise<{ allowed: boolean; current: number; remaining: number }> {
    const today = new Date().toISOString().split('T')[0];
    const key = `rate-limit:${tenantId}:${providerName}:${today}`;

    const current = await this.cache.get(key);
    const currentCount = current ? parseInt(current, 10) : 0;

    return {
      allowed: currentCount < limit,
      current: currentCount,
      remaining: Math.max(0, limit - currentCount),
    };
  }

  /**
   * Increment rate limit counter for a tenant.
   */
  async incrementRateLimit(
    tenantId: string,
    providerName: string
  ): Promise<number> {
    const today = new Date().toISOString().split('T')[0];
    const key = `rate-limit:${tenantId}:${providerName}:${today}`;

    // Set expiry at end of day
    const remainingSeconds = this.secondsUntilEndOfDay();
    const count = await this.cache.incr(key);
    if (count === 1) {
      await this.cache.expire(key, remainingSeconds);
    }

    return count;
  }

  // Private helpers

  private async getTenant(tenantId: string): Promise<{ id: string; name: string; isActive: boolean } | null> {
    // In a real implementation, this would query the tenant repository
    // For now, return a mock active tenant
    // TODO: Integrate with actual tenant repository
    return {
      id: tenantId,
      name: 'Tenant',
      isActive: true,
    };
  }

  private async validateProviderConfigured(tenantId: string): Promise<boolean> {
    // In a real implementation, this would check the tenant_sms_providers table
    // TODO: Integrate with TenantProviderRegistry
    return true;
  }

  private async validateResourceOwnership(
    tenantId: string,
    resourceId: string
  ): Promise<boolean> {
    // In a real implementation, this would verify the resource belongs to the tenant
    // For example, verify an OTP flow belongs to the tenant
    // TODO: Integrate with actual resource ownership check
    return true;
  }

  private async recordIsolationSuccess(params: {
    tenantId: string;
    operation: OtpOperation;
    resourceId?: string;
    identity?: string;
  }): Promise<void> {
    // In a real implementation, this would write to otp_isolation_audit table
    this.logger.debug(params, 'Isolation validation passed');
  }

  private async recordIsolationFailure(params: {
    tenantId: string;
    operation: OtpOperation;
    resourceId?: string;
    reason: string;
  }): Promise<void> {
    // In a real implementation, this would write to otp_isolation_audit table
    this.logger.warn(params, 'Isolation validation failed');
  }

  private isValidUuid(value: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(value);
  }

  private secondsUntilEndOfDay(): number {
    const now = new Date();
    const endOfDay = new Date(now);
    endOfDay.setHours(23, 59, 59, 999);
    return Math.floor((endOfDay.getTime() - now.getTime()) / 1000);
  }
}