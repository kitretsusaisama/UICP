import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  ITenantOtpProviderRepository,
  TenantOtpProvider,
  CircuitState,
  RateLimitResult,
} from '../../../application/ports/driven/i-otp-provider.repository';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';
import { TenantIsolationGuard } from '../isolation/tenant-isolation-guard';

@Injectable()
export class TenantProviderRegistry {
  private readonly logger = new Logger(TenantProviderRegistry.name);

  constructor(
    private readonly isolationGuard: TenantIsolationGuard,
    @Inject(INJECTION_TOKENS.OTP_PROVIDER_REPO)
    private readonly providerRepo: ITenantOtpProviderRepository,
  ) {}

  async getProviders(tenantId: string): Promise<TenantOtpProvider[]> {
    await this.isolationGuard.validateTenantAccess({
      tenantId,
      operation: 'CONFIGURE',
    });

    return this.providerRepo.findByTenantId(tenantId);
  }

  async getPrimaryProvider(tenantId: string): Promise<TenantOtpProvider> {
    await this.isolationGuard.validateTenantAccess({
      tenantId,
      operation: 'SEND',
    });

    const primary = await this.providerRepo.findPrimaryByTenantId(tenantId);

    if (!primary) {
      throw new DomainException(
        DomainErrorCode.NO_PROVIDER_CONFIGURED,
        `Tenant ${tenantId} has no primary SMS provider`,
      );
    }

    const circuitState = await this.getCircuitState(tenantId, primary.providerName);

    if (circuitState.state === 'OPEN') {
      const fallback = await this.getFallbackChain(tenantId);
      const firstFallback = fallback[0];
      if (firstFallback) {
        this.logger.warn(
          { tenantId, primaryProvider: primary.providerName, usingFallback: firstFallback.providerName },
          'Primary provider circuit open, using fallback',
        );
        return firstFallback;
      }
      throw new DomainException(
        DomainErrorCode.CIRCUIT_BREAKER_OPEN,
        `Provider ${primary.providerName} is unavailable for tenant ${tenantId}`,
      );
    }

    return primary;
  }

  async getFallbackChain(tenantId: string): Promise<TenantOtpProvider[]> {
    const providers = await this.getProviders(tenantId);
    const fallbacks = providers.filter(p => !p.isPrimary);

    const availableFallbacks: TenantOtpProvider[] = [];
    for (const provider of fallbacks) {
      const circuitState = await this.getCircuitState(tenantId, provider.providerName);
      if (circuitState.state !== 'OPEN') {
        availableFallbacks.push(provider);
      }
    }

    return availableFallbacks.sort((a, b) => a.priority - b.priority);
  }

  async getCircuitState(tenantId: string, providerName: string): Promise<CircuitState> {
    const provider = await this.providerRepo.findByTenantAndProvider(tenantId, providerName);

    if (!provider) {
      return { state: 'CLOSED', failureCount: 0 };
    }

    return {
      state: provider.circuitState,
      failureCount: provider.circuitFailureCount,
      lastFailure: provider.circuitLastFailureAt ?? undefined,
    };
  }

  async recordFailure(tenantId: string, providerName: string): Promise<void> {
    await this.providerRepo.incrementFailureCount(tenantId, providerName);
    this.logger.warn(
      { tenantId, providerName },
      'Provider failure recorded, circuit breaker updated',
    );
  }

  async recordSuccess(tenantId: string, providerName: string): Promise<void> {
    await this.providerRepo.incrementSuccessCount(tenantId, providerName);
  }

  async checkRateLimit(tenantId: string, providerName: string): Promise<RateLimitResult> {
    const provider = await this.getPrimaryProvider(tenantId);
    const rateLimit = await this.providerRepo.checkRateLimit(tenantId, providerName);

    return {
      allowed: rateLimit.current < rateLimit.limit,
      current: rateLimit.current,
      limit: rateLimit.limit,
      remaining: Math.max(0, rateLimit.limit - rateLimit.current),
    };
  }

  async incrementRateLimit(tenantId: string, providerName: string): Promise<number> {
    return this.providerRepo.incrementRateLimit(tenantId, providerName);
  }

  async getProviderConfig(tenantId: string): Promise<{
    provider: TenantOtpProvider;
    config: Record<string, string>;
  }> {
    const provider = await this.getPrimaryProvider(tenantId);

    return {
      provider,
      config: {
        credentialsRef: provider.credentialsRef,
        senderId: provider.senderId ?? '',
        templateId: provider.templateId ?? '',
        providerType: provider.providerType,
      },
    };
  }

  async getProviderCredentials(tenantId: string, providerName: string): Promise<{
    apiKey: string;
    senderId: string;
    templateId: string;
  }> {
    const provider = await this.providerRepo.findByTenantAndProvider(tenantId, providerName);

    if (!provider) {
      throw new Error(`Provider ${providerName} not found for tenant ${tenantId}`);
    }

    // In production, fetch encrypted credentials from vault
    // For now, return credentials ref which should be resolved by vault service
    return {
      apiKey: provider.credentialsRef,
      senderId: provider.senderId ?? '',
      templateId: provider.templateId ?? '',
    };
  }
}