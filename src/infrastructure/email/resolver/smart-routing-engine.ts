import { Injectable, Logger } from '@nestjs/common';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';
import { EmailCircuitBreaker, CircuitBreakerState } from '../circuit/email-circuit-breaker';

export interface TenantEmailProvider {
  id: string;
  tenantId: string;
  providerKey: string;
  providerName: string;
  fromEmail: string;
  fromName?: string;
  priority: number;
  isPrimary: boolean;
  isEnabled: boolean;
  weight: number;
  rateLimitPerMin: number;
  dailyLimit: number;
  circuitState: CircuitBreakerState['state'];
  successCount24h: number;
  failureCount24h: number;
  avgLatencyMs: number;
}

export interface RoutingScore {
  provider: TenantEmailProvider;
  score: number;
  reasons: string[];
}

export interface SendEmailPayload {
  tenantId: string;
  lineageId: string;
  recipient: string;
  subject: string;
  text: string;
  html: string;
  purpose: string;
  traceId: string;
}

@Injectable()
export class SmartRoutingEngine {
  private readonly logger = new Logger(SmartRoutingEngine.name);

  constructor(
    private readonly circuitBreaker: EmailCircuitBreaker,
  // Inject repository via method to avoid circular dependency
  private readonly _providerRepo?: { findEnabledByTenantId: (tenantId: string) => Promise<TenantEmailProvider[]> },
  private readonly _rateLimiter?: { checkRateLimit: (provider: TenantEmailProvider) => Promise<{ allowed: boolean; current: number; limit: number }> },
  ) {}

  async selectProvider(
    providers: TenantEmailProvider[],
    _payload?: SendEmailPayload,
  ): Promise<TenantEmailProvider> {
    if (providers.length === 0) {
      throw new DomainException(
        DomainErrorCode.NO_PROVIDER_CONFIGURED,
        'No email providers configured for tenant',
      );
    }

    // Filter to only enabled providers
    const enabled = providers.filter((p) => p.isEnabled);

    if (enabled.length === 0) {
      throw new DomainException(
        DomainErrorCode.NO_PROVIDER_CONFIGURED,
        'No enabled email providers for tenant',
      );
    }

    // Score each provider
    const scored = await Promise.all(
      enabled.map((p) => this.scoreProvider(p)),
    );

    // Sort by score descending
    scored.sort((a, b) => b.score - a.score);

    // Find first available (circuit not OPEN)
    const available = scored.find(
      (s) => s.provider.circuitState !== 'OPEN',
    );

    if (!available) {
      this.logger.error(
        { tenantId: providers[0]?.tenantId, providers: providers.map((p) => p.providerKey) },
        'All provider circuits are OPEN',
      );
      throw new DomainException(
        DomainErrorCode.CIRCUIT_BREAKER_OPEN,
        'All email provider circuits are open',
      );
    }

    this.logger.debug(
      {
        tenantId: available.provider.tenantId,
        selected: available.provider.providerKey,
        score: available.score,
        reasons: available.reasons,
      },
      'Provider selected by smart routing',
    );

    return available.provider;
  }

  private async scoreProvider(
    provider: TenantEmailProvider,
  ): Promise<RoutingScore> {
    let score = 100;
    const reasons: string[] = [];

    // Circuit state check (CRITICAL - must be checked first)
    const isAvailable = await this.circuitBreaker.isAvailable(
      provider.tenantId,
      provider.providerKey,
    );

    if (!isAvailable) {
      return {
        provider,
        score: -1000,
        reasons: ['Circuit breaker OPEN'],
      };
    }

    // Circuit HALF_OPEN: penalty but still available
    if (provider.circuitState === 'HALF_OPEN') {
      score -= 30;
      reasons.push('Circuit HALF_OPEN (-30)');
    }

    // Calculate success rate
    const total = provider.successCount24h + provider.failureCount24h;
    const successRate = total === 0 ? 1.0 : provider.successCount24h / total;

    // Success rate scoring
    if (successRate >= 0.99) {
      score += 20;
      reasons.push(`Excellent success rate ${(successRate * 100).toFixed(1)}% (+20)`);
    } else if (successRate >= 0.95) {
      score += 10;
      reasons.push(`High success rate ${(successRate * 100).toFixed(1)}% (+10)`);
    } else if (successRate >= 0.90) {
      score += 0;
      reasons.push(`Good success rate ${(successRate * 100).toFixed(1)}%`);
    } else if (successRate >= 0.80) {
      score -= 20;
      reasons.push(`Low success rate ${(successRate * 100).toFixed(1)}% (-20)`);
    } else {
      score -= 50;
      reasons.push(`Poor success rate ${(successRate * 100).toFixed(1)}% (-50)`);
    }

    // Latency scoring
    if (provider.avgLatencyMs) {
      if (provider.avgLatencyMs < 200) {
        score += 15;
        reasons.push(`Fast latency ${provider.avgLatencyMs}ms (+15)`);
      } else if (provider.avgLatencyMs < 500) {
        score += 10;
        reasons.push(`Good latency ${provider.avgLatencyMs}ms (+10)`);
      } else if (provider.avgLatencyMs > 2000) {
        score -= 30;
        reasons.push(`Slow latency ${provider.avgLatencyMs}ms (-30)`);
      } else {
        score += 0;
        reasons.push(`Latency ${provider.avgLatencyMs}ms`);
      }
    }

    // Primary provider bonus
    if (provider.isPrimary) {
      score += 25;
      reasons.push('Primary provider (+25)');
    }

    // Priority weight
    score += provider.priority * 5;
    reasons.push(`Priority ${provider.priority} (${provider.priority * 5})`);

    // Weight configuration (for weighted round-robin)
    const weightScore = (provider.weight / 100);
    score *= weightScore;
    if (weightScore > 1) {
      reasons.push(`High weight ${provider.weight}%`);
    } else if (weightScore < 1) {
      reasons.push(`Low weight ${provider.weight}%`);
    }

    // Rate limit headroom check (simplified - in production, query actual usage)
    const limit = provider.rateLimitPerMin;
    if (limit >= 100) {
      score += 5;
      reasons.push(`High rate limit ${limit}/min (+5)`);
    }

    return { provider, score, reasons };
  }

  // Get ordered provider list for fallback chain
  async getOrderedProviders(
    providers: TenantEmailProvider[],
  ): Promise<TenantEmailProvider[]> {
    const scored = await Promise.all(
      providers.map((p) => this.scoreProvider(p)),
    );

    scored.sort((a, b) => b.score - a.score);

    return scored
      .filter((s) => s.score > -100)
      .map((s) => s.provider);
  }
}