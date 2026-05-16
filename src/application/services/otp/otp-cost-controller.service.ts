import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ICachePort } from '../../ports/driven/i-cache.port';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';

// ── Types ────────────────────────────────────────────────────────────────────

export interface OtpSpendQuota {
  tenantId: string;
  dailyLimit: number;        // e.g., ₹10,000
  spentToday: number;
  windowStart: number;       // Unix timestamp (start of day)
  circuitState: 'closed' | 'open' | 'half-open';
}

export interface OtpCostConfig {
  /** Cost per SMS in cents (e.g., 300 = ₹3). */
  smsCostCents: number;
  /** Default daily limit per tenant in cents. */
  defaultDailyLimitCents: number;
  /** Threshold for alert (0.0 - 1.0). */
  alertThreshold: number;
  /** Circuit breaker reset time in ms. */
  circuitResetMs: number;
}

export enum OtpCostResult {
  ALLOWED = 'ALLOWED',
  BLOCKED_LIMIT_EXCEEDED = 'BLOCKED_LIMIT_EXCEEDED',
  BLOCKED_CIRCUIT_OPEN = 'BLOCKED_CIRCUIT_OPEN',
  FALLBACK_TO_EMAIL = 'FALLBACK_TO_EMAIL',
}

// ── Service ─────────────────────────────────────────────────────────────────

/**
 * OtpCostControllerService — enforces tenant OTP spend limits and prevents cost explosion.
 *
 * Key features:
 * - Per-tenant daily spend tracking in Redis
 * - Circuit breaker (closed → open → half-open)
 * - Alert at 90% threshold
 * - Fallback to email when circuit opens
 */
@Injectable()
export class OtpCostControllerService {
  private readonly logger = new Logger(OtpCostControllerService.name);
  private readonly config: OtpCostConfig;

  constructor(
    private readonly configService: ConfigService,
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
  ) {
    this.config = {
      smsCostCents: this.configService.get<number>('OTP_SMS_COST_CENTS', 300),
      defaultDailyLimitCents: this.configService.get<number>('OTP_DAILY_LIMIT_CENTS', 100000), // ₹10,000
      alertThreshold: 0.9,
      circuitResetMs: 60_000, // 1 minute
    };
  }

  /**
   * Check if OTP can be sent and track the cost.
   * Returns { allowed, reason, fallbackEmail }.
   */
  async checkAndTrack(
    tenantId: string,
    channel: 'sms' | 'email',
  ): Promise<{ allowed: boolean; result: OtpCostResult; fallbackEmail?: boolean }> {
    // Email is always allowed (no cost)
    if (channel === 'email') {
      return { allowed: true, result: OtpCostResult.ALLOWED };
    }

    const quota = await this.getOrCreateQuota(tenantId);

    // Check circuit breaker
    if (quota.circuitState === 'open') {
      // Check if we should try half-open
      const timeSinceOpen = Date.now() - (quota.windowStart * 1000);
      if (timeSinceOpen > this.config.circuitResetMs) {
        await this.setCircuitState(tenantId, 'half-open');
        return { allowed: true, result: OtpCostResult.ALLOWED };
      }

      this.logger.warn({ tenantId, spent: quota.spentToday }, 'OTP circuit open - blocking SMS');
      return { allowed: false, result: OtpCostResult.BLOCKED_CIRCUIT_OPEN, fallbackEmail: true };
    }

    // Check daily limit
    if (quota.spentToday >= quota.dailyLimit) {
      await this.openCircuit(tenantId);
      this.logger.error({ tenantId, spent: quota.spentToday, limit: quota.dailyLimit }, 'OTP daily limit exceeded');
      return { allowed: false, result: OtpCostResult.BLOCKED_LIMIT_EXCEEDED, fallbackEmail: true };
    }

    // Track the cost
    const newSpent = quota.spentToday + this.config.smsCostCents;
    await this.incrementSpend(tenantId, this.config.smsCostCents);

    // Check 90% threshold for alert
    if (newSpent >= quota.dailyLimit * this.config.alertThreshold) {
      this.logger.warn(
        { tenantId, spent: newSpent, limit: quota.dailyLimit, percentage: (newSpent / quota.dailyLimit) * 100 },
        'OTP spend at 90% threshold - consider alerting',
      );
      // TODO: Integrate with alerting service (Slack, PagerDuty, etc.)
    }

    return { allowed: true, result: OtpCostResult.ALLOWED };
  }

  /**
   * Get current quota for a tenant (for dashboard/admin).
   */
  async getQuota(tenantId: string): Promise<OtpSpendQuota | null> {
    return this.getOrCreateQuota(tenantId);
  }

  /**
   * Reset circuit breaker (for manual reset or testing).
   */
  async resetCircuit(tenantId: string): Promise<void> {
    await this.setCircuitState(tenantId, 'closed');
    this.logger.log({ tenantId }, 'OTP circuit breaker reset');
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private getDailyWindowStart(): number {
    const now = new Date();
    now.setHours(0, 0, 0, 0);
    return Math.floor(now.getTime() / 1000);
  }

  private async getOrCreateQuota(tenantId: string): Promise<OtpSpendQuota> {
    const key = `otp-spend:${tenantId}`;
    const windowStart = this.getDailyWindowStart();

    try {
      const stored = await this.cache.get(key);
      if (stored) {
        const quota = JSON.parse(stored) as OtpSpendQuota;

        // Reset if new day
        if (quota.windowStart !== windowStart) {
          return this.createQuota(tenantId, windowStart);
        }

        return quota;
      }
    } catch {
      // Ignore parse errors
    }

    return this.createQuota(tenantId, windowStart);
  }

  private async createQuota(tenantId: string, windowStart: number): Promise<OtpSpendQuota> {
    const quota: OtpSpendQuota = {
      tenantId,
      dailyLimit: this.config.defaultDailyLimitCents,
      spentToday: 0,
      windowStart,
      circuitState: 'closed',
    };

    await this.saveQuota(tenantId, quota);
    return quota;
  }

  private async saveQuota(tenantId: string, quota: OtpSpendQuota): Promise<void> {
    const key = `otp-spend:${tenantId}`;
    // TTL of 25 hours to cover across day boundaries
    await this.cache.set(key, JSON.stringify(quota), 90_000);
  }

  private async incrementSpend(tenantId: string, cents: number): Promise<void> {
    const quota = await this.getOrCreateQuota(tenantId);
    quota.spentToday += cents;
    await this.saveQuota(tenantId, quota);
  }

  private async setCircuitState(tenantId: string, state: 'closed' | 'open' | 'half-open'): Promise<void> {
    const quota = await this.getOrCreateQuota(tenantId);
    quota.circuitState = state;
    await this.saveQuota(tenantId, quota);
  }

  private async openCircuit(tenantId: string): Promise<void> {
    await this.setCircuitState(tenantId, 'open');
    this.logger.error({ tenantId }, 'OTP circuit breaker opened');
  }
}