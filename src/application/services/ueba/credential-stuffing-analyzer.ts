import { Injectable, Logger } from '@nestjs/common';
import { ICachePort } from '../../ports/driven/i-cache.port';

/**
 * Detects credential stuffing attacks via cross-tenant and per-tenant sliding 10-minute windows.
 *
 * Keys (Section 10.1):
 *   cs:ip:{ipHash}:global:10m  — cross-tenant failure count (TTL 600s)
 *   cs:ip:{ipHash}:{tenantId}:10m — per-tenant failure count (TTL 600s)
 *
 * Scoring:
 *   global_failures > 30  → 1.0
 *   global_failures > 15  → 0.7
 *   tenant_failures > 10  → 0.5
 *   otherwise             → min(0.3, global_failures / 30)
 *
 * Implements: Req 11.6
 */
@Injectable()
export class CredentialStuffingAnalyzer {
  private readonly logger = new Logger(CredentialStuffingAnalyzer.name);

  /** Sliding window TTL in seconds (10 minutes). */
  private static readonly WINDOW_TTL_S = 600;

  constructor(private readonly cache: ICachePort) {}

  /**
   * Returns the current credential stuffing score without recording a failure.
   * Use `recordFailure()` to increment counters on a failed login.
   */
  async score(ipHash: string, tenantId: string): Promise<number> {
    try {
      const [globalRaw, tenantRaw] = await Promise.all([
        this.cache.get(`cs:ip:${ipHash}:global:10m`),
        this.cache.get(`cs:ip:${ipHash}:${tenantId}:10m`),
      ]);

      const globalFailures = globalRaw ? parseInt(globalRaw, 10) : 0;
      const tenantFailures = tenantRaw ? parseInt(tenantRaw, 10) : 0;

      return this.computeScore(globalFailures, tenantFailures);
    } catch (err) {
      this.logger.warn({ err }, 'CredentialStuffingAnalyzer failed — using 0.0');
      return 0.0;
    }
  }

  /**
   * Records a failed login attempt and returns the updated score.
   * Increments both global and per-tenant counters.
   */
  async recordFailure(ipHash: string, tenantId: string): Promise<number> {
    const globalKey = `cs:ip:${ipHash}:global:10m`;
    const tenantKey = `cs:ip:${ipHash}:${tenantId}:10m`;

    try {
      const [globalCount, tenantCount] = await Promise.all([
        this.incrementWindow(globalKey),
        this.incrementWindow(tenantKey),
      ]);

      return this.computeScore(globalCount, tenantCount);
    } catch (err) {
      this.logger.warn({ err }, 'CredentialStuffingAnalyzer.recordFailure failed — using 0.0');
      return 0.0;
    }
  }

  // ── Private ──────────────────────────────────────────────────────────────

  private async incrementWindow(key: string): Promise<number> {
    const count = await this.cache.incr(key);
    if (count === 1) {
      await this.cache.expire(key, CredentialStuffingAnalyzer.WINDOW_TTL_S);
    }
    return count;
  }

  private computeScore(globalFailures: number, tenantFailures: number): number {
    if (globalFailures > 30) return 1.0;
    if (globalFailures > 15) return 0.7;
    if (tenantFailures > 10) return 0.5;
    return Math.min(0.3, globalFailures / 30);
  }
}
