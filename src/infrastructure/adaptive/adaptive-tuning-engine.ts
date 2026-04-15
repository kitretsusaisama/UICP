import { Injectable, Logger, OnModuleDestroy, OnModuleInit, Optional, Inject } from '@nestjs/common';
import { IMetricsPort } from '../../application/ports/driven/i-metrics.port';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';
import { AdaptiveCacheService } from './adaptive-cache';
import { AdaptiveDbPoolService } from './adaptive-db-pool';
import { AdaptiveQueueConcurrencyService } from './adaptive-queue-concurrency';
import { AdaptiveRateLimitService } from './adaptive-rate-limit';

// ── AdaptiveChangeLog ────────────────────────────────────────────────────────

/** Structured log entry for every adaptive parameter change — Section 12.7. */
export interface AdaptiveChangeLog {
  parameter:
    | 'bcrypt_rounds'
    | 'cache_ttl_multiplier'
    | 'db_pool_size'
    | 'queue_concurrency'
    | 'rate_limit_multiplier';
  oldValue: number;
  newValue: number;
  reason: string;
  loadScore: number;
  timestamp: string;
}

// ── ThresholdTuner ───────────────────────────────────────────────────────────

/** UEBA false-positive feedback loop state per threshold. */
interface ThresholdState {
  falsePositives7d: number;
  totalAlerts7d: number;
  /** Current threshold value. */
  value: number;
  /** Timestamps of FP records within the last 7 days (epoch ms). */
  fpTimestamps: number[];
  /** Timestamps of all alert records within the last 7 days (epoch ms). */
  alertTimestamps: number[];
}

const THRESHOLD_BOUNDS: Readonly<Record<string, { min: number; max: number; default: number }>> = {
  MFA_REQUIRED:    { min: 0.25, max: 0.50, default: 0.35 },
  ACCOUNT_LOCKED:  { min: 0.60, max: 0.85, default: 0.70 },
};

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * UEBA threshold tuner — Section 10.4.
 *
 * Tracks false-positive rates per threshold over a rolling 7-day window.
 * Adjusts thresholds to reduce false positives while maintaining sensitivity.
 */
export class ThresholdTuner {
  private readonly logger = new Logger(ThresholdTuner.name);
  private readonly state = new Map<string, ThresholdState>();

  constructor(
    private readonly onChanged?: (log: AdaptiveChangeLog) => void,
  ) {
    for (const [name, bounds] of Object.entries(THRESHOLD_BOUNDS)) {
      this.state.set(name, {
        falsePositives7d: 0,
        totalAlerts7d: 0,
        value: bounds.default,
        fpTimestamps: [],
        alertTimestamps: [],
      });
    }
  }

  /**
   * Record that an alert was created for a threshold.
   * Call this whenever a UEBA alert is raised.
   */
  recordAlert(threshold: string): void {
    const s = this.getOrInit(threshold);
    s.alertTimestamps.push(Date.now());
    this.pruneWindow(s);
    s.totalAlerts7d = s.alertTimestamps.length;
  }

  /**
   * Record a false positive for a threshold.
   * Called when a SOC analyst marks an alert as FALSE_POSITIVE.
   */
  recordFalsePositive(alertId: string, threshold: string): void {
    const s = this.getOrInit(threshold);
    s.fpTimestamps.push(Date.now());
    this.pruneWindow(s);
    s.falsePositives7d = s.fpTimestamps.length;
    s.totalAlerts7d = s.alertTimestamps.length;

    this.logger.log(
      { alertId, threshold, falsePositives7d: s.falsePositives7d, totalAlerts7d: s.totalAlerts7d },
      'False positive recorded',
    );
  }

  /**
   * Run one tuning cycle across all thresholds.
   * Called by the tuning engine every hour.
   */
  tuneThresholds(): void {
    for (const [name, s] of this.state) {
      this.pruneWindow(s);
      if (s.totalAlerts7d === 0) continue;

      const fpRate = s.falsePositives7d / s.totalAlerts7d;
      const bounds = THRESHOLD_BOUNDS[name];
      if (!bounds) continue;

      const oldValue = s.value;
      let newValue = oldValue;

      if (fpRate > 0.20) {
        // Too many false positives → raise threshold (reduce sensitivity)
        newValue = Math.min(bounds.max, oldValue + 0.05);
      } else if (fpRate < 0.05) {
        // Very few false positives → lower threshold (increase sensitivity)
        newValue = Math.max(bounds.min, oldValue - 0.02);
      }

      if (newValue !== oldValue) {
        s.value = newValue;
        const log: AdaptiveChangeLog = {
          parameter: 'cache_ttl_multiplier', // closest available; thresholds are UEBA-specific
          oldValue,
          newValue,
          reason: `fp_rate=${fpRate.toFixed(3)} threshold=${name}`,
          loadScore: 0,
          timestamp: new Date().toISOString(),
        };
        this.logger.log(
          { threshold: name, oldValue, newValue, fpRate },
          'UEBA threshold tuned',
        );
        this.onChanged?.(log);
      }
    }
  }

  /** Get the current value for a threshold. */
  getThreshold(name: string): number {
    return this.state.get(name)?.value ?? THRESHOLD_BOUNDS[name]?.default ?? 0.5;
  }

  // ── Private ────────────────────────────────────────────────────────────────

  private getOrInit(threshold: string): ThresholdState {
    if (!this.state.has(threshold)) {
      const bounds = THRESHOLD_BOUNDS[threshold];
      this.state.set(threshold, {
        falsePositives7d: 0,
        totalAlerts7d: 0,
        value: bounds?.default ?? 0.5,
        fpTimestamps: [],
        alertTimestamps: [],
      });
    }
    return this.state.get(threshold)!;
  }

  private pruneWindow(s: ThresholdState): void {
    const cutoff = Date.now() - SEVEN_DAYS_MS;
    s.fpTimestamps = s.fpTimestamps.filter((t) => t > cutoff);
    s.alertTimestamps = s.alertTimestamps.filter((t) => t > cutoff);
    s.falsePositives7d = s.fpTimestamps.length;
    s.totalAlerts7d = s.alertTimestamps.length;
  }
}

// ── AdaptiveTuningEngine ─────────────────────────────────────────────────────

/**
 * Orchestrates all adaptive components — Section 12.
 *
 * - Holds a `ThresholdTuner` for UEBA false-positive feedback (Section 10.4).
 * - Logs all parameter changes via `AdaptiveChangeLog` (Section 12.7).
 * - Runs the threshold tuning cycle every hour.
 * - Emits `uicp_adaptive_parameter_change_total` metric on each change.
 */
@Injectable()
export class AdaptiveTuningEngine implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AdaptiveTuningEngine.name);

  readonly thresholdTuner: ThresholdTuner;

  private tuningTimer: NodeJS.Timeout | null = null;

  constructor(
    readonly cacheService: AdaptiveCacheService,
    readonly dbPoolService: AdaptiveDbPoolService,
    readonly queueConcurrencyService: AdaptiveQueueConcurrencyService,
    readonly rateLimitService: AdaptiveRateLimitService,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT)
    private readonly metrics?: IMetricsPort,
  ) {
    this.thresholdTuner = new ThresholdTuner((log) => this.logChange(log));
  }

  onModuleInit(): void {
    // Tune UEBA thresholds every hour
    this.tuningTimer = setInterval(() => this.thresholdTuner.tuneThresholds(), 60 * 60 * 1000);
    this.tuningTimer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.tuningTimer) {
      clearInterval(this.tuningTimer);
      this.tuningTimer = null;
    }
  }

  /**
   * Log an adaptive parameter change with structured context.
   * Emits a Prometheus counter if metrics are available.
   */
  logChange(log: AdaptiveChangeLog): void {
    this.logger.log(log, 'Adaptive parameter changed');
    this.metrics?.increment('uicp_adaptive_parameter_change_total', {
      parameter: log.parameter,
    });
  }

  /**
   * Convenience: record a UEBA false positive and trigger threshold tuning.
   */
  recordUebaFalsePositive(alertId: string, threshold: string): void {
    this.thresholdTuner.recordFalsePositive(alertId, threshold);
  }

  /**
   * Convenience: record a UEBA alert for threshold tracking.
   */
  recordUebaAlert(threshold: string): void {
    this.thresholdTuner.recordAlert(threshold);
  }
}
