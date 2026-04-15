import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit, Optional } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { IMetricsPort } from '../../application/ports/driven/i-metrics.port';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';
import { ServerLoadMonitor } from './server-load-monitor';

const MIN_ROUNDS = 10;
const MAX_ROUNDS = 13;
const TARGET_P95_MS = 200;
const CALIBRATION_SAMPLES = 5;
const CALIBRATION_INTERVAL_MS = 30 * 60 * 1_000; // 30 minutes
const HIGH_LOAD_THRESHOLD = 0.80;

/**
 * Adaptive bcrypt service that calibrates cost rounds to target ~200ms P95 latency.
 *
 * - Calibrates at startup and every 30 minutes.
 * - Under high server load (composite score > 0.80), falls back to MIN_ROUNDS.
 * - Emits `uicp_adaptive_parameter_change_total` metric on round changes.
 *
 * Implements Req 3.9 and Req 15.
 */
@Injectable()
export class AdaptiveBcrypt implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AdaptiveBcrypt.name);
  private currentRounds = 12;
  private calibrationTimer: NodeJS.Timeout | null = null;

  constructor(
    private readonly loadMonitor: ServerLoadMonitor,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
  ) {}

  async onModuleInit(): Promise<void> {
    await this.calibrateBcryptRounds();

    this.calibrationTimer = setInterval(() => {
      void this.calibrateBcryptRounds();
    }, CALIBRATION_INTERVAL_MS);

    this.calibrationTimer.unref();
  }

  onModuleDestroy(): void {
    if (this.calibrationTimer) {
      clearInterval(this.calibrationTimer);
      this.calibrationTimer = null;
    }
  }

  getCurrentRounds(): number {
    if (this.loadMonitor.getCompositeScore() > HIGH_LOAD_THRESHOLD) {
      return MIN_ROUNDS;
    }
    return this.currentRounds;
  }

  async calibrateBcryptRounds(): Promise<void> {
    const samples: number[] = [];

    for (let i = 0; i < CALIBRATION_SAMPLES; i++) {
      const start = Date.now();
      await bcrypt.hash('calibration_sample', this.currentRounds);
      samples.push(Date.now() - start);
    }

    samples.sort((a, b) => a - b);
    const p95 = samples[Math.ceil(CALIBRATION_SAMPLES * 0.95) - 1] ?? samples[samples.length - 1] ?? TARGET_P95_MS;

    const previousRounds = this.currentRounds;
    let newRounds = this.currentRounds;

    if (p95 < TARGET_P95_MS && newRounds < MAX_ROUNDS) {
      newRounds = Math.min(newRounds + 1, MAX_ROUNDS);
    } else if (p95 > TARGET_P95_MS && newRounds > MIN_ROUNDS) {
      newRounds = Math.max(newRounds - 1, MIN_ROUNDS);
    }

    if (newRounds !== previousRounds) {
      this.currentRounds = newRounds;
      this.logger.log(
        `Bcrypt rounds adjusted: ${previousRounds} → ${newRounds} (P95 latency: ${p95}ms, target: ${TARGET_P95_MS}ms)`,
      );
      this.metrics?.increment('uicp_adaptive_parameter_change_total', {
        parameter: 'bcrypt_rounds',
        from: String(previousRounds),
        to: String(newRounds),
      });
    } else {
      this.logger.debug(
        `Bcrypt rounds unchanged at ${this.currentRounds} (P95 latency: ${p95}ms)`,
      );
    }
  }
}
