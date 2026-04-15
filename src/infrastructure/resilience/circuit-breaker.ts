import { Logger } from '@nestjs/common';
import { IMetricsPort } from '../../application/ports/driven/i-metrics.port';

/**
 * Circuit breaker states (Req 15.4).
 * CLOSED    → normal operation, calls pass through
 * OPEN      → failing fast, no calls to dependency
 * HALF_OPEN → single probe allowed to test recovery
 */
export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

/**
 * Per-dependency circuit breaker configuration.
 */
export interface CircuitBreakerConfig {
  /** Human-readable name used in metrics labels. */
  name: string;
  /** Per-call timeout in milliseconds. */
  timeoutMs: number;
  /** Error rate percentage (0–100) to trip OPEN. */
  errorThresholdPercent: number;
  /** Minimum calls in rolling window before tripping. */
  volumeThreshold: number;
  /** How long (ms) to stay OPEN before moving to HALF_OPEN. */
  resetTimeoutMs: number;
  /** Rolling window size in ms. Default: 10_000. */
  rollingWindowMs?: number;
}

/**
 * Pre-configured circuit breaker configs per dependency (Section 11.1).
 */
export const CIRCUIT_BREAKER_CONFIGS = {
  mysql: {
    name: 'mysql',
    timeoutMs: 5_000,
    errorThresholdPercent: 50,
    volumeThreshold: 10,
    resetTimeoutMs: 30_000,
  } satisfies CircuitBreakerConfig,

  redis: {
    name: 'redis',
    timeoutMs: 200,
    errorThresholdPercent: 30,
    volumeThreshold: 20,
    resetTimeoutMs: 10_000,
  } satisfies CircuitBreakerConfig,

  firebase: {
    name: 'firebase',
    timeoutMs: 3_000,
    errorThresholdPercent: 40,
    volumeThreshold: 5,
    resetTimeoutMs: 60_000,
  } satisfies CircuitBreakerConfig,

  geoip: {
    name: 'geoip',
    timeoutMs: 100,
    errorThresholdPercent: 20,
    volumeThreshold: 10,
    resetTimeoutMs: 30_000,
  } satisfies CircuitBreakerConfig,
} as const;

/**
 * Generic circuit breaker implementing the CLOSED→OPEN→HALF_OPEN state machine.
 *
 * Implements Req 15.1–15.4:
 * - Wraps async operations with timeout + error rate tracking
 * - Trips OPEN when errorRate > threshold AND calls > volumeThreshold
 * - Moves to HALF_OPEN after resetTimeout
 * - Emits `uicp_circuit_breaker_state` metric on state change (Req 15.3)
 */
export class CircuitBreaker<T = unknown> {
  private readonly logger: Logger;
  private readonly rollingWindowMs: number;

  private state: CircuitState = 'CLOSED';
  private failures = 0;
  private totalCalls = 0;
  private windowStart = Date.now();
  private openedAt?: number;

  constructor(
    private readonly config: CircuitBreakerConfig,
    private readonly metrics?: IMetricsPort,
  ) {
    this.logger = new Logger(`CircuitBreaker[${config.name}]`);
    this.rollingWindowMs = config.rollingWindowMs ?? 10_000;
  }

  /**
   * Execute an async operation through the circuit breaker.
   * Applies the configured timeout and tracks success/failure rates.
   *
   * @throws Error with code CIRCUIT_OPEN when the circuit is OPEN
   * @throws Error with code CIRCUIT_TIMEOUT when the operation exceeds timeoutMs
   */
  async execute(fn: () => Promise<T>): Promise<T> {
    this.rollingWindowReset();

    if (this.state === 'OPEN') {
      const elapsed = Date.now() - (this.openedAt ?? 0);
      if (elapsed >= this.config.resetTimeoutMs) {
        this.transitionTo('HALF_OPEN');
      } else {
        throw Object.assign(
          new Error(`CIRCUIT_OPEN: ${this.config.name} circuit breaker is OPEN`),
          { code: 'CIRCUIT_OPEN', dependency: this.config.name },
        );
      }
    }

    this.totalCalls++;

    try {
      const result = await this.withTimeout(fn(), this.config.timeoutMs);
      this.onSuccess();
      return result;
    } catch (err) {
      this.onFailure();
      throw err;
    }
  }

  /**
   * Returns the current circuit state.
   */
  getState(): CircuitState {
    this.rollingWindowReset();
    if (this.state === 'OPEN') {
      const elapsed = Date.now() - (this.openedAt ?? 0);
      if (elapsed >= this.config.resetTimeoutMs) {
        this.transitionTo('HALF_OPEN');
      }
    }
    return this.state;
  }

  /**
   * Returns true when the circuit is OPEN (failing fast).
   */
  isOpen(): boolean {
    return this.getState() === 'OPEN';
  }

  // ── Private ────────────────────────────────────────────────────────────────

  private onSuccess(): void {
    this.metrics?.increment('uicp_circuit_breaker_success_total', { name: this.config.name });
    if (this.state === 'HALF_OPEN') {
      this.failures = 0;
      this.totalCalls = 0;
      this.windowStart = Date.now();
      this.transitionTo('CLOSED');
    }
  }

  private onFailure(): void {
    this.failures++;
    this.metrics?.increment('uicp_circuit_breaker_failure_total', { name: this.config.name });

    if (this.state === 'HALF_OPEN') {
      this.transitionTo('OPEN');
      return;
    }

    if (
      this.state === 'CLOSED' &&
      this.totalCalls >= this.config.volumeThreshold &&
      (this.failures / this.totalCalls) * 100 >= this.config.errorThresholdPercent
    ) {
      this.transitionTo('OPEN');
    }
  }

  private transitionTo(next: CircuitState): void {
    const prev = this.state;
    this.state = next;

    if (next === 'OPEN') {
      this.openedAt = Date.now();
    }

    this.logger.warn(
      { from: prev, to: next, failures: this.failures, total: this.totalCalls },
      `Circuit breaker ${this.config.name}: ${prev} → ${next}`,
    );

    // Emit metric on state change (Req 15.3)
    // uicp_circuit_breaker_state: 0=closed, 0.5=half-open, 1=open
    const stateValue = next === 'OPEN' ? 1 : next === 'HALF_OPEN' ? 0.5 : 0;
    this.metrics?.gauge('uicp_circuit_breaker_state', stateValue, { name: this.config.name });

    if (next === 'OPEN') {
      this.metrics?.increment('uicp_circuit_breaker_fire_total', { name: this.config.name });
    }
  }

  private rollingWindowReset(): void {
    const now = Date.now();
    if (now - this.windowStart >= this.rollingWindowMs) {
      this.failures = 0;
      this.totalCalls = 0;
      this.windowStart = now;
    }
  }

  private withTimeout(promise: Promise<T>, ms: number): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(
        () =>
          reject(
            Object.assign(
              new Error(`CIRCUIT_TIMEOUT: ${this.config.name} call timed out after ${ms}ms`),
              { code: 'CIRCUIT_TIMEOUT', dependency: this.config.name },
            ),
          ),
        ms,
      );
      promise.then(
        (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        (e) => {
          clearTimeout(timer);
          reject(e);
        },
      );
    });
  }
}
