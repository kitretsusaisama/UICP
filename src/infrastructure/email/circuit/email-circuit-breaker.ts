import { Inject, Injectable, Logger } from '@nestjs/common';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerState {
  state: CircuitState;
  failureCount: number;
  successCount: number;
  lastFailure?: Date;
  lastSuccess?: Date;
}

@Injectable()
export class EmailCircuitBreaker {
  private readonly logger = new Logger(EmailCircuitBreaker.name);

  private readonly THRESHOLD = 5; // failures before opening
  private readonly RESET_TIMEOUT_MS = 60000; // 1 minute before half-open
  private readonly SUCCESS_THRESHOLD = 3; // successes needed to close

  constructor(
    @Inject(INJECTION_TOKENS.CACHE_PORT) private readonly cache: ICachePort,
  ) {}

  private circuitKey(tenantId: string, providerKey: string): string {
    return `email:circuit:${tenantId}:${providerKey}`;
  }

  async getState(tenantId: string, providerKey: string): Promise<CircuitBreakerState> {
    const key = this.circuitKey(tenantId, providerKey);
    const cached = await this.cache.get(key);

    if (cached) {
      return JSON.parse(cached);
    }

    // Default closed state
    return {
      state: 'CLOSED',
      failureCount: 0,
      successCount: 0,
    };
  }

  async recordSuccess(tenantId: string, providerKey: string): Promise<void> {
    const state = await this.getState(tenantId, providerKey);

    // Increment success count
    state.successCount += 1;
    state.lastSuccess = new Date();

    // If in HALF_OPEN state, need multiple successes to close
    if (state.state === 'HALF_OPEN') {
      if (state.successCount >= this.SUCCESS_THRESHOLD) {
        state.state = 'CLOSED';
        state.failureCount = 0;
        state.successCount = 0;
        this.logger.log(
          { tenantId, provider: providerKey },
          'Circuit breaker CLOSED after recoveries',
        );
      }
    } else if (state.state === 'OPEN') {
      // Transition to HALF_OPEN to test
      state.state = 'HALF_OPEN';
      state.successCount = 1;
      this.logger.log(
        { tenantId, provider: providerKey },
        'Circuit breaker HALF_OPEN for testing',
      );
    }

    // Reset failure count on success
    state.failureCount = 0;

    await this.cache.set(
      this.circuitKey(tenantId, providerKey),
      JSON.stringify(state),
      3600,
    );
  }

  async recordFailure(tenantId: string, providerKey: string): Promise<void> {
    const state = await this.getState(tenantId, providerKey);

    // Increment failure count
    state.failureCount += 1;
    state.lastFailure = new Date();
    state.successCount = 0;

    // Check if we should open the circuit
    if (state.failureCount >= this.THRESHOLD) {
      state.state = 'OPEN';
      this.logger.warn(
        { tenantId, provider: providerKey, failures: state.failureCount },
        'Circuit breaker OPEN due to failures',
      );
    }

    await this.cache.set(
      this.circuitKey(tenantId, providerKey),
      JSON.stringify(state),
      3600,
    );
  }

  async isAvailable(tenantId: string, providerKey: string): Promise<boolean> {
    const state = await this.getState(tenantId, providerKey);

    // If OPEN, check if we should transition to HALF_OPEN
    const currentState = state.state as string;
    if (currentState === 'OPEN') {
      if (state.lastFailure) {
        const timeSinceFailure = Date.now() - state.lastFailure.getTime();
        if (timeSinceFailure >= this.RESET_TIMEOUT_MS) {
          state.state = 'HALF_OPEN';
          state.successCount = 0;
          this.logger.log(
            { tenantId, provider: providerKey },
            'Circuit breaker transitioning to HALF_OPEN',
          );
          await this.cache.set(
            this.circuitKey(tenantId, providerKey),
            JSON.stringify(state),
            3600,
          );
          return true;
        }
      }
      return false;
    }

    return state.state !== 'OPEN';
  }

  async getFailureCount(tenantId: string, providerKey: string): Promise<number> {
    const state = await this.getState(tenantId, providerKey);
    return state.failureCount;
  }

  async reset(tenantId: string, providerKey: string): Promise<void> {
    const key = this.circuitKey(tenantId, providerKey);
    await this.cache.del(key);
    this.logger.log({ tenantId, provider: providerKey }, 'Circuit breaker reset');
  }
}