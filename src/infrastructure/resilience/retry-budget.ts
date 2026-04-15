import { Injectable } from '@nestjs/common';
import { ClsService } from 'nestjs-cls';

/**
 * CLS store key for the retry budget.
 * Stored as a plain number to avoid object allocation overhead.
 */
const RETRY_BUDGET_KEY = 'retryBudget';

/**
 * Default retry budget per request.
 * Max 3 retries across all dependencies per incoming request (Section 11.3).
 */
const DEFAULT_BUDGET = 3;

/**
 * Retry budget stored in CLS context (Req 15.5).
 *
 * Prevents retry storms by limiting the total number of retries
 * across all dependencies within a single request's async call stack.
 *
 * Usage:
 *   const budget = new RetryBudget(clsService);
 *   if (!budget.consume()) {
 *     throw new InfrastructureException('RETRY_BUDGET_EXHAUSTED');
 *   }
 *   // proceed with retry
 */
@Injectable()
export class RetryBudget {
  constructor(private readonly cls: ClsService) {}

  /**
   * Attempt to consume one retry unit from the budget.
   *
   * @returns true if a retry is allowed (budget decremented), false if exhausted.
   */
  consume(): boolean {
    const current = this.getRemaining();
    if (current <= 0) {
      return false;
    }
    this.cls.set(RETRY_BUDGET_KEY as any, current - 1);
    return true;
  }

  /**
   * Returns the number of retries remaining in the current request context.
   * Returns DEFAULT_BUDGET when called outside a CLS context (e.g., background jobs).
   */
  getRemaining(): number {
    try {
      const stored = this.cls.get(RETRY_BUDGET_KEY as any);
      if (typeof stored === 'number') {
        return stored;
      }
      // Not yet initialized — set and return default
      this.cls.set(RETRY_BUDGET_KEY as any, DEFAULT_BUDGET);
      return DEFAULT_BUDGET;
    } catch {
      // Outside CLS context (e.g., background workers) — allow retries
      return DEFAULT_BUDGET;
    }
  }

  /**
   * Reset the budget to the default value.
   * Called at the start of each request by the CLS interceptor.
   */
  reset(budget = DEFAULT_BUDGET): void {
    try {
      this.cls.set(RETRY_BUDGET_KEY as any, budget);
    } catch {
      // Outside CLS context — no-op
    }
  }

  /**
   * Returns true when the budget is exhausted.
   */
  isExhausted(): boolean {
    return this.getRemaining() <= 0;
  }
}
