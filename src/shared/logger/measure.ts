import { UicpLogger } from './pino-logger.service';

export interface MeasureOptions {
  /** Logger instance to emit the timing log. */
  logger: UicpLogger;
  /** Logical operation name (e.g. 'login', 'signup', 'token_validation'). */
  operation: string;
  /** NestJS context label (e.g. 'LoginHandler'). */
  context?: string;
  /** Extra fields merged into the log line on success. */
  extra?: Record<string, unknown>;
}

/**
 * measure() — wraps an async operation and emits a structured log line
 * with `durationMs` on completion (or error).
 *
 * Usage:
 *   const result = await measure({ logger, operation: 'login', context: 'LoginHandler' }, () =>
 *     this.doLogin(cmd),
 *   );
 *
 * Implements: Req 13.6 — durationMs measurement for login, signup,
 * token validation, and UEBA scoring.
 */
export async function measure<T>(
  opts: MeasureOptions,
  fn: () => Promise<T>,
): Promise<T> {
  const start = performance.now();
  try {
    const result = await fn();
    const durationMs = Math.round(performance.now() - start);
    opts.logger.log(
      `${opts.operation} completed`,
      opts.context,
      { operation: opts.operation, durationMs, ...opts.extra },
    );
    return result;
  } catch (err: unknown) {
    const durationMs = Math.round(performance.now() - start);
    opts.logger.error(
      `${opts.operation} failed`,
      opts.context,
      {
        err,
        operation: opts.operation,
        durationMs,
        errorCode: (err as { errorCode?: string })?.errorCode,
        ...opts.extra,
      },
    );
    throw err;
  }
}
