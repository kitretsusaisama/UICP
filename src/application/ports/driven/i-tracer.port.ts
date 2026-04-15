/**
 * Arbitrary key-value attributes attached to a span.
 */
export type SpanAttributes = Record<string, string | number | boolean>;

/**
 * Opaque span handle returned by `startSpan`.
 * Callers must end the span when the operation completes.
 */
export interface Span {
  /** Add or update attributes on this span. */
  setAttributes(attributes: SpanAttributes): void;
  /** Record an exception and set span status to ERROR. */
  recordException(error: Error): void;
  /** End the span. Must be called exactly once. */
  end(): void;
}

/**
 * Driven port — OpenTelemetry distributed tracing (Section 4.6).
 *
 * Contract:
 * - `startSpan` creates a child span of the current active span.
 * - W3C TraceContext headers are propagated automatically.
 * - `recordException` sets span status to ERROR.
 * - `withSpan` always ends the span — even when `fn` throws.
 */
export interface ITracerPort {
  /**
   * Start a new span as a child of the current active span.
   * The caller is responsible for calling `span.end()`.
   */
  startSpan(name: string, attributes?: SpanAttributes): Span;

  /**
   * Add attributes to the current active span.
   * No-op when there is no active span.
   */
  setAttributes(attributes: SpanAttributes): void;

  /**
   * Record an exception on the current active span and set status to ERROR.
   * No-op when there is no active span.
   */
  recordException(error: Error): void;

  /**
   * Return the trace ID of the current active span for log correlation.
   * Returns undefined when there is no active span.
   */
  getCurrentTraceId(): string | undefined;

  /**
   * Wrap an async operation in a span.
   * The span is always ended — even when `fn` throws.
   */
  withSpan<T>(name: string, fn: () => Promise<T>, attributes?: SpanAttributes): Promise<T>;
}
