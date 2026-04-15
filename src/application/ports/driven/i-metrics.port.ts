/**
 * Label key-value pairs attached to a metric observation.
 */
export type MetricLabels = Record<string, string | number>;

/**
 * Driven port — Prometheus metrics (Section 13.4).
 *
 * Contract:
 * - All counters, gauges, and histograms defined in Section 13.4 are registered
 *   by the infrastructure adapter at startup.
 * - The `/metrics` endpoint is exposed by the adapter.
 */
export interface IMetricsPort {
  /**
   * Increment a counter by 1 (or by `value` when provided).
   */
  increment(metric: string, labels?: MetricLabels, value?: number): void;

  /**
   * Set a gauge to an absolute value.
   */
  gauge(metric: string, value: number, labels?: MetricLabels): void;

  /**
   * Record a value in a histogram (e.g. request duration in milliseconds).
   */
  histogram(metric: string, value: number, labels?: MetricLabels): void;

  /**
   * Generic observation — delegates to the appropriate metric type
   * based on the registered metric kind.
   */
  observe(metric: string, value: number, labels?: MetricLabels): void;
}
