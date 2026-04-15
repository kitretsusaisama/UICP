import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as client from 'prom-client';
import { IMetricsPort, MetricLabels } from '../../application/ports/driven/i-metrics.port';

/**
 * Prometheus metrics adapter implementing IMetricsPort.
 *
 * Registers all counters, gauges, and histograms from Section 13.4.
 * Exposes the /metrics endpoint via the prom-client default registry.
 *
 * Implements: Req 15.3, Req 16.4–16.6
 */
@Injectable()
export class PromClientMetricsAdapter implements IMetricsPort, OnModuleInit {
  private readonly logger = new Logger(PromClientMetricsAdapter.name);

  // ── Counters ───────────────────────────────────────────────────────────────
  private readonly counters = new Map<string, client.Counter>();

  // ── Gauges ─────────────────────────────────────────────────────────────────
  private readonly gauges = new Map<string, client.Gauge>();

  // ── Histograms ─────────────────────────────────────────────────────────────
  private readonly histograms = new Map<string, client.Histogram>();

  onModuleInit(): void {
    // Clear default registry to avoid duplicate registration on hot reload
    client.register.clear();

    // Collect default Node.js metrics (heap, GC, event loop lag, etc.)
    client.collectDefaultMetrics({ register: client.register });

    this.registerCounters();
    this.registerGauges();
    this.registerHistograms();

    this.logger.log('Prometheus metrics registered');
  }

  // ── IMetricsPort ───────────────────────────────────────────────────────────

  increment(metric: string, labels?: MetricLabels, value?: number): void {
    const counter = this.counters.get(metric);
    if (!counter) {
      this.logger.warn({ metric }, 'Unknown counter metric — skipping');
      return;
    }
    const inc = value ?? 1;
    labels ? counter.inc(this.normalizeLabels(labels), inc) : counter.inc(inc);
  }

  gauge(metric: string, value: number, labels?: MetricLabels): void {
    const g = this.gauges.get(metric);
    if (!g) {
      this.logger.warn({ metric }, 'Unknown gauge metric — skipping');
      return;
    }
    labels ? g.set(this.normalizeLabels(labels), value) : g.set(value);
  }

  histogram(metric: string, value: number, labels?: MetricLabels): void {
    const h = this.histograms.get(metric);
    if (!h) {
      this.logger.warn({ metric }, 'Unknown histogram metric — skipping');
      return;
    }
    labels ? h.observe(this.normalizeLabels(labels), value) : h.observe(value);
  }

  observe(metric: string, value: number, labels?: MetricLabels): void {
    // Delegate to the appropriate metric type
    if (this.counters.has(metric)) {
      this.increment(metric, labels, value);
    } else if (this.gauges.has(metric)) {
      this.gauge(metric, value, labels);
    } else if (this.histograms.has(metric)) {
      this.histogram(metric, value, labels);
    } else {
      this.logger.warn({ metric }, 'Unknown metric in observe() — skipping');
    }
  }

  /**
   * Return the Prometheus text format for the /metrics endpoint.
   */
  async getMetrics(): Promise<string> {
    return client.register.metrics();
  }

  /**
   * Return the content type header value for the /metrics endpoint.
   */
  getContentType(): string {
    return client.register.contentType;
  }

  // ── Registration ───────────────────────────────────────────────────────────

  private registerCounters(): void {
    const counters: Array<{ name: string; help: string; labelNames: string[] }> = [
      {
        name: 'uicp_auth_attempts_total',
        help: 'Total authentication attempts',
        labelNames: ['tenant_id', 'result'],
      },
      {
        name: 'uicp_signup_total',
        help: 'Total signup attempts',
        labelNames: ['tenant_id', 'result'],
      },
      {
        name: 'uicp_otp_sent_total',
        help: 'Total OTP codes sent',
        labelNames: ['tenant_id', 'channel', 'purpose'],
      },
      {
        name: 'uicp_otp_verified_total',
        help: 'Total OTP verification attempts',
        labelNames: ['tenant_id', 'result'],
      },
      {
        name: 'uicp_token_minted_total',
        help: 'Total JWT tokens minted',
        labelNames: ['tenant_id', 'type'],
      },
      {
        name: 'uicp_token_refreshed_total',
        help: 'Total token refresh attempts',
        labelNames: ['tenant_id', 'result'],
      },
      {
        name: 'uicp_errors_total',
        help: 'Total errors by code, category, and HTTP status',
        labelNames: ['error_code', 'category', 'http_status'],
      },
      {
        name: 'uicp_soc_alerts_total',
        help: 'Total SOC alerts created',
        labelNames: ['tenant_id', 'kill_chain_stage', 'threat_level'],
      },
      {
        name: 'uicp_circuit_breaker_fire_total',
        help: 'Total circuit breaker trips to OPEN',
        labelNames: ['name'],
      },
      {
        name: 'uicp_circuit_breaker_success_total',
        help: 'Total successful calls through circuit breaker',
        labelNames: ['name'],
      },
      {
        name: 'uicp_circuit_breaker_failure_total',
        help: 'Total failed calls through circuit breaker',
        labelNames: ['name'],
      },
      {
        name: 'uicp_outbox_published_total',
        help: 'Total outbox events published',
        labelNames: ['event_type'],
      },
      {
        name: 'uicp_outbox_dlq_total',
        help: 'Total outbox events moved to DLQ',
        labelNames: ['event_type'],
      },
      {
        name: 'uicp_adaptive_parameter_change_total',
        help: 'Total adaptive parameter changes',
        labelNames: ['parameter'],
      },
    ];

    for (const def of counters) {
      const counter = new client.Counter({
        name: def.name,
        help: def.help,
        labelNames: def.labelNames,
        registers: [client.register],
      });
      this.counters.set(def.name, counter);
    }
  }

  private registerGauges(): void {
    const gauges: Array<{ name: string; help: string; labelNames: string[] }> = [
      {
        name: 'uicp_active_sessions',
        help: 'Current active session count per tenant',
        labelNames: ['tenant_id'],
      },
      {
        name: 'uicp_threat_score',
        help: 'Latest UEBA threat score per user',
        labelNames: ['tenant_id', 'user_id'],
      },
      {
        name: 'uicp_circuit_breaker_state',
        help: 'Circuit breaker state: 0=closed, 0.5=half-open, 1=open',
        labelNames: ['name'],
      },
      {
        name: 'uicp_db_pool_size',
        help: 'Current database connection pool size',
        labelNames: ['pool'],
      },
      {
        name: 'uicp_db_pool_waiting',
        help: 'Requests waiting for a database connection',
        labelNames: ['pool'],
      },
      {
        name: 'uicp_queue_depth',
        help: 'BullMQ waiting job count per queue',
        labelNames: ['queue_name'],
      },
      {
        name: 'uicp_bcrypt_rounds',
        help: 'Current adaptive bcrypt rounds',
        labelNames: [],
      },
      {
        name: 'uicp_rate_limit_multiplier',
        help: 'Current rate limit multiplier per tenant',
        labelNames: ['tenant_id'],
      },
      {
        name: 'uicp_load_score',
        help: 'Composite server load score (0.0–1.0)',
        labelNames: [],
      },
    ];

    for (const def of gauges) {
      const g = new client.Gauge({
        name: def.name,
        help: def.help,
        labelNames: def.labelNames,
        registers: [client.register],
      });
      this.gauges.set(def.name, g);
    }
  }

  private registerHistograms(): void {
    const histograms: Array<{
      name: string;
      help: string;
      labelNames: string[];
      buckets: number[];
    }> = [
      {
        name: 'uicp_request_duration_ms',
        help: 'HTTP request duration in milliseconds',
        labelNames: ['method', 'route', 'status'],
        buckets: [5, 10, 25, 50, 100, 250, 500, 1000, 2500],
      },
      {
        name: 'uicp_db_query_duration_ms',
        help: 'Database query duration in milliseconds',
        labelNames: ['operation', 'table'],
        buckets: [1, 5, 10, 25, 50, 100, 250, 500],
      },
      {
        name: 'uicp_redis_command_duration_ms',
        help: 'Redis command duration in milliseconds',
        labelNames: ['command'],
        buckets: [0.5, 1, 2, 5, 10, 25, 50],
      },
      {
        name: 'uicp_bcrypt_hash_duration_ms',
        help: 'Bcrypt hash duration in milliseconds',
        labelNames: [],
        buckets: [50, 100, 150, 200, 250, 300, 500],
      },
      {
        name: 'uicp_ueba_score_duration_ms',
        help: 'UEBA threat scoring duration in milliseconds',
        labelNames: [],
        buckets: [1, 5, 10, 25, 50, 100],
      },
      {
        name: 'uicp_token_validation_duration_ms',
        help: 'JWT token validation duration in milliseconds',
        labelNames: [],
        buckets: [0.5, 1, 2, 5, 10, 25],
      },
    ];

    for (const def of histograms) {
      const h = new client.Histogram({
        name: def.name,
        help: def.help,
        labelNames: def.labelNames,
        buckets: def.buckets,
        registers: [client.register],
      });
      this.histograms.set(def.name, h);
    }
  }

  private normalizeLabels(labels: MetricLabels): Record<string, string | number> {
    return labels as Record<string, string | number>;
  }
}
