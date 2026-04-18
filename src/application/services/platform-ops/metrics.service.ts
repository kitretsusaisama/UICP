import { Injectable, OnModuleInit } from '@nestjs/common';
import * as client from 'prom-client';

@Injectable()
export class MetricsService implements OnModuleInit {
  private registry: client.Registry;

  // Auth Metrics
  public readonly authLoginTotal: client.Counter;
  public readonly authLoginFailedTotal: client.Counter;
  public readonly authTokenRefreshTotal: client.Counter;
  public readonly authTokenReuseTotal: client.Counter;
  public readonly authSessionActive: client.Gauge;

  // OTP Metrics
  public readonly otpSentTotal: client.Counter;
  public readonly otpFailedTotal: client.Counter;
  public readonly otpCostEstimate: client.Counter;
  public readonly otpRateLimitedTotal: client.Counter;

  // Cache & DB Metrics
  public readonly redisLatencyMs: client.Histogram;
  public readonly redisErrorsTotal: client.Counter;
  public readonly mysqlQueryLatencyMs: client.Histogram;
  public readonly mysqlErrorsTotal: client.Counter;

  // Auditing
  public readonly auditWriteTotal: client.Counter;
  public readonly outboxLag: client.Gauge;

  // Queue Metrics
  public readonly queueJobsWaiting: client.Gauge;
  public readonly queueJobsFailed: client.Counter;
  public readonly queueJobsStalled: client.Gauge;
  public readonly queueLatency: client.Histogram;

  // SOC Metrics
  public readonly socAlertsCreatedTotal: client.Counter;
  public readonly socAlertsCriticalTotal: client.Counter;
  public readonly incidentOpenTotal: client.Gauge;

  // Caching for backpressure protection (1-5s)
  private cachedMetricsSnapshot: string = '';
  private lastMetricsCollectionTime: number = 0;
  private readonly METRICS_CACHE_TTL_MS = 2000;

  constructor() {
    this.registry = new client.Registry();

    // Setup Auth Metrics
    this.authLoginTotal = new client.Counter({
      name: 'auth_login_total',
      help: 'Total number of successful logins',
      registers: [this.registry],
    });
    this.authLoginFailedTotal = new client.Counter({
      name: 'auth_login_failed_total',
      help: 'Total number of failed logins',
      labelNames: ['reason'],
      registers: [this.registry],
    });
    this.authTokenRefreshTotal = new client.Counter({
      name: 'auth_token_refresh_total',
      help: 'Total number of token refreshes',
      registers: [this.registry],
    });
    this.authTokenReuseTotal = new client.Counter({
      name: 'auth_token_reuse_total',
      help: 'Total number of detected token reuse events (Security!)',
      registers: [this.registry],
    });
    this.authSessionActive = new client.Gauge({
      name: 'auth_session_active',
      help: 'Current active session count estimate',
      registers: [this.registry],
    });

    // Setup OTP Metrics
    this.otpSentTotal = new client.Counter({
      name: 'otp_sent_total',
      help: 'Total OTPs successfully sent',
      labelNames: ['provider'],
      registers: [this.registry],
    });
    this.otpFailedTotal = new client.Counter({
      name: 'otp_failed_total',
      help: 'Total OTP failures',
      labelNames: ['provider', 'reason'],
      registers: [this.registry],
    });
    this.otpCostEstimate = new client.Counter({
      name: 'otp_cost_estimate',
      help: 'Estimated cost of OTP messages sent (Financial!)',
      labelNames: ['provider'],
      registers: [this.registry],
    });
    this.otpRateLimitedTotal = new client.Counter({
      name: 'otp_rate_limited_total',
      help: 'Total OTP requests dropped by rate limiters',
      registers: [this.registry],
    });

    // Infrastructure Metrics
    this.redisLatencyMs = new client.Histogram({
      name: 'redis_latency_ms',
      help: 'Latency of Redis operations in ms',
      labelNames: ['operation'],
      buckets: [1, 5, 10, 50, 100, 250, 500, 1000],
      registers: [this.registry],
    });
    this.redisErrorsTotal = new client.Counter({
      name: 'redis_errors_total',
      help: 'Total Redis errors',
      labelNames: ['operation'],
      registers: [this.registry],
    });
    this.mysqlQueryLatencyMs = new client.Histogram({
      name: 'mysql_query_latency_ms',
      help: 'Latency of MySQL queries in ms',
      labelNames: ['table', 'operation'],
      buckets: [5, 10, 50, 100, 250, 500, 1000, 5000],
      registers: [this.registry],
    });
    this.mysqlErrorsTotal = new client.Counter({
      name: 'mysql_errors_total',
      help: 'Total MySQL query errors',
      registers: [this.registry],
    });
    this.auditWriteTotal = new client.Counter({
      name: 'audit_write_total',
      help: 'Total audit log entries written',
      registers: [this.registry],
    });
    this.outboxLag = new client.Gauge({
      name: 'outbox_lag',
      help: 'Number of outbox events pending processing',
      registers: [this.registry],
    });

    // Setup Queue Metrics
    this.queueJobsWaiting = new client.Gauge({
      name: 'queue_jobs_waiting',
      help: 'Number of jobs waiting in the queue',
      labelNames: ['name'],
      registers: [this.registry],
    });
    this.queueJobsFailed = new client.Counter({
      name: 'queue_jobs_failed',
      help: 'Number of failed jobs in the queue',
      labelNames: ['name'],
      registers: [this.registry],
    });
    this.queueJobsStalled = new client.Gauge({
      name: 'queue_jobs_stalled',
      help: 'Number of stalled jobs in the queue',
      labelNames: ['name'],
      registers: [this.registry],
    });
    this.queueLatency = new client.Histogram({
      name: 'queue_latency',
      help: 'Time jobs spend waiting before execution',
      labelNames: ['name'],
      buckets: [10, 50, 100, 500, 1000, 5000, 10000],
      registers: [this.registry],
    });

    // SOC Metrics
    this.socAlertsCreatedTotal = new client.Counter({
      name: 'soc_alerts_created_total',
      help: 'Total SOC alerts generated',
      labelNames: ['rule'],
      registers: [this.registry],
    });
    this.socAlertsCriticalTotal = new client.Counter({
      name: 'soc_alerts_critical_total',
      help: 'Total CRITICAL severity SOC alerts generated',
      labelNames: ['rule'],
      registers: [this.registry],
    });
    this.incidentOpenTotal = new client.Gauge({
      name: 'incident_open_total',
      help: 'Total number of currently open unresolved incidents',
      registers: [this.registry],
    });
  }

  onModuleInit() {
    client.collectDefaultMetrics({ register: this.registry });
  }

  async getMetrics(): Promise<string> {
    const now = Date.now();
    if (now - this.lastMetricsCollectionTime > this.METRICS_CACHE_TTL_MS) {
      this.cachedMetricsSnapshot = await this.registry.metrics();
      this.lastMetricsCollectionTime = now;
    }
    return this.cachedMetricsSnapshot;
  }
}
