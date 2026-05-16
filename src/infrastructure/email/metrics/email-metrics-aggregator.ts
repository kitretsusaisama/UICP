import { Injectable, Logger } from '@nestjs/common';
import { Inject } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';

export interface ProviderMetrics {
  providerKey: string;
  tenantId: string;
  totalSent24h: number;
  totalDelivered24h: number;
  totalFailed24h: number;
  totalBounced24h: number;
  avgLatencyMs: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  successRate: number;
  updatedAt: Date;
}

export interface LatencyBucket {
  timestamp: number;
  latencyMs: number;
  success: boolean;
}

export interface MetricsSummary {
  providerKey: string;
  tenantId: string;
  sent: number;
  delivered: number;
  failed: number;
  bounced: number;
  successRate: number;
  avgLatency: number;
  p50Latency: number;
  p95Latency: number;
  p99Latency: number;
}

@Injectable()
export class EmailMetricsAggregator {
  private readonly logger = new Logger(EmailMetricsAggregator.name);

  constructor(
    @Inject(INJECTION_TOKENS.CACHE_PORT) private readonly cache: ICachePort
  ) {}

  private metricsKey(tenantId: string, providerKey: string): string {
    return `email:metrics:${tenantId}:${providerKey}`;
  }

  private latencyKey(tenantId: string, providerKey: string): string {
    return `email:latencies:${tenantId}:${providerKey}`;
  }

  private countersKey(tenantId: string, providerKey: string): string {
    return `email:counters:${tenantId}:${providerKey}`;
  }

  async recordSend(tenantId: string, providerKey: string): Promise<void> {
    const key = this.countersKey(tenantId, providerKey);
    const current = await this.cache.get(key);
    const counters = current ? JSON.parse(current) : { sent: 0, delivered: 0, failed: 0, bounced: 0 };

    counters.sent = (counters.sent ?? 0) + 1;
    await this.cache.set(key, JSON.stringify(counters), 86400);
  }

  async recordDelivery(tenantId: string, providerKey: string, success: boolean): Promise<void> {
    const key = this.countersKey(tenantId, providerKey);
    const current = await this.cache.get(key);
    const counters = current ? JSON.parse(current) : { sent: 0, delivered: 0, failed: 0, bounced: 0 };

    if (success) {
      counters.delivered = (counters.delivered ?? 0) + 1;
    } else {
      counters.failed = (counters.failed ?? 0) + 1;
    }

    await this.cache.set(key, JSON.stringify(counters), 86400);
  }

  async recordBounce(tenantId: string, providerKey: string): Promise<void> {
    const key = this.countersKey(tenantId, providerKey);
    const current = await this.cache.get(key);
    const counters = current ? JSON.parse(current) : { sent: 0, delivered: 0, failed: 0, bounced: 0 };

    counters.bounced = (counters.bounced ?? 0) + 1;
    await this.cache.set(key, JSON.stringify(counters), 86400);
  }

  async recordLatency(tenantId: string, providerKey: string, latencyMs: number): Promise<void> {
    const key = this.latencyKey(tenantId, providerKey);
    const current = await this.cache.get(key);

    const latencies: LatencyBucket[] = current ? JSON.parse(current) : [];

    latencies.push({
      timestamp: Date.now(),
      latencyMs,
      success: true,
    });

    // Keep only last 24 hours of data
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    const filtered = latencies.filter(l => l.timestamp > cutoff);

    await this.cache.set(key, JSON.stringify(filtered), 86400);
  }

  async aggregateMetrics(tenantId: string, providerKey: string): Promise<ProviderMetrics> {
    const countersKey = this.countersKey(tenantId, providerKey);
    const latencyKey = this.latencyKey(tenantId, providerKey);

    const countersRaw = await this.cache.get(countersKey);
    const latenciesRaw = await this.cache.get(latencyKey);

    const counters = countersRaw ? JSON.parse(countersRaw) : { sent: 0, delivered: 0, failed: 0, bounced: 0 };
    const latencies: LatencyBucket[] = latenciesRaw ? JSON.parse(latenciesRaw) : [];

    const latencyValues = latencies
      .filter(l => l.latencyMs > 0)
      .map(l => l.latencyMs)
      .sort((a, b) => a - b);

    const sent = counters.sent ?? 0;
    const delivered = counters.delivered ?? 0;
    const failed = counters.failed ?? 0;
    const bounced = counters.bounced ?? 0;

    const metrics: ProviderMetrics = {
      providerKey,
      tenantId,
      totalSent24h: sent,
      totalDelivered24h: delivered,
      totalFailed24h: failed,
      totalBounced24h: bounced,
      avgLatencyMs: this.calculateAverage(latencyValues),
      p50LatencyMs: this.percentile(latencyValues, 50),
      p95LatencyMs: this.percentile(latencyValues, 95),
      p99LatencyMs: this.percentile(latencyValues, 99),
      successRate: sent > 0 ? delivered / sent : 0,
      updatedAt: new Date(),
    };

    // Cache the aggregated metrics
    await this.cache.set(this.metricsKey(tenantId, providerKey), JSON.stringify(metrics), 3600);

    return metrics;
  }

  async getMetrics(tenantId: string, providerKey: string): Promise<ProviderMetrics | null> {
    const cached = await this.cache.get(this.metricsKey(tenantId, providerKey));
    if (!cached) {
      return null;
    }
    return JSON.parse(cached) as ProviderMetrics;
  }

  async getAllMetrics(tenantId: string, providers: string[]): Promise<ProviderMetrics[]> {
    const results: ProviderMetrics[] = [];

    for (const provider of providers) {
      const metrics = await this.getMetrics(tenantId, provider);
      if (metrics) {
        results.push(metrics);
      }
    }

    return results;
  }

  async getSummary(tenantId: string, providerKey: string): Promise<MetricsSummary | null> {
    const metrics = await this.aggregateMetrics(tenantId, providerKey);

    return {
      providerKey: metrics.providerKey,
      tenantId: metrics.tenantId,
      sent: metrics.totalSent24h,
      delivered: metrics.totalDelivered24h,
      failed: metrics.totalFailed24h,
      bounced: metrics.totalBounced24h,
      successRate: metrics.successRate,
      avgLatency: metrics.avgLatencyMs,
      p50Latency: metrics.p50LatencyMs,
      p95Latency: metrics.p95LatencyMs,
      p99Latency: metrics.p99LatencyMs,
    };
  }

  async resetMetrics(tenantId: string, providerKey: string): Promise<void> {
    const countersKey = this.countersKey(tenantId, providerKey);
    const latencyKey = this.latencyKey(tenantId, providerKey);
    const metricsKey = this.metricsKey(tenantId, providerKey);

    await this.cache.del(countersKey);
    await this.cache.del(latencyKey);
    await this.cache.del(metricsKey);

    this.logger.log({ tenantId, provider: providerKey }, 'Metrics reset');
  }

  calculateAverage(values: number[]): number {
    if (!values.length) return 0;
    return Math.round(values.reduce((a, b) => a + b, 0) / values.length);
  }

  percentile(sorted: number[], p: number): number {
    if (!sorted.length) return 0;

    const index = Math.max(0, Math.ceil((p / 100) * sorted.length) - 1);
    return sorted[index] ?? 0;
  }

  min(values: number[]): number {
    if (!values.length) return 0;
    return Math.min(...values);
  }

  max(values: number[]): number {
    if (!values.length) return 0;
    return Math.max(...values);
  }

  median(values: number[]): number {
    if (!values.length) return 0;
    const sorted = [...values].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    if (sorted.length % 2 !== 0) {
      return sorted[mid] ?? 0;
    }
    const left = sorted[mid - 1] ?? 0;
    const right = sorted[mid] ?? 0;
    return (left + right) / 2;
  }
}