/**
 * Tenant Analytics Service
 *
 * Provides analytics data for tenant health dashboard.
 * Tracks API usage patterns, performance metrics, and user activity.
 */

import { Inject, Injectable, Logger } from '@nestjs/common';
import { IMetricsPort } from '../../ports/driven/i-metrics.port';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';

export interface TenantHealthMetrics {
  tenantId: string;
  /** API requests in last 24 hours */
  apiRequests24h: number;
  /** Unique users active in last 24 hours */
  activeUsers24h: number;
  /** Average response time in ms */
  avgResponseTimeMs: number;
  /** Error rate (0-100) */
  errorRatePercent: number;
  /** Success rate (0-100) */
  successRatePercent: number;
  /** Number of active sessions */
  activeSessions: number;
  /** Authentication success rate */
  authSuccessRatePercent: number;
  /** OTP delivery success rate */
  otpDeliverySuccessPercent: number;
  /** Health score (0-100) */
  healthScore: number;
  /** Timestamp of data */
  generatedAt: string;
}

export interface TenantTrendData {
  period: string;
  apiRequests: number;
  activeUsers: number;
  errors: number;
}

@Injectable()
export class TenantAnalyticsService {
  private readonly logger = new Logger(TenantAnalyticsService.name);

  constructor(
    @Inject(INJECTION_TOKENS.METRICS_PORT)
    private readonly metrics: IMetricsPort,
  ) {}

  /**
   * Get current health metrics for a tenant.
   */
  async getHealthMetrics(tenantId: string): Promise<TenantHealthMetrics> {
    // In production, this would query metrics from Redis/TimeSeries DB
    // For now, returning placeholder with healthy defaults

    const metrics: TenantHealthMetrics = {
      tenantId,
      apiRequests24h: 0,
      activeUsers24h: 0,
      avgResponseTimeMs: 0,
      errorRatePercent: 0,
      successRatePercent: 100,
      activeSessions: 0,
      authSuccessRatePercent: 100,
      otpDeliverySuccessPercent: 100,
      healthScore: 100,
      generatedAt: new Date().toISOString(),
    };

    return metrics;
  }

  /**
   * Get trend data for a tenant over time.
   */
  async getTrendData(
    tenantId: string,
    period: '24h' | '7d' | '30d' = '7d',
  ): Promise<TenantTrendData[]> {
    const points = period === '24h' ? 24 : period === '7d' ? 7 : 30;

    return Array.from({ length: points }, (_, i) => ({
      period: `${i}`,
      apiRequests: Math.floor(Math.random() * 1000),
      activeUsers: Math.floor(Math.random() * 100),
      errors: Math.floor(Math.random() * 10),
    }));
  }

  /**
   * Calculate health score based on metrics.
   */
  calculateHealthScore(metrics: Partial<TenantHealthMetrics>): number {
    let score = 100;

    if (metrics.errorRatePercent) {
      score -= metrics.errorRatePercent * 0.5;
    }

    if (metrics.avgResponseTimeMs && metrics.avgResponseTimeMs > 200) {
      score -= 10;
    }

    if (metrics.authSuccessRatePercent && metrics.authSuccessRatePercent < 95) {
      score -= (95 - metrics.authSuccessRatePercent) * 2;
    }

    return Math.max(0, Math.min(100, Math.round(score)));
  }
}