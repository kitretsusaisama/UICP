import { Injectable, Inject, ServiceUnavailableException } from '@nestjs/common';
import { MetricsService } from './metrics.service';
import { Pool } from 'mysql2/promise';

@Injectable()
export class HealthService {
  constructor(
    @Inject('CACHE_PORT') private readonly cache: any,
    @Inject('QUEUE_PORT') private readonly queue: any,
    @Inject('MYSQL_POOL') private readonly dbPool: Pool,
    private readonly metrics: MetricsService
  ) {}

  getLiveness() {
    return {
      status: 'alive',
      uptime: process.uptime(),
      timestamp: Math.floor(Date.now() / 1000)
    };
  }

  async getReadiness() {
    const checks: any = {};
    let isReady = true;
    let isDegraded = false;

    // 1. MySQL Check
    const mysqlStart = Date.now();
    try {
      await this.dbPool.query('SELECT 1');
      checks.mysql = { status: 'ok', latencyMs: Date.now() - mysqlStart };
    } catch (e: any) {
      checks.mysql = { status: 'down', error: e.message };
      isReady = false;
    }

    // 2. Redis Check
    const redisStart = Date.now();
    try {
      await this.cache.set('health_check', 'ok', 5);
      const val = await this.cache.get('health_check');
      if (val !== 'ok') throw new Error('Write test failed');
      checks.redis = { status: 'ok', latencyMs: Date.now() - redisStart };
    } catch (e: any) {
      checks.redis = { status: 'down', error: e.message };
      isReady = false;
    }

    // 3. Queue Check
    checks.queues = {};
    try {
      const otpQueue = this.queue.getQueue('otp-send');
      if (otpQueue) {
        const waiting = await otpQueue.getWaitingCount();
        const stalled = await otpQueue.getStalledCount();
        this.metrics.queueJobsWaiting.set({ name: 'otp-send' }, waiting);
        if (waiting > 1000) {
          checks.queues['otp-send'] = { status: 'degraded', waiting };
          isDegraded = true;
        } else {
          checks.queues['otp-send'] = { status: 'ok', waiting };
        }
      }
    } catch (e: any) {
      checks.queues.error = e.message;
      isDegraded = true;
    }

    const finalStatus = isReady ? (isDegraded ? 'degraded' : 'ready') : 'not_ready';
    const response = { status: finalStatus, checks };

    if (!isReady) {
      throw new ServiceUnavailableException(response);
    }

    return response;
  }
}
