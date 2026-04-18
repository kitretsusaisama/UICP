import { Injectable } from '@nestjs/common';
import { HealthService } from './health.service';
import { MetricsService } from './metrics.service';

@Injectable()
export class StatusService {
  constructor(
    private readonly healthService: HealthService,
    private readonly metricsService: MetricsService
  ) {}

  async getOperationalStatus() {
    let healthState;
    try {
      healthState = await this.healthService.getReadiness();
    } catch (e: any) {
      healthState = e.response || { status: 'down', error: e.message };
    }

    const alerts = [];
    const systems = {
      auth: 'ok',
      otp: 'ok',
      sessions: 'ok',
      audit: 'ok',
      soc: 'ok'
    };

    // 1. Evaluate Queue Backlogs
    const otpQueueInfo = healthState?.checks?.queues?.['otp-send'];
    if (otpQueueInfo && otpQueueInfo.waiting > 1000) {
      systems.otp = 'degraded';
      alerts.push({ type: 'QUEUE_LAG', severity: 'HIGH', message: 'otp-send lag > 1000' });
    }

    // 2. Evaluate External / Database Statuses
    if (healthState?.checks?.mysql?.status !== 'ok') {
      systems.auth = 'degraded';
      systems.audit = 'degraded';
      alerts.push({ type: 'DB_DOWN', severity: 'CRITICAL', message: 'MySQL is down or unreachable' });
    }

    if (healthState?.checks?.redis?.status !== 'ok') {
      systems.sessions = 'degraded';
      alerts.push({ type: 'CACHE_DOWN', severity: 'CRITICAL', message: 'Redis is down or readonly' });
    }

    // Determine aggregate summary status
    const isDegraded = Object.values(systems).some(s => s !== 'ok');

    return {
      status: isDegraded ? 'degraded' : 'ok',
      summary: isDegraded ? 'System is experiencing operational issues.' : 'All systems operating normally.',
      systems,
      alerts
    };
  }
}
