import { Controller, Get, HttpCode, HttpStatus, Optional, Inject } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { INJECTION_TOKENS } from '@application/ports/injection-tokens';
import { ICachePort } from '@application/ports/driven/i-cache.port';
import { MYSQL_POOL } from '@infrastructure/db/mysql/mysql.module';

/**
 * Health check endpoints for Kubernetes liveness/readiness probes.
 *
 * Routes:
 *   GET /health/live     — liveness probe (process is alive, no dependencies)
 *   GET /health/ready   — readiness probe (DB + Redis are reachable)
 *
 * The /health endpoint mirrors /health/ready for backward compatibility.
 */
@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(
    @Optional()
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort | undefined,
    @Optional()
    @Inject(MYSQL_POOL)
    private readonly dbPool: any,
  ) {}

  // ── GET /health (backward compat) ────────────────────────────────────────────

  @Get()
  @HttpCode(HttpStatus.OK)
  async health() {
    return this.buildResponse('/health');
  }

  // ── GET /health/live ───────────────────────────────────────────────────────

  @Get('live')
  @HttpCode(HttpStatus.OK)
  async live() {
    return {
      status: 'ok',
      ok: true,
      probe: 'live',
      timestamp: new Date().toISOString(),
    };
  }

  // ── GET /health/ready ───────────────────────────────────────────────────────

  @Get('ready')
  @HttpCode(HttpStatus.OK)
  async ready() {
    const checks = await this.runChecks();
    const allHealthy = Object.values(checks).every((c) => c.healthy);

    return {
      status: allHealthy ? 'ok' : 'degraded',
      ok: allHealthy,
      probe: 'ready',
      checks,
      timestamp: new Date().toISOString(),
    };
  }

  // ── Private ─────────────────────────────────────────────────────────────────

  private buildResponse(probe: string) {
    // For the root /health alias: fire checks, report readiness
    return this.runChecks().then((checks) => ({
      status: Object.values(checks).every((c) => c.healthy) ? 'ok' : 'degraded',
      ok: Object.values(checks).every((c) => c.healthy),
      probe,
      checks,
      timestamp: new Date().toISOString(),
    }));
  }

  private async runChecks(): Promise<Record<string, { healthy: boolean; latencyMs?: number; error?: string }>> {
    const results: Record<string, { healthy: boolean; latencyMs?: number; error?: string }> = {};

    // MySQL connectivity check
    if (this.dbPool) {
      const start = Date.now();
      try {
        const [rows]: any = await this.dbPool.execute('SELECT 1 AS val');
        results['mysql'] = {
          healthy: rows[0]?.val === 1,
          latencyMs: Date.now() - start,
        };
      } catch (err) {
        results['mysql'] = {
          healthy: false,
          latencyMs: Date.now() - start,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    } else {
      results['mysql'] = { healthy: false, error: 'MYSQL_POOL not injected' };
    }

    // Redis connectivity check
    if (this.cache) {
      const start = Date.now();
      try {
        const pong = await this.cache.ping();
        results['redis'] = {
          healthy: pong === 'PONG',
          latencyMs: Date.now() - start,
        };
      } catch (err) {
        results['redis'] = {
          healthy: false,
          latencyMs: Date.now() - start,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    } else {
      results['redis'] = { healthy: false, error: 'CACHE_PORT not injected' };
    }

    return results;
  }
}
