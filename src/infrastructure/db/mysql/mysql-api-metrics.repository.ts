import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import {
  IApiMetricsPort,
  ApiMetricEntry,
} from '../../../application/ports/driven/i-api-metrics.port';
import { MYSQL_POOL, DbPool } from './mysql.module';
import { uuidToBuffer, bufferToUuid } from './uuid-utils';

interface ApiMetricRow {
  id: Buffer;
  tenant_id: Buffer;
  user_id: Buffer | null;
  principal_id: Buffer | null;
  method: string;
  path: string;
  path_template: string | null;
  status_code: number;
  latency_ms: number;
  db_query_count: number;
  db_query_time_ms: number;
  cache_hit: number;
  external_api_calls: number;
  external_api_time_ms: number;
  request_size_bytes: number | null;
  response_size_bytes: number | null;
  user_agent: string | null;
  ip_hash: Buffer | null;
  correlation_id: string | null;
  error_type: string | null;
  error_message: string | null;
  created_at: Date;
}

@Injectable()
export class MysqlApiMetricsRepository implements IApiMetricsPort {
  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async record(entry: Omit<ApiMetricEntry, 'createdAt'>): Promise<void> {
    await this.pool.execute(
      `INSERT INTO api_metrics (
        id, tenant_id, user_id, principal_id, method, path, path_template,
        status_code, latency_ms, db_query_count, db_query_time_ms, cache_hit,
        external_api_calls, external_api_time_ms, request_size_bytes,
        response_size_bytes, user_agent, ip_hash, correlation_id,
        error_type, error_message, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(3))`,
      [
        uuidToBuffer(randomUUID()),
        uuidToBuffer(entry.tenantId),
        entry.userId ? uuidToBuffer(entry.userId) : null,
        entry.principalId ? uuidToBuffer(entry.principalId) : null,
        entry.method,
        entry.path,
        entry.pathTemplate ?? null,
        entry.statusCode,
        entry.latencyMs,
        entry.dbQueryCount,
        entry.dbQueryTimeMs,
        entry.cacheHit ? 1 : 0,
        entry.externalApiCalls,
        entry.externalApiTimeMs,
        entry.requestSizeBytes ?? null,
        entry.responseSizeBytes ?? null,
        entry.userAgent ?? null,
        entry.ipHash ? Buffer.from(entry.ipHash, 'hex') : null,
        entry.correlationId ?? null,
        entry.errorType ?? null,
        entry.errorMessage ?? null,
      ],
    );
  }

  async recordBatch(entries: Omit<ApiMetricEntry, 'createdAt'>[]): Promise<void> {
    if (entries.length === 0) return;

    const conn = await this.pool.getConnection();
    try {
      await conn.beginTransaction();

      for (const entry of entries) {
        await conn.execute(
          `INSERT INTO api_metrics (
            id, tenant_id, user_id, principal_id, method, path, path_template,
            status_code, latency_ms, db_query_count, db_query_time_ms, cache_hit,
            external_api_calls, external_api_time_ms, request_size_bytes,
            response_size_bytes, user_agent, ip_hash, correlation_id,
            error_type, error_message, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(3))`,
          [
            uuidToBuffer(randomUUID()),
            uuidToBuffer(entry.tenantId),
            entry.userId ? uuidToBuffer(entry.userId) : null,
            entry.principalId ? uuidToBuffer(entry.principalId) : null,
            entry.method,
            entry.path,
            entry.pathTemplate ?? null,
            entry.statusCode,
            entry.latencyMs,
            entry.dbQueryCount,
            entry.dbQueryTimeMs,
            entry.cacheHit ? 1 : 0,
            entry.externalApiCalls,
            entry.externalApiTimeMs,
            entry.requestSizeBytes ?? null,
            entry.responseSizeBytes ?? null,
            entry.userAgent ?? null,
            entry.ipHash ? Buffer.from(entry.ipHash, 'hex') : null,
            entry.correlationId ?? null,
            entry.errorType ?? null,
            entry.errorMessage ?? null,
          ],
        );
      }

      await conn.commit();
    } catch (error) {
      await conn.rollback();
      throw error;
    } finally {
      conn.release();
    }
  }

  async getStats(
    tenantId: string,
    pathTemplate: string,
    from: Date,
    to: Date,
  ): Promise<{
    count: number;
    avgLatencyMs: number;
    p50LatencyMs: number;
    p95LatencyMs: number;
    p99LatencyMs: number;
    errorRate: number;
  }> {
    const [rows] = await this.pool.execute<any[]>(
      `SELECT
        COUNT(*) as count,
        AVG(latency_ms) as avg_latency,
        PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_ms) as p50_latency,
        PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) as p95_latency,
        PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ms) as p99_latency,
        SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) / COUNT(*) as error_rate
       FROM api_metrics
       WHERE tenant_id = ?
         AND path_template = ?
         AND created_at >= ?
         AND created_at <= ?`,
      [uuidToBuffer(tenantId), pathTemplate, from, to],
    );

    const row = rows[0];
    return {
      count: Number(row.count) || 0,
      avgLatencyMs: parseFloat(row.avg_latency) || 0,
      p50LatencyMs: parseFloat(row.p50_latency) || 0,
      p95LatencyMs: parseFloat(row.p95_latency) || 0,
      p99LatencyMs: parseFloat(row.p99_latency) || 0,
      errorRate: parseFloat(row.error_rate) || 0,
    };
  }
}