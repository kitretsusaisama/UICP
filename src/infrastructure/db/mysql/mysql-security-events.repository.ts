import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import {
  ISecurityEventsPort,
  SecurityEvent,
  SecurityEventType,
  SecurityEventSeverity,
  SecurityEventDetectionMethod,
} from '../../../application/ports/driven/i-security-events.port';
import { MYSQL_POOL, DbPool } from './mysql.module';
import { uuidToBuffer, bufferToUuid } from './uuid-utils';

interface SecurityEventRow {
  id: Buffer;
  tenant_id: Buffer;
  user_id: Buffer | null;
  principal_id: Buffer | null;
  session_id: Buffer | null;
  event_type: string;
  severity: string;
  ip_hash: Buffer | null;
  ip_country: string | null;
  ip_city: string | null;
  user_agent: string | null;
  device_fingerprint: string | null;
  geo_delta_seconds: number | null;
  ip_change_detected: number;
  time_delta_from_last: number | null;
  failure_count_window: number | null;
  details_json: string | null;
  threat_score: string | null;
  detected_by: string;
  created_at: Date;
}

function rowToSecurityEvent(row: SecurityEventRow): SecurityEvent {
  return {
    id: bufferToUuid(row.id),
    tenantId: bufferToUuid(row.tenant_id),
    userId: row.user_id ? bufferToUuid(row.user_id) : undefined,
    principalId: row.principal_id ? bufferToUuid(row.principal_id) : undefined,
    sessionId: row.session_id ? bufferToUuid(row.session_id) : undefined,
    eventType: row.event_type as SecurityEventType,
    severity: row.severity as SecurityEventSeverity,
    ipHash: row.ip_hash ? row.ip_hash.toString('hex') : undefined,
    ipCountry: row.ip_country ?? undefined,
    ipCity: row.ip_city ?? undefined,
    userAgent: row.user_agent ?? undefined,
    deviceFingerprint: row.device_fingerprint ?? undefined,
    geoDeltaSeconds: row.geo_delta_seconds ?? undefined,
    ipChangeDetected: row.ip_change_detected === 1,
    timeDeltaFromLast: row.time_delta_from_last ?? undefined,
    failureCountWindow: row.failure_count_window ?? undefined,
    detailsJson: row.details_json ? JSON.parse(row.details_json) : undefined,
    threatScore: row.threat_score ? parseFloat(row.threat_score) : undefined,
    detectedBy: row.detected_by as SecurityEventDetectionMethod,
    createdAt: row.created_at,
  };
}

@Injectable()
export class MysqlSecurityEventsRepository implements ISecurityEventsPort {
  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async log(event: Omit<SecurityEvent, 'id' | 'createdAt'>): Promise<void> {
    await this.pool.execute(
      `INSERT INTO security_events (
        id, tenant_id, user_id, principal_id, session_id,
        event_type, severity, ip_hash, ip_country, ip_city,
        user_agent, device_fingerprint, geo_delta_seconds,
        ip_change_detected, time_delta_from_last, failure_count_window,
        details_json, threat_score, detected_by, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(3))`,
      [
        uuidToBuffer(randomUUID()),
        uuidToBuffer(event.tenantId),
        event.userId ? uuidToBuffer(event.userId) : null,
        event.principalId ? uuidToBuffer(event.principalId) : null,
        event.sessionId ? uuidToBuffer(event.sessionId) : null,
        event.eventType,
        event.severity,
        event.ipHash ? Buffer.from(event.ipHash, 'hex') : null,
        event.ipCountry ?? null,
        event.ipCity ?? null,
        event.userAgent ?? null,
        event.deviceFingerprint ?? null,
        event.geoDeltaSeconds ?? null,
        event.ipChangeDetected ? 1 : 0,
        event.timeDeltaFromLast ?? null,
        event.failureCountWindow ?? null,
        event.detailsJson ? JSON.stringify(event.detailsJson) : null,
        event.threatScore ?? null,
        event.detectedBy,
      ],
    );
  }

  async logBatch(events: Omit<SecurityEvent, 'id' | 'createdAt'>[]): Promise<void> {
    if (events.length === 0) return;

    const conn = await this.pool.getConnection();
    try {
      await conn.beginTransaction();

      for (const event of events) {
        await conn.execute(
          `INSERT INTO security_events (
            id, tenant_id, user_id, principal_id, session_id,
            event_type, severity, ip_hash, ip_country, ip_city,
            user_agent, device_fingerprint, geo_delta_seconds,
            ip_change_detected, time_delta_from_last, failure_count_window,
            details_json, threat_score, detected_by, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(3))`,
          [
            uuidToBuffer(randomUUID()),
            uuidToBuffer(event.tenantId),
            event.userId ? uuidToBuffer(event.userId) : null,
            event.principalId ? uuidToBuffer(event.principalId) : null,
            event.sessionId ? uuidToBuffer(event.sessionId) : null,
            event.eventType,
            event.severity,
            event.ipHash ? Buffer.from(event.ipHash, 'hex') : null,
            event.ipCountry ?? null,
            event.ipCity ?? null,
            event.userAgent ?? null,
            event.deviceFingerprint ?? null,
            event.geoDeltaSeconds ?? null,
            event.ipChangeDetected ? 1 : 0,
            event.timeDeltaFromLast ?? null,
            event.failureCountWindow ?? null,
            event.detailsJson ? JSON.stringify(event.detailsJson) : null,
            event.threatScore ?? null,
            event.detectedBy,
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

  async findByTenant(
    tenantId: string,
    options?: {
      eventTypes?: SecurityEventType[];
      severities?: SecurityEventSeverity[];
      from?: Date;
      to?: Date;
      limit?: number;
      offset?: number;
    },
  ): Promise<SecurityEvent[]> {
    const conditions: string[] = ['tenant_id = ?'];
    const params: unknown[] = [uuidToBuffer(tenantId)];

    if (options?.eventTypes?.length) {
      conditions.push(`event_type IN (${options.eventTypes.map(() => '?').join(',')})`);
      params.push(...options.eventTypes);
    }

    if (options?.severities?.length) {
      conditions.push(`severity IN (${options.severities.map(() => '?').join(',')})`);
      params.push(...options.severities);
    }

    if (options?.from) {
      conditions.push('created_at >= ?');
      params.push(options.from);
    }

    if (options?.to) {
      conditions.push('created_at <= ?');
      params.push(options.to);
    }

    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;

    const [rows] = await this.pool.execute<SecurityEventRow[]>(
      `SELECT * FROM security_events
       WHERE ${conditions.join(' AND ')}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset],
    );

    return rows.map(rowToSecurityEvent);
  }

  async findByUser(
    userId: string,
    options?: {
      eventTypes?: SecurityEventType[];
      from?: Date;
      to?: Date;
      limit?: number;
    },
  ): Promise<SecurityEvent[]> {
    const conditions: string[] = ['user_id = ?'];
    const params: unknown[] = [uuidToBuffer(userId)];

    if (options?.eventTypes?.length) {
      conditions.push(`event_type IN (${options.eventTypes.map(() => '?').join(',')})`);
      params.push(...options.eventTypes);
    }

    if (options?.from) {
      conditions.push('created_at >= ?');
      params.push(options.from);
    }

    if (options?.to) {
      conditions.push('created_at <= ?');
      params.push(options.to);
    }

    const limit = options?.limit ?? 100;

    const [rows] = await this.pool.execute<SecurityEventRow[]>(
      `SELECT * FROM security_events
       WHERE ${conditions.join(' AND ')}
       ORDER BY created_at DESC
       LIMIT ?`,
      [...params, limit],
    );

    return rows.map(rowToSecurityEvent);
  }
}