import { Inject, Injectable, ConflictException } from '@nestjs/common';
import { IEventStore } from '../../../application/ports/driven/i-event-store';
import { DomainEvent } from '../../../domain/events/domain-event.base';
import { MYSQL_POOL, DbPool } from './mysql.module';

function uuidToBuffer(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

function bufferToUuid(buf: Buffer | string): string {
  const hex = Buffer.isBuffer(buf) ? buf.toString('hex') : Buffer.from(buf).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface DomainEventRow {
  id: Buffer;
  aggregate_id: string;
  aggregate_type: string;
  event_type: string;
  aggregate_seq: number;
  payload_enc: Buffer;
  payload_enc_kid: string;
  tenant_id: Buffer;
  created_at: Date;
}

/**
 * MySQL implementation of IEventStore.
 *
 * - append() uses INSERT with the uq_aggregate_seq unique key to enforce
 *   optimistic concurrency — duplicate seq throws ConflictException(VERSION_CONFLICT).
 * - loadEvents() returns events ordered by aggregate_seq ASC.
 * - Events are immutable once written (no UPDATE/DELETE).
 *
 * NOTE: Event payloads are stored as JSON serialised to a VARBINARY column
 * (payload_enc). In production these would be AES-256-GCM encrypted via the
 * IEncryptionPort; here we store plain JSON to keep the repository focused on
 * persistence concerns. The encryption adapter wraps this layer.
 */
@Injectable()
export class MysqlEventStoreRepository implements IEventStore {
  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async append(aggregateId: string, events: DomainEvent[]): Promise<void> {
    if (events.length === 0) return;

    const conn = await this.pool.getConnection();
    try {
      await conn.beginTransaction();

      for (const event of events) {
        const payloadJson = JSON.stringify(this._serializeEvent(event));
        const payloadBuf = Buffer.from(payloadJson, 'utf8');

        try {
          await conn.execute(
            `INSERT INTO domain_events
               (id, aggregate_id, aggregate_type, event_type,
                aggregate_seq, payload_enc, payload_enc_kid,
                tenant_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, '', ?, ?)`,
            [
              uuidToBuffer(event.eventId),
              aggregateId,
              event.aggregateType,
              event.eventType,
              event.aggregateSeq,
              payloadBuf,
              uuidToBuffer(event.tenantId),
              event.occurredAt,
            ],
          );
        } catch (err: unknown) {
          if (this._isDuplicateKeyError(err)) {
            await conn.rollback();
            throw new ConflictException('VERSION_CONFLICT');
          }
          throw err;
        }
      }

      await conn.commit();
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  }

  async loadEvents(aggregateId: string): Promise<DomainEvent[]> {
    const [rows] = await this.pool.execute<DomainEventRow[]>(
      `SELECT id, aggregate_id, aggregate_type, event_type,
              aggregate_seq, payload_enc, payload_enc_kid,
              tenant_id, created_at
         FROM domain_events
        WHERE aggregate_id = ?
        ORDER BY aggregate_seq ASC`,
      [aggregateId],
    );

    return (rows as DomainEventRow[]).map((row) => this._deserializeEvent(row));
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private _serializeEvent(event: DomainEvent): Record<string, unknown> {
    // Capture all enumerable own properties (eventType, payload, etc.)
    return { ...event };
  }

  private _deserializeEvent(row: DomainEventRow): DomainEvent {
    const payload = JSON.parse(row.payload_enc.toString('utf8')) as Record<string, unknown>;

    // Return a plain object that satisfies the DomainEvent interface.
    // Command handlers that need typed events (e.g. UserCreatedEvent) should
    // use User.fromEvents() which re-applies the typed event classes.
    return {
      eventId: bufferToUuid(row.id),
      aggregateId: row.aggregate_id,
      aggregateType: row.aggregate_type,
      eventType: row.event_type,
      aggregateSeq: row.aggregate_seq,
      tenantId: bufferToUuid(row.tenant_id),
      occurredAt: row.created_at,
      ...payload,
    } as unknown as DomainEvent;
  }

  private _isDuplicateKeyError(err: unknown): boolean {
    return (
      typeof err === 'object' &&
      err !== null &&
      'code' in err &&
      (err as { code: string }).code === 'ER_DUP_ENTRY'
    );
  }
}
