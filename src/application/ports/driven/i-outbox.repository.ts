/**
 * Outbox event record written atomically with domain data changes.
 */
export interface OutboxEvent {
  id: string;
  eventType: string;
  aggregateId: string;
  aggregateType: string;
  tenantId: string;
  payload: Record<string, unknown>;
  status: 'PENDING' | 'PUBLISHED' | 'FAILED' | 'DLQ';
  attempts: number;
  createdAt: Date;
  publishedAt?: Date;
  lastError?: string;
}

/**
 * Opaque handle to an active database transaction.
 * Infrastructure adapters cast this to their concrete transaction type.
 */
export type DbTransaction = unknown;

/**
 * Driven port — transactional outbox (Section 4.5).
 *
 * Contract:
 * - `insertWithinTransaction` participates in the caller's transaction (atomicity).
 * - `claimPendingBatch` uses `SELECT ... FOR UPDATE SKIP LOCKED` — multi-replica safe.
 * - `markPublished` is idempotent.
 * - Events with `attempts >= 5` are moved to DLQ automatically.
 */
export interface IOutboxRepository {
  /**
   * Insert an outbox event within an existing DB transaction.
   * MUST be called within the same transaction as the command's data changes
   * to guarantee atomicity between domain data and outbox record.
   */
  insertWithinTransaction(event: OutboxEvent, tx: DbTransaction): Promise<void>;

  /**
   * Claim a batch of pending events for processing.
   * Uses `SELECT ... FOR UPDATE SKIP LOCKED LIMIT {limit}` so that
   * concurrent relay workers never process the same event.
   */
  claimPendingBatch(limit: number): Promise<OutboxEvent[]>;

  /**
   * Mark an event as successfully published.
   * Idempotent — safe to call multiple times.
   */
  markPublished(eventId: string): Promise<void>;

  /**
   * Increment the attempt counter and record the error message.
   */
  markFailed(eventId: string, error: string): Promise<void>;

  /**
   * Move an event to the dead-letter queue after max attempts exceeded.
   */
  moveToDlq(eventId: string): Promise<void>;
}
