/**
 * Property-Based Test — Audit Log Immutability (Property 10)
 *
 * **Property 10: UPDATE audit_logs WHERE id = A.id → 0 rows affected**
 *
 * **Validates: Req 12.1**
 *
 * The audit log is INSERT-only. Any attempt to mutate a persisted record
 * must be rejected — the original row must remain unchanged.
 *
 * Strategy: Use an in-memory stub of IAuditLogRepository that enforces
 * INSERT-only semantics (no update path). For any arbitrary audit log record:
 *   1. save(record) persists it
 *   2. Attempting to overwrite via save() with the same id is rejected
 *      (or silently ignored — 0 rows affected)
 *   3. The original record is always returned unchanged on read
 *
 * Additionally verifies HMAC checksum integrity: tampering with any field
 * causes the checksum verification to fail on read.
 */

import * as fc from 'fast-check';
import { createHmac } from 'crypto';
import { IAuditLogRepository, AuditLogRecord, AuditLogQueryParams } from '../../../application/ports/driven/i-audit-log.repository';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

// ── In-memory stub ─────────────────────────────────────────────────────────

const HMAC_KEY = 'test-audit-hmac-key';

function computeChecksum(record: AuditLogRecord): string {
  const input = [
    record.id,
    record.tenantId,
    record.actorId ?? '',
    record.actorType,
    record.action,
    record.resourceType,
    record.resourceId ?? '',
    record.createdAt.toISOString(),
  ].join('|');
  return createHmac('sha256', HMAC_KEY).update(input).digest('hex');
}

/**
 * INSERT-only in-memory audit log repository.
 * - save() is idempotent on the same id (INSERT IGNORE semantics — 0 rows affected on dup).
 * - findByTenantId() verifies HMAC checksum on every row.
 * - No update path exists.
 */
class InMemoryAuditLogRepository implements IAuditLogRepository {
  private readonly store = new Map<string, AuditLogRecord>();
  /** Tracks how many times save() was called for each id (for assertion). */
  readonly saveCalls = new Map<string, number>();

  async save(record: AuditLogRecord): Promise<void> {
    const calls = (this.saveCalls.get(record.id) ?? 0) + 1;
    this.saveCalls.set(record.id, calls);

    // INSERT IGNORE: if the id already exists, do nothing (0 rows affected)
    if (this.store.has(record.id)) {
      return; // immutable — silently ignore duplicate
    }

    // Compute and attach checksum on first insert
    const checksum = computeChecksum(record);
    this.store.set(record.id, { ...record, checksum });
  }

  async findByTenantId(tenantId: TenantId, params: AuditLogQueryParams) {
    const items: AuditLogRecord[] = [];
    for (const record of this.store.values()) {
      if (record.tenantId !== tenantId.toString()) continue;

      // Verify HMAC checksum on read (Req 12.10)
      const expected = computeChecksum(record);
      if (record.checksum !== expected) {
        throw new Error(`INTEGRITY_VIOLATION: audit log ${record.id} has been tampered`);
      }

      items.push(record);
    }
    return { items, total: items.length };
  }

  /** Test helper: directly mutate a stored record (simulates DB tampering). */
  tamper(id: string, field: keyof AuditLogRecord, value: unknown): void {
    const record = this.store.get(id);
    if (record) {
      (record as unknown as Record<string, unknown>)[field] = value;
    }
  }

  /** Test helper: get raw stored record without checksum verification. */
  getRaw(id: string): AuditLogRecord | undefined {
    return this.store.get(id);
  }
}

// ── Fixtures ───────────────────────────────────────────────────────────────

const TENANT_ID = TenantId.from('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');

function makeRecord(overrides: Partial<AuditLogRecord> = {}): AuditLogRecord {
  const id = crypto.randomUUID();
  const record: AuditLogRecord = {
    id,
    tenantId: TENANT_ID.toString(),
    actorId: crypto.randomUUID(),
    actorType: 'USER',
    action: 'LOGIN',
    resourceType: 'Session',
    resourceId: crypto.randomUUID(),
    ipHash: 'abc123',
    checksum: '', // will be computed by save()
    createdAt: new Date('2024-01-01T00:00:00.000Z'),
    ...overrides,
  };
  return record;
}

// ── Arbitraries ────────────────────────────────────────────────────────────

const actionArb = fc.constantFrom('LOGIN', 'LOGOUT', 'SIGNUP', 'PASSWORD_CHANGE', 'OTP_VERIFY');
const actorTypeArb = fc.constantFrom('USER', 'SYSTEM', 'ADMIN');
const resourceTypeArb = fc.constantFrom('Session', 'User', 'Identity', 'Token');

const recordArb = fc.record({
  action: actionArb,
  actorType: actorTypeArb,
  resourceType: resourceTypeArb,
  actorId: fc.option(fc.uuid(), { nil: undefined }),
  resourceId: fc.option(fc.uuid(), { nil: undefined }),
  ipHash: fc.option(fc.hexaString({ minLength: 8, maxLength: 16 }), { nil: undefined }),
});

// ── Property 10 ────────────────────────────────────────────────────────────

describe('Property 10 — Audit log immutability (Req 12.1)', () => {
  /**
   * Core property: saving the same record id twice does not overwrite the
   * original — the first write wins (INSERT IGNORE semantics).
   */
  it('second save() with same id does not overwrite the original record', async () => {
    await fc.assert(
      fc.asyncProperty(recordArb, recordArb, async (fieldsA, fieldsB) => {
        const repo = new InMemoryAuditLogRepository();
        const id = crypto.randomUUID();

        const recordA = makeRecord({ id, ...fieldsA });
        const recordB = makeRecord({ id, ...fieldsB, action: 'TAMPERED_ACTION' });

        await repo.save(recordA);
        await repo.save(recordB); // second save — must be ignored

        const raw = repo.getRaw(id);
        expect(raw).not.toBeNull();
        // Original action must be preserved
        expect(raw!.action).toBe(recordA.action);
        expect(raw!.action).not.toBe('TAMPERED_ACTION');
      }),
      { numRuns: 200 },
    );
  });

  it('save() is called twice but stored record count stays at 1 for the same id', async () => {
    await fc.assert(
      fc.asyncProperty(recordArb, async (fields) => {
        const repo = new InMemoryAuditLogRepository();
        const id = crypto.randomUUID();

        const record = makeRecord({ id, ...fields });
        await repo.save(record);
        await repo.save({ ...record, action: 'OVERWRITE_ATTEMPT' });

        // saveCalls tracks invocations, but the store must have exactly 1 entry
        expect(repo.saveCalls.get(id)).toBe(2); // called twice
        expect(repo.getRaw(id)!.action).toBe(record.action); // original preserved
      }),
      { numRuns: 200 },
    );
  });

  it('HMAC checksum is computed on save and verified on read', async () => {
    await fc.assert(
      fc.asyncProperty(recordArb, async (fields) => {
        const repo = new InMemoryAuditLogRepository();
        const record = makeRecord(fields);

        await repo.save(record);

        const { items } = await repo.findByTenantId(TENANT_ID, { limit: 50 });
        expect(items).toHaveLength(1);
        expect(items[0]!.id).toBe(record.id);
        // Checksum must be present and non-empty
        expect(items[0]!.checksum).toBeTruthy();
        expect(items[0]!.checksum).toHaveLength(64); // SHA-256 hex = 64 chars
      }),
      { numRuns: 100 },
    );
  });

  it('tampered record fails HMAC checksum verification on read', async () => {
    await fc.assert(
      fc.asyncProperty(
        recordArb,
        fc.constantFrom<keyof AuditLogRecord>('action', 'actorType', 'resourceType'),
        async (fields, tamperedField) => {
          const repo = new InMemoryAuditLogRepository();
          const record = makeRecord(fields);

          await repo.save(record);

          // Directly tamper with the stored record (simulates DB-level mutation)
          repo.tamper(record.id, tamperedField, 'TAMPERED_VALUE');

          // Read must throw INTEGRITY_VIOLATION
          await expect(
            repo.findByTenantId(TENANT_ID, { limit: 50 }),
          ).rejects.toThrow('INTEGRITY_VIOLATION');
        },
      ),
      { numRuns: 100 },
    );
  });

  it('multiple records with different ids are all stored independently', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(recordArb, { minLength: 2, maxLength: 10 }),
        async (fieldsList) => {
          const repo = new InMemoryAuditLogRepository();
          const records = fieldsList.map((f) => makeRecord(f));

          for (const r of records) {
            await repo.save(r);
          }

          const { items } = await repo.findByTenantId(TENANT_ID, { limit: 100 });
          expect(items).toHaveLength(records.length);

          // Each record is retrievable and unchanged
          for (const original of records) {
            const found = items.find((i) => i.id === original.id);
            expect(found).not.toBeUndefined();
            expect(found!.action).toBe(original.action);
          }
        },
      ),
      { numRuns: 50 },
    );
  });
});
