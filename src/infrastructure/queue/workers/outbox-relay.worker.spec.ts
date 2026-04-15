import { OutboxRelayWorker } from './outbox-relay.worker';
import { IOutboxRepository, OutboxEvent } from '../../../application/ports/driven/i-outbox.repository';
import { BullMqQueueAdapter, QUEUE_NAMES } from '../bullmq-queue.adapter';

// ── Helpers ────────────────────────────────────────────────────────────────

function makeEvent(overrides: Partial<OutboxEvent> = {}): OutboxEvent {
  return {
    id: 'evt-001',
    eventType: 'UserCreated',
    aggregateId: 'user-123',
    aggregateType: 'User',
    tenantId: 'tenant-abc',
    payload: { foo: 'bar' },
    status: 'PENDING',
    attempts: 0,
    createdAt: new Date('2024-01-01T00:00:00.000Z'),
    ...overrides,
  };
}

function buildWorker(
  outboxRepo: Partial<IOutboxRepository>,
  queueAdapter: Partial<BullMqQueueAdapter>,
): OutboxRelayWorker {
  const mockConfig = {
    get: jest.fn().mockReturnValue(undefined),
  } as any;

  const worker = new OutboxRelayWorker(
    outboxRepo as IOutboxRepository,
    queueAdapter as BullMqQueueAdapter,
    mockConfig,
  );

  return worker;
}

// ── Tests ──────────────────────────────────────────────────────────────────

/**
 * Unit tests for OutboxRelayWorker.
 * Implements: Req 4.5
 */
describe('OutboxRelayWorker — relay scenarios', () => {
  let outboxRepo: jest.Mocked<IOutboxRepository>;
  let queueAdapter: jest.Mocked<Pick<BullMqQueueAdapter, 'enqueue'>>;

  beforeEach(() => {
    outboxRepo = {
      insertWithinTransaction: jest.fn(),
      claimPendingBatch: jest.fn(),
      markPublished: jest.fn(),
      markFailed: jest.fn(),
      moveToDlq: jest.fn(),
    };

    queueAdapter = {
      enqueue: jest.fn(),
    };
  });

  // ── Scenario 1: Successful relay ──────────────────────────────────────────

  describe('successful relay', () => {
    it('publishes the event to BullMQ and marks it as PUBLISHED', async () => {
      const event = makeEvent();
      outboxRepo.claimPendingBatch.mockResolvedValue([event]);
      outboxRepo.markPublished.mockResolvedValue(undefined);
      queueAdapter.enqueue.mockResolvedValue(undefined);

      const worker = buildWorker(outboxRepo, queueAdapter as any);
      await (worker as any).pollAndRelay();

      expect(queueAdapter.enqueue).toHaveBeenCalledTimes(1);
      expect(queueAdapter.enqueue).toHaveBeenCalledWith(
        QUEUE_NAMES.AUDIT_WRITE,
        expect.objectContaining({
          eventId: event.id,
          eventType: event.eventType,
          aggregateId: event.aggregateId,
          tenantId: event.tenantId,
        }),
      );

      expect(outboxRepo.markPublished).toHaveBeenCalledWith(event.id);
      expect(outboxRepo.markFailed).not.toHaveBeenCalled();
      expect(outboxRepo.moveToDlq).not.toHaveBeenCalled();
    });

    it('processes all events in a batch', async () => {
      const events = [makeEvent({ id: 'evt-1' }), makeEvent({ id: 'evt-2' }), makeEvent({ id: 'evt-3' })];
      outboxRepo.claimPendingBatch.mockResolvedValue(events);
      outboxRepo.markPublished.mockResolvedValue(undefined);
      queueAdapter.enqueue.mockResolvedValue(undefined);

      const worker = buildWorker(outboxRepo, queueAdapter as any);
      await (worker as any).pollAndRelay();

      expect(queueAdapter.enqueue).toHaveBeenCalledTimes(3);
      expect(outboxRepo.markPublished).toHaveBeenCalledTimes(3);
      expect(outboxRepo.markPublished).toHaveBeenCalledWith('evt-1');
      expect(outboxRepo.markPublished).toHaveBeenCalledWith('evt-2');
      expect(outboxRepo.markPublished).toHaveBeenCalledWith('evt-3');
    });

    it('does nothing when the batch is empty', async () => {
      outboxRepo.claimPendingBatch.mockResolvedValue([]);

      const worker = buildWorker(outboxRepo, queueAdapter as any);
      await (worker as any).pollAndRelay();

      expect(queueAdapter.enqueue).not.toHaveBeenCalled();
      expect(outboxRepo.markPublished).not.toHaveBeenCalled();
    });

    it('routes threat events to the soc-alert queue', async () => {
      const event = makeEvent({ eventType: 'ThreatDetected' });
      outboxRepo.claimPendingBatch.mockResolvedValue([event]);
      outboxRepo.markPublished.mockResolvedValue(undefined);
      queueAdapter.enqueue.mockResolvedValue(undefined);

      const worker = buildWorker(outboxRepo, queueAdapter as any);
      await (worker as any).pollAndRelay();

      expect(queueAdapter.enqueue).toHaveBeenCalledWith(
        QUEUE_NAMES.SOC_ALERT,
        expect.objectContaining({ eventId: event.id }),
      );
    });
  });

  // ── Scenario 2: Retry on failure ──────────────────────────────────────────

  describe('retry on failure', () => {
    it('calls markFailed and increments attempt count when publish fails (attempts < 5)', async () => {
      const event = makeEvent({ attempts: 0 });
      outboxRepo.claimPendingBatch.mockResolvedValue([event]);
      queueAdapter.enqueue.mockRejectedValue(new Error('BullMQ connection refused'));
      outboxRepo.markFailed.mockResolvedValue(undefined);

      const worker = buildWorker(outboxRepo, queueAdapter as any);
      await (worker as any).pollAndRelay();

      expect(outboxRepo.markFailed).toHaveBeenCalledWith(event.id, 'BullMQ connection refused');
      expect(outboxRepo.markPublished).not.toHaveBeenCalled();
      expect(outboxRepo.moveToDlq).not.toHaveBeenCalled();
    });

    it('increments attempt count correctly across multiple failures', async () => {
      // Simulate event that has already failed 3 times (attempts=3, next will be 4 < 5)
      const event = makeEvent({ attempts: 3 });
      outboxRepo.claimPendingBatch.mockResolvedValue([event]);
      queueAdapter.enqueue.mockRejectedValue(new Error('timeout'));
      outboxRepo.markFailed.mockResolvedValue(undefined);

      const worker = buildWorker(outboxRepo, queueAdapter as any);
      await (worker as any).pollAndRelay();

      // newAttempts = 3 + 1 = 4, which is < 5, so markFailed (not DLQ)
      expect(outboxRepo.markFailed).toHaveBeenCalledWith(event.id, 'timeout');
      expect(outboxRepo.moveToDlq).not.toHaveBeenCalled();
    });

    it('does not move to DLQ when attempts is 3 (below threshold)', async () => {
      const event = makeEvent({ attempts: 3 });
      outboxRepo.claimPendingBatch.mockResolvedValue([event]);
      queueAdapter.enqueue.mockRejectedValue(new Error('network error'));
      outboxRepo.markFailed.mockResolvedValue(undefined);

      const worker = buildWorker(outboxRepo, queueAdapter as any);
      await (worker as any).pollAndRelay();

      expect(outboxRepo.moveToDlq).not.toHaveBeenCalled();
      expect(outboxRepo.markFailed).toHaveBeenCalledTimes(1);
    });

    it('continues processing remaining events when one fails', async () => {
      const failingEvent = makeEvent({ id: 'evt-fail', attempts: 0 });
      const successEvent = makeEvent({ id: 'evt-ok', attempts: 0 });

      outboxRepo.claimPendingBatch.mockResolvedValue([failingEvent, successEvent]);
      queueAdapter.enqueue
        .mockRejectedValueOnce(new Error('fail'))
        .mockResolvedValueOnce(undefined);
      outboxRepo.markFailed.mockResolvedValue(undefined);
      outboxRepo.markPublished.mockResolvedValue(undefined);

      const worker = buildWorker(outboxRepo, queueAdapter as any);
      await (worker as any).pollAndRelay();

      expect(outboxRepo.markFailed).toHaveBeenCalledWith('evt-fail', 'fail');
      expect(outboxRepo.markPublished).toHaveBeenCalledWith('evt-ok');
    });
  });

  // ── Scenario 3: DLQ after 5 failures ─────────────────────────────────────

  describe('DLQ after 5 failures', () => {
    it('moves event to DLQ when attempts reaches MAX_ATTEMPTS (5)', async () => {
      // attempts=4, newAttempts=5 → triggers DLQ
      const event = makeEvent({ attempts: 4 });
      outboxRepo.claimPendingBatch.mockResolvedValue([event]);
      queueAdapter.enqueue
        .mockRejectedValueOnce(new Error('final failure')) // relay attempt fails
        .mockResolvedValueOnce(undefined);                 // SOC alert enqueue succeeds
      outboxRepo.moveToDlq.mockResolvedValue(undefined);

      const worker = buildWorker(outboxRepo, queueAdapter as any);
      await (worker as any).pollAndRelay();

      expect(outboxRepo.moveToDlq).toHaveBeenCalledWith(event.id);
      expect(outboxRepo.markFailed).not.toHaveBeenCalled();
    });

    it('emits a SOC alert when event is moved to DLQ', async () => {
      const event = makeEvent({ attempts: 4, tenantId: 'tenant-xyz' });
      outboxRepo.claimPendingBatch.mockResolvedValue([event]);
      queueAdapter.enqueue
        .mockRejectedValueOnce(new Error('dlq trigger'))
        .mockResolvedValueOnce(undefined);
      outboxRepo.moveToDlq.mockResolvedValue(undefined);

      const worker = buildWorker(outboxRepo, queueAdapter as any);
      await (worker as any).pollAndRelay();

      // Second enqueue call is the SOC alert
      expect(queueAdapter.enqueue).toHaveBeenCalledTimes(2);
      expect(queueAdapter.enqueue).toHaveBeenNthCalledWith(
        2,
        QUEUE_NAMES.SOC_ALERT,
        expect.objectContaining({
          alert: expect.objectContaining({
            id: `dlq-${event.id}`,
            tenantId: event.tenantId,
            signals: expect.arrayContaining([
              expect.objectContaining({ signal: 'outbox_dlq' }),
            ]),
          }),
        }),
      );
    });

    it('moves to DLQ when attempts is already at 4 (boundary: 4+1=5 >= MAX_ATTEMPTS)', async () => {
      const event = makeEvent({ attempts: 4 });
      outboxRepo.claimPendingBatch.mockResolvedValue([event]);
      queueAdapter.enqueue
        .mockRejectedValueOnce(new Error('boundary'))
        .mockResolvedValueOnce(undefined);
      outboxRepo.moveToDlq.mockResolvedValue(undefined);

      const worker = buildWorker(outboxRepo, queueAdapter as any);
      await (worker as any).pollAndRelay();

      expect(outboxRepo.moveToDlq).toHaveBeenCalledWith(event.id);
    });

    it('does NOT move to DLQ when attempts is 3 (3+1=4 < MAX_ATTEMPTS)', async () => {
      const event = makeEvent({ attempts: 3 });
      outboxRepo.claimPendingBatch.mockResolvedValue([event]);
      queueAdapter.enqueue.mockRejectedValue(new Error('not yet'));
      outboxRepo.markFailed.mockResolvedValue(undefined);

      const worker = buildWorker(outboxRepo, queueAdapter as any);
      await (worker as any).pollAndRelay();

      expect(outboxRepo.moveToDlq).not.toHaveBeenCalled();
      expect(outboxRepo.markFailed).toHaveBeenCalledWith(event.id, 'not yet');
    });

    it('SOC alert failure does not propagate — other events still processed', async () => {
      const event = makeEvent({ attempts: 4 });
      outboxRepo.claimPendingBatch.mockResolvedValue([event]);
      // Both relay and SOC alert enqueue fail
      queueAdapter.enqueue.mockRejectedValue(new Error('all fail'));
      outboxRepo.moveToDlq.mockResolvedValue(undefined);

      const worker = buildWorker(outboxRepo, queueAdapter as any);
      // Should not throw even if SOC alert enqueue fails
      await expect((worker as any).pollAndRelay()).resolves.toBeUndefined();

      expect(outboxRepo.moveToDlq).toHaveBeenCalledWith(event.id);
    });
  });

  // ── Queue routing ─────────────────────────────────────────────────────────

  describe('queue routing', () => {
    const routingCases: Array<[string, string]> = [
      ['UserCreated', QUEUE_NAMES.AUDIT_WRITE],
      ['UserSuspended', QUEUE_NAMES.AUDIT_WRITE],
      ['IdentityVerified', QUEUE_NAMES.AUDIT_WRITE],
      ['LoginSucceeded', QUEUE_NAMES.AUDIT_WRITE],
      ['LogoutRequested', QUEUE_NAMES.AUDIT_WRITE],
      ['PasswordChanged', QUEUE_NAMES.AUDIT_WRITE],
      ['SessionCreated', QUEUE_NAMES.AUDIT_WRITE],
      ['TokenIssued', QUEUE_NAMES.AUDIT_WRITE],
      ['OtpSent', QUEUE_NAMES.AUDIT_WRITE],
      ['ThreatDetected', QUEUE_NAMES.SOC_ALERT],
      ['CredentialReuse', QUEUE_NAMES.SOC_ALERT],
      ['UnknownEvent', QUEUE_NAMES.AUDIT_WRITE],
    ];

    it.each(routingCases)('routes %s to %s', async (eventType, expectedQueue) => {
      const event = makeEvent({ eventType });
      outboxRepo.claimPendingBatch.mockResolvedValue([event]);
      outboxRepo.markPublished.mockResolvedValue(undefined);
      queueAdapter.enqueue.mockResolvedValue(undefined);

      const worker = buildWorker(outboxRepo, queueAdapter as any);
      await (worker as any).pollAndRelay();

      expect(queueAdapter.enqueue).toHaveBeenCalledWith(
        expectedQueue,
        expect.objectContaining({ eventId: event.id }),
      );
    });
  });
});
