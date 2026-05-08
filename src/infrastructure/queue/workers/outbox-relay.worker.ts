import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Worker, Job } from 'bullmq';
import { IOutboxRepository, OutboxEvent } from '../../../application/ports/driven/i-outbox.repository';
import { IMetricsPort } from '../../../application/ports/driven/i-metrics.port';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { BullMqQueueAdapter, QUEUE_CONCURRENCY, QUEUE_NAMES } from '../bullmq-queue.adapter';

/** Maximum delivery attempts before moving to DLQ. */
const MAX_ATTEMPTS = 5;

/** Polling interval in milliseconds (Req 4.5 — poll every 500ms). */
const POLL_INTERVAL_MS = 500;

/** Batch size for `claimPendingBatch` (SKIP LOCKED). */
const BATCH_SIZE = 50;

/**
 * BullMQ worker for the `outbox-relay` queue.
 *
 * Implements the Transactional Outbox relay loop (Section 2.5):
 *   1. Poll `outbox_events` every 500ms using `claimPendingBatch(50)` (SKIP LOCKED).
 *   2. For each claimed event, enqueue it onto the appropriate BullMQ queue.
 *   3. Mark the event as PUBLISHED.
 *   4. On failure, increment attempt counter.
 *   5. After MAX_ATTEMPTS (5) failures, move to DLQ and emit a SOC alert.
 *
 * - Concurrency: 10 (Section 11.2 bulkhead — medium concurrency)
 * - SKIP LOCKED ensures multiple relay pods never double-process the same event.
 *
 * Implements: Req 4.5 (outbox relay), Req 15 (resilience), Property 19 (at-least-once delivery)
 */
@Injectable()
export class OutboxRelayWorker implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(OutboxRelayWorker.name);
  private worker!: Worker;
  private pollTimer?: ReturnType<typeof setInterval>;
  private isPolling = false;
  // WAR-GRADE DEFENSE: Track graceful shutdown state to not drop active relay promises
  private isShuttingDown = false;
  private activeRelayPromise: Promise<void> | null = null;

  private readonly connection: { host: string; port: number; password?: string; tls?: object };

  constructor(
    @Inject(INJECTION_TOKENS.OUTBOX_REPOSITORY)
    private readonly outboxRepository: IOutboxRepository,
    private readonly queueAdapter: BullMqQueueAdapter,
    private readonly config: ConfigService,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
  ) {
    this.connection = {
      host: this.config.get<string>('REDIS_HOST') ?? 'localhost',
      port: this.config.get<number>('REDIS_PORT') ?? 6379,
      password: this.config.get<string>('REDIS_PASSWORD'),
      tls: this.config.get<string>('REDIS_TLS') === 'true' ? {} : undefined,
    };
  }

  onModuleInit(): void {
    // The outbox relay uses a polling loop rather than a BullMQ consumer,
    // because it drives the outbox → BullMQ bridge (not the other way around).
    // A BullMQ Worker is still created to handle any jobs that were enqueued
    // directly onto the outbox-relay queue (e.g. for manual re-processing).
    this.worker = new Worker(
      QUEUE_NAMES.OUTBOX_RELAY,
      async (job: Job<{ eventId: string }>) => this.reprocessSingle(job),
      {
        connection: this.connection,
        concurrency: QUEUE_CONCURRENCY[QUEUE_NAMES.OUTBOX_RELAY],
      },
    );

    this.worker.on('failed', (job, err) => {
      this.logger.error({ jobId: job?.id, err }, 'Outbox relay job failed');
    });

    // Start the polling loop
    this.startPolling();

    this.logger.log(
      `OutboxRelayWorker started (concurrency=${QUEUE_CONCURRENCY[QUEUE_NAMES.OUTBOX_RELAY]}, pollInterval=${POLL_INTERVAL_MS}ms)`,
    );
  }

  async onModuleDestroy(): Promise<void> {
    this.isShuttingDown = true;
    this.stopPolling();

    // WAR-GRADE DEFENSE: Phase 8 Codebase Purge
    // Wait for active polling loop to finish to prevent dropping events in flight.
    if (this.activeRelayPromise) {
      this.logger.log('Waiting for active outbox relay cycle to complete before shutdown...');
      await this.activeRelayPromise;
    }

    await this.worker.close();
    this.logger.log('OutboxRelayWorker gracefully stopped');
  }

  // ── Polling Loop ───────────────────────────────────────────────────────────

  private startPolling(): void {
    this.pollTimer = setInterval(() => {
      // Prevent overlapping poll cycles
      if (!this.isPolling && !this.isShuttingDown) {
        this.activeRelayPromise = this.pollAndRelay();
      }
    }, POLL_INTERVAL_MS);
  }

  private stopPolling(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = undefined;
    }
  }

  /**
   * Core relay loop:
   * 1. Claim a batch of pending outbox events (SKIP LOCKED — multi-replica safe).
   * 2. For each event, publish to BullMQ and mark as PUBLISHED.
   * 3. On failure, increment attempt counter; move to DLQ after MAX_ATTEMPTS.
   */
  private async pollAndRelay(): Promise<void> {
    this.isPolling = true;
    try {
      const events = await this.outboxRepository.claimPendingBatch(BATCH_SIZE);

      if (events.length === 0) {
        return;
      }

      this.logger.debug({ count: events.length }, 'Claimed outbox batch');

      await Promise.allSettled(events.map((event) => this.relayEvent(event)));
    } catch (err) {
      this.logger.error({ err }, 'Outbox poll cycle failed');
    } finally {
      this.isPolling = false;
      this.activeRelayPromise = null;
    }
  }

  private async relayEvent(event: OutboxEvent): Promise<void> {
    try {
      // Determine target queue from event type
      const targetQueue = this.resolveTargetQueue(event.eventType);

      // Publish to BullMQ
      await this.queueAdapter.enqueue(targetQueue, {
        eventId: event.id,
        eventType: event.eventType,
        aggregateId: event.aggregateId,
        aggregateType: event.aggregateType,
        tenantId: event.tenantId,
        payload: event.payload,
        createdAt: event.createdAt.toISOString(),
      });

      // Mark as published
      await this.outboxRepository.markPublished(event.id);

      this.metrics?.increment('uicp_outbox_published_total', { event_type: event.eventType });

      this.logger.debug(
        { eventId: event.id, eventType: event.eventType, targetQueue },
        'Outbox event relayed',
      );
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      const newAttempts = event.attempts + 1;

      this.logger.warn(
        { eventId: event.id, eventType: event.eventType, attempts: newAttempts, err },
        'Outbox relay failed for event',
      );

      if (newAttempts >= MAX_ATTEMPTS) {
        // Move to DLQ after max attempts exceeded
        await this.outboxRepository.moveToDlq(event.id);

        this.metrics?.increment('uicp_outbox_dlq_total', { event_type: event.eventType });

        // Emit a SOC alert for DLQ events (Req 4.5)
        await this.emitDlqAlert(event, errorMessage);

        this.logger.error(
          { eventId: event.id, eventType: event.eventType },
          'Outbox event moved to DLQ after max attempts',
        );
      } else {
        await this.outboxRepository.markFailed(event.id, errorMessage);
      }
    }
  }

  /**
   * Resolve the target BullMQ queue for a given domain event type.
   * Domain events are routed to their appropriate processing queues.
   */
  private resolveTargetQueue(eventType: string): string {
    // WAR-GRADE DEFENSE: Phase 7 SOC & Detection
    // Threat/security events must route to soc-alert BEFORE falling into audit-write
    // to ensure replay and reuse events bypass normal logs and immediately trigger SOC pipelines.
    const socSecurityEventTypes = new Set<string>([
      'TokenReuseDetected',
      'ThreatSignalRaised',
    ]);

    const SOC_SECURITY_EVENT_PREFIXES = ['Security.', 'Threat.', 'AuthThreat.'] as const;

    const isExplicitSocEvent = socSecurityEventTypes.has(eventType);
    const hasSocSecurityPrefix = SOC_SECURITY_EVENT_PREFIXES.some((prefix) =>
      eventType.startsWith(prefix),
    );

    if (isExplicitSocEvent || hasSocSecurityPrefix) {
      return QUEUE_NAMES.SOC_ALERT;
    }

    // Audit events → audit-write queue
    if (
      eventType.includes('Login') ||
      eventType.includes('Logout') ||
      eventType.includes('Password') ||
      eventType.includes('Identity') ||
      eventType.includes('User') ||
      eventType.includes('Session') ||
      eventType.includes('Token') ||
      eventType.includes('Otp')
    ) {
      return QUEUE_NAMES.AUDIT_WRITE;
    }

    // Default: audit-write (catch-all for domain events)
    return QUEUE_NAMES.AUDIT_WRITE;
  }

  /**
   * Emit a SOC alert when an outbox event is moved to DLQ.
   * Uses the queue adapter to enqueue a soc-alert job.
   */
  private async emitDlqAlert(event: OutboxEvent, lastError: string): Promise<void> {
    try {
      await this.queueAdapter.enqueue(QUEUE_NAMES.SOC_ALERT, {
        alert: {
          id: `dlq-${event.id}`,
          tenantId: event.tenantId,
          ipHash: '',
          threatScore: 0,
          killChainStage: 'INITIAL_ACCESS',
          signals: [{ signal: 'outbox_dlq', score: 0, detail: lastError }],
          workflow: 'OPEN',
          checksum: '',
          createdAt: new Date().toISOString(),
        },
      });
    } catch (err) {
      this.logger.error({ err, eventId: event.id }, 'Failed to emit DLQ SOC alert');
    }
  }

  /**
   * Re-process a single outbox event by ID (for manual retry via BullMQ job).
   */
  private async reprocessSingle(job: Job<{ eventId: string }>): Promise<void> {
    this.logger.debug({ jobId: job.id, eventId: job.data.eventId }, 'Manual outbox event reprocess');
    // Re-trigger a poll cycle to pick up the event
    await this.pollAndRelay();
  }
}
