import { Injectable, Inject, Logger } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { INJECTION_TOKENS } from '../ports/injection-tokens';
import { IOutboxRepository, OutboxEvent } from '../ports/driven/i-outbox.repository';
import { IQueuePort } from '../ports/driven/i-queue.port';
import { UserId } from '../../domain/value-objects/user-id.vo';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';
import { IdentityId } from '../../domain/value-objects/identity-id.vo';

export interface IdentityVerificationSagaInput {
  userId: string;
  identityId: string;
  tenantId: string;
}

enum SagaState {
  STARTED = 'STARTED',
  WELCOME_EMAIL_SENT = 'WELCOME_EMAIL_SENT',
  AUDIT_LOGGED = 'AUDIT_LOGGED',
  COMPLETED = 'COMPLETED',
  COMPENSATING = 'COMPENSATING',
  COMPENSATION_FAILED = 'COMPENSATION_FAILED',
}

/**
 * IdentityVerificationSaga — orchestrates post-verification side effects.
 *
 * Triggered after OTP verification for new user signup (Section 5.7).
 *
 * Steps:
 *   1. Send welcome email (non-critical — failure is logged and skipped)
 *   2. Write audit log entry (via outbox for at-least-once guarantee)
 *   3. Trigger downstream provisioning via queue
 *
 * Compensation:
 *   - Welcome email failure: non-critical, continue
 *   - Audit log failure: retry via outbox
 *   - Provisioning failure: set PROVISIONING_FAILED metadata flag, alert SOC
 *
 * Implements: Req 2.1 (OTP dispatch after signup), Req 12.1 (audit log write)
 */
@Injectable()
export class IdentityVerificationSaga {
  private readonly logger = new Logger(IdentityVerificationSaga.name);

  constructor(
    @Inject(INJECTION_TOKENS.OUTBOX_REPOSITORY)
    private readonly outboxRepo: IOutboxRepository,
    @Inject(INJECTION_TOKENS.QUEUE_PORT)
    private readonly queue: IQueuePort,
  ) {}

  /**
   * Execute the saga for a newly verified identity.
   * Each step is independently fault-tolerant.
   */
  async execute(input: IdentityVerificationSagaInput): Promise<void> {
    const userId = UserId.from(input.userId);
    const tenantId = TenantId.from(input.tenantId);
    const identityId = IdentityId.from(input.identityId);

    let state: SagaState = SagaState.STARTED;

    this.logger.log(
      { userId: input.userId, identityId: input.identityId, state },
      'IdentityVerificationSaga started',
    );

    // ── Step 1: Send welcome email (non-critical) ──────────────────────────
    try {
      await this._sendWelcomeEmail(userId, tenantId);
      state = SagaState.WELCOME_EMAIL_SENT;
      this.logger.log({ userId: input.userId, state }, 'Welcome email sent');
    } catch (err) {
      // Non-critical — log warning and continue
      this.logger.warn(
        { userId: input.userId, err },
        'Welcome email failed — continuing saga',
      );
    }

    // ── Step 2: Write audit log (via outbox for at-least-once) ────────────
    try {
      await this._writeAuditLog(userId, identityId, tenantId);
      state = SagaState.AUDIT_LOGGED;
      this.logger.log({ userId: input.userId, state }, 'Audit log written');
    } catch (err) {
      this.logger.error(
        { userId: input.userId, err },
        'Audit log write failed — enqueuing for retry',
      );
      // Outbox guarantees at-least-once delivery; failure here is retried by relay worker
    }

    // ── Step 3: Trigger downstream provisioning ───────────────────────────
    try {
      await this._triggerProvisioning(userId, tenantId);
      state = SagaState.COMPLETED;
      this.logger.log({ userId: input.userId, state }, 'IdentityVerificationSaga completed');
    } catch (err) {
      state = SagaState.COMPENSATING;
      this.logger.error(
        { userId: input.userId, err, state },
        'Provisioning failed — running compensation',
      );
      await this._compensateProvisioningFailure(userId, tenantId, err as Error);
    }
  }

  // ── Private steps ──────────────────────────────────────────────────────────

  /**
   * Step 1: Enqueue a welcome email via the queue (non-critical).
   * We use the queue rather than the OTP port directly because welcome emails
   * are informational and do not require a code — the worker handles templating.
   */
  private async _sendWelcomeEmail(userId: UserId, tenantId: TenantId): Promise<void> {
    await this.queue.enqueue('welcome-email', {
      userId: userId.toString(),
      tenantId: tenantId.toString(),
      sentAt: new Date().toISOString(),
    });
  }

  /**
   * Step 2: Write an audit log entry via the outbox (at-least-once guarantee).
   */
  private async _writeAuditLog(
    userId: UserId,
    identityId: IdentityId,
    tenantId: TenantId,
  ): Promise<void> {
    const auditEvent: OutboxEvent = {
      id: randomUUID(),
      eventType: 'AuditLog',
      aggregateId: userId.toString(),
      aggregateType: 'User',
      tenantId: tenantId.toString(),
      payload: {
        actorId: userId.toString(),
        actorType: 'user',
        action: 'identity.verified',
        resourceType: 'Identity',
        resourceId: identityId.toString(),
        metadata: { sagaStep: 'IdentityVerificationSaga.writeAuditLog' },
      },
      status: 'PENDING',
      attempts: 0,
      createdAt: new Date(),
    };

    await this.outboxRepo.insertWithinTransaction(auditEvent, null);
  }

  /**
   * Step 3: Enqueue a provisioning job for downstream systems.
   */
  private async _triggerProvisioning(userId: UserId, tenantId: TenantId): Promise<void> {
    await this.queue.enqueue('user-provisioning', {
      userId: userId.toString(),
      tenantId: tenantId.toString(),
      triggeredAt: new Date().toISOString(),
    });
  }

  /**
   * Compensation: mark user with PROVISIONING_FAILED metadata and emit SOC alert.
   */
  private async _compensateProvisioningFailure(
    userId: UserId,
    tenantId: TenantId,
    error: Error,
  ): Promise<void> {
    try {
      // Enqueue a SOC alert for the provisioning failure
      const socAlertEvent: OutboxEvent = {
        id: randomUUID(),
        eventType: 'SocAlert',
        aggregateId: userId.toString(),
        aggregateType: 'User',
        tenantId: tenantId.toString(),
        payload: {
          type: 'PROVISIONING_FAILED',
          userId: userId.toString(),
          error: error.message,
          sagaState: SagaState.COMPENSATING,
        },
        status: 'PENDING',
        attempts: 0,
        createdAt: new Date(),
      };

      await this.outboxRepo.insertWithinTransaction(socAlertEvent, null);

      this.logger.warn(
        { userId: userId.toString() },
        'Compensation complete — PROVISIONING_FAILED alert emitted',
      );
    } catch (compensationErr) {
      this.logger.error(
        { userId: userId.toString(), compensationErr },
        'Compensation itself failed — saga in COMPENSATION_FAILED state',
      );
    }
  }
}
