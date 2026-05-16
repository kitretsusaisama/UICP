import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { IQueuePort } from '../ports/driven/i-queue.port';
import { INJECTION_TOKENS } from '../ports/injection-tokens';
import { QUEUE_NAMES } from '../../infrastructure/queue/bullmq-queue.adapter';
import { CommunicationJobPayload, CommunicationPurpose } from './communication.types';
import { TenantProviderResolver } from './provider-resolver.service';

@Injectable()
export class EmailRuntime {
  constructor(
    private readonly resolver: TenantProviderResolver,
    @Inject(INJECTION_TOKENS.QUEUE_PORT) private readonly queue: IQueuePort,
  ) {}

  async send(input: {
    tenantId: string;
    recipient: string;
    subject: string;
    text?: string;
    html?: string;
    purpose?: CommunicationPurpose;
    tenantName?: string;
    idempotencyKey?: string;
    traceId?: string;
  }) {
    const purpose = input.purpose ?? 'VERIFY_EMAIL';
    const resolution = await this.resolver.resolve({
      tenantId: input.tenantId,
      channel: 'EMAIL',
      purpose,
      tenantName: input.tenantName,
    });
    const idempotencyKey = input.idempotencyKey ?? `email:${input.tenantId}:${purpose}:${randomUUID()}`;
    const payload: CommunicationJobPayload = {
      tenantId: input.tenantId,
      lineageId: resolution.lineageId,
      idempotencyKey,
      providerName: resolution.primary.providerName,
      channel: 'EMAIL',
      purpose,
      recipient: input.recipient,
      attempt: 1,
      maxAttempts: resolution.policy.maxRetries + 1,
      createdAt: new Date().toISOString(),
      traceId: input.traceId ?? randomUUID(),
      subject: input.subject,
      text: input.text,
      html: input.html,
    };

    await this.queue.enqueue(QUEUE_NAMES.EMAIL_SEND, payload as unknown as Record<string, unknown>, {
      priority: 5,
      maxAttempts: payload.maxAttempts,
      idempotencyKey,
    });

    return {
      queued: true,
      lineageId: resolution.lineageId,
      provider: resolution.primary.providerName,
      idempotencyKey,
    };
  }
}
