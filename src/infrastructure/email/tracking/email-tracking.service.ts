import { Injectable, Logger } from '@nestjs/common';
import { Inject } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';

export type EmailDeliveryStatus =
  | 'QUEUED'
  | 'SENDING'
  | 'SENT'
  | 'DELIVERED'
  | 'BOUNCED'
  | 'FAILED'
  | 'RETRYING';

export interface EmailDeliveryLog {
  id: string;
  tenantId: string;
  lineageId: string;
  providerMessageId?: string;
  providerName?: string;
  recipient: string;
  subject?: string;
  templateKey?: string;
  status: EmailDeliveryStatus;
  errorMessage?: string;
  retryCount: number;
  providerLatencyMs?: number;
  attempt: number;
  createdAt: Date;
  sentAt?: Date;
  deliveredAt?: Date;
}

export interface CreateDeliveryLogParams {
  tenantId: string;
  lineageId: string;
  recipient: string;
  subject?: string;
  templateKey?: string;
  provider?: string;
  providerMessageId?: string;
}

@Injectable()
export class EmailTrackingService {
  private readonly logger = new Logger(EmailTrackingService.name);

  constructor(
    @Inject(INJECTION_TOKENS.CACHE_PORT) private readonly cache: ICachePort
  ) {}

  private logKey(lineageId: string): string {
    return `email:log:${lineageId}`;
  }

  private statusKey(lineageId: string): string {
    return `email:status:${lineageId}`;
  }

  async createLog(params: CreateDeliveryLogParams): Promise<EmailDeliveryLog> {
    const log: EmailDeliveryLog = {
      id: this.generateId(),
      tenantId: params.tenantId,
      lineageId: params.lineageId,
      recipient: params.recipient,
      subject: params.subject,
      templateKey: params.templateKey,
      providerName: params.provider,
      providerMessageId: params.providerMessageId,
      status: 'QUEUED',
      retryCount: 0,
      attempt: 1,
      createdAt: new Date(),
    };

    await this.cache.set(this.logKey(params.lineageId), JSON.stringify(log), 86400);
    await this.cache.set(
      this.statusKey(params.lineageId),
      'QUEUED',
      86400
    );

    this.logger.debug({ lineageId: params.lineageId, status: 'QUEUED' }, 'Created delivery log');

    return log;
  }

  async getLog(lineageId: string): Promise<EmailDeliveryLog | null> {
    const cached = await this.cache.get(this.logKey(lineageId));
    if (!cached) {
      return null;
    }
    return JSON.parse(cached) as EmailDeliveryLog;
  }

  async updateStatus(
    lineageId: string,
    status: EmailDeliveryStatus,
    metadata?: {
      providerMessageId?: string;
      providerName?: string;
      errorMessage?: string;
      providerLatencyMs?: number;
    }
  ): Promise<EmailDeliveryLog | null> {
    const log = await this.getLog(lineageId);
    if (!log) {
      this.logger.warn({ lineageId }, 'Delivery log not found for update');
      return null;
    }

    log.status = status;

    if (metadata) {
      if (metadata.providerMessageId) {
        log.providerMessageId = metadata.providerMessageId;
      }
      if (metadata.providerName) {
        log.providerName = metadata.providerName;
      }
      if (metadata.errorMessage) {
        log.errorMessage = metadata.errorMessage;
      }
      if (metadata.providerLatencyMs !== undefined) {
        log.providerLatencyMs = metadata.providerLatencyMs;
      }
    }

    // Update timestamps based on status
    const now = new Date();
    switch (status) {
      case 'SENT':
      case 'SENDING':
        log.sentAt = now;
        break;
      case 'DELIVERED':
        log.deliveredAt = now;
        break;
      case 'RETRYING':
        log.retryCount += 1;
        log.attempt += 1;
        break;
    }

    await this.cache.set(this.logKey(lineageId), JSON.stringify(log), 86400);
    await this.cache.set(this.statusKey(lineageId), status, 86400);

    this.logger.debug(
      { lineageId, status, attempt: log.attempt, retryCount: log.retryCount },
      'Updated delivery log status'
    );

    return log;
  }

  async setSending(lineageId: string, provider: string): Promise<EmailDeliveryLog | null> {
    return this.updateStatus(lineageId, 'SENDING', { providerName: provider });
  }

  async setSent(
    lineageId: string,
    providerMessageId: string,
    latencyMs: number
  ): Promise<EmailDeliveryLog | null> {
    return this.updateStatus(lineageId, 'SENT', {
      providerMessageId,
      providerLatencyMs: latencyMs,
    });
  }

  async setDelivered(lineageId: string): Promise<EmailDeliveryLog | null> {
    return this.updateStatus(lineageId, 'DELIVERED');
  }

  async setBounced(lineageId: string, errorMessage: string): Promise<EmailDeliveryLog | null> {
    return this.updateStatus(lineageId, 'BOUNCED', { errorMessage });
  }

  async setFailed(lineageId: string, errorMessage: string): Promise<EmailDeliveryLog | null> {
    return this.updateStatus(lineageId, 'FAILED', { errorMessage });
  }

  async setRetrying(lineageId: string, errorMessage: string): Promise<EmailDeliveryLog | null> {
    return this.updateStatus(lineageId, 'RETRYING', { errorMessage });
  }

  async getStatus(lineageId: string): Promise<EmailDeliveryStatus | null> {
    const status = await this.cache.get(this.statusKey(lineageId));
    return status as EmailDeliveryStatus | null;
  }

  async markDelivered(lineageId: string): Promise<void> {
    const log = await this.getLog(lineageId);
    if (!log) return;

    log.status = 'DELIVERED';
    log.deliveredAt = new Date();

    await this.cache.set(this.logKey(lineageId), JSON.stringify(log), 86400);
    await this.cache.set(this.statusKey(lineageId), 'DELIVERED', 86400);
  }

  async isDelivered(lineageId: string): Promise<boolean> {
    const status = await this.getStatus(lineageId);
    return status === 'DELIVERED';
  }

  async hasBeenSent(lineageId: string): Promise<boolean> {
    const status = await this.getStatus(lineageId);
    return status !== null && status !== 'QUEUED';
  }

  async incrementRetry(lineageId: string): Promise<number> {
    const log = await this.getLog(lineageId);
    if (!log) {
      return 0;
    }

    log.retryCount += 1;
    log.attempt += 1;
    log.status = 'RETRYING';

    await this.cache.set(this.logKey(lineageId), JSON.stringify(log), 86400);

    return log.retryCount;
  }

  async getProviderLatency(lineageId: string): Promise<number | null> {
    const log = await this.getLog(lineageId);
    return log?.providerLatencyMs ?? null;
  }

  async getLogsByTenant(
    tenantId: string,
    limit: number = 100
  ): Promise<EmailDeliveryLog[]> {
    // This would query the database in production
    // For now, return empty array - database query happens elsewhere
    return [];
  }

  async getLogsByStatus(
    status: EmailDeliveryStatus,
    limit: number = 100
  ): Promise<EmailDeliveryLog[]> {
    // This would query the database in production
    return [];
  }

  private generateId(): string {
    return `eml_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;
  }
}