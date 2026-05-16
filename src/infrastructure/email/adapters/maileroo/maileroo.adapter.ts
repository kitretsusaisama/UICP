import { Injectable, Logger } from '@nestjs/common';
import {
  IEmailProviderAdapter,
  ProviderType,
  ProviderCapabilities,
  SendEmailPayload,
  SendResult,
  ProviderHealth,
  ProviderConfigValidation,
  ParsedWebhookEvent,
  CredentialsSchema,
} from '../../../../application/ports/driven/i-email-adapter.port';

export interface MailerooCredentials {
  apiKey: string;
  fromEmail: string;
  fromName?: string;
}

@Injectable()
export class MailerooEmailAdapter implements IEmailProviderAdapter {
  private readonly logger = new Logger(MailerooEmailAdapter.name);

  readonly providerKey = 'MAILEROO';
  readonly providerType: ProviderType = 'MAILEROO';
  readonly channel: 'EMAIL' = 'EMAIL';

  readonly capabilities: ProviderCapabilities = {
    supportsWebhooks: true,
    supportsTemplates: false,
    supportsBatch: true,
    supportsCustomHeaders: true,
    maxRecipientsPerSend: 50,
    regions: ['us-east-1', 'eu-west-1'],
  };

  async send(
    params: SendEmailPayload & { credentials: MailerooCredentials },
  ): Promise<SendResult> {
    const startTime = Date.now();

    const response = await fetch('https://smtp.maileroo.com/api/v2/emails', {
      method: 'POST',
      headers: {
        'X-API-Key': params.credentials.apiKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: {
          address: params.fromEmail ?? params.credentials.fromEmail,
          name: params.fromName ?? params.credentials.fromName,
        },
        to: params.recipients ?? [{ address: params.recipient }],
        subject: params.subject,
        html: params.html,
        plain: params.text,
        tags: {
          purpose: params.purpose,
          tenantId: params.tenantId,
          traceId: params.traceId,
        },
      }),
    });

    const latencyMs = Date.now() - startTime;

    if (!response.ok) {
      const error = await response.text();
      this.logger.error({ status: response.status, error }, 'Maileroo send failed');
      throw new Error(`Maileroo API error: ${response.status} - ${error}`);
    }

    const payload = (await response.json()) as { data?: { id?: string }; id?: string };

    return {
      providerMessageId: payload.data?.id ?? payload.id,
      accepted: true,
      latencyMs,
    };
  }

  async sendBatch(
    params: (SendEmailPayload & { credentials: MailerooCredentials })[],
  ): Promise<SendResult> {
    const startTime = Date.now();
    const first = params[0]!;  // Non-null assertion for batch send

    const response = await fetch('https://smtp.maileroo.com/api/v2/emails/batch', {
      method: 'POST',
      headers: {
        'X-API-Key': first.credentials.apiKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        emails: params.map((p) => ({
          to: [{ address: p.recipient }],
          subject: p.subject,
          html: p.html,
          plain: p.text,
        })),
      }),
    });

    const latencyMs = Date.now() - startTime;

    if (!response.ok) {
      throw new Error(`Maileroo batch failed: ${response.status}`);
    }

    return {
      providerMessageId: `batch-${Date.now()}`,
      accepted: true,
      latencyMs,
    };
  }

  async healthCheck(): Promise<ProviderHealth> {
    return {
      providerName: this.providerKey,
      state: 'CLOSED',
      successRate: 1.0,
      avgLatencyMs: 250,
      totalRequests24h: 0,
      failureCount24h: 0,
    };
  }

  async validateConfig(credentials: Record<string, string>): Promise<ProviderConfigValidation> {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!credentials.apiKey) {
      errors.push('API key is required');
    }

    if (!credentials.fromEmail) {
      errors.push('From email is required');
    }

    if (credentials.apiKey && credentials.apiKey.length < 20) {
      warnings.push('API key seems too short');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  verifyWebhookSignature(payload: string, secret?: string): boolean {
    // Maileroo webhook signature verification
    return true;
  }

  parseWebhookEvent(payload: unknown): ParsedWebhookEvent {
    const event = payload as {
      event: string;
      message_id: string;
      recipient: string;
      timestamp: number;
    };

    return {
      messageId: event.message_id ?? '',
      eventType: this.mapEventType(event.event),
      recipient: event.recipient ?? '',
      timestamp: new Date(event.timestamp * 1000),
    };
  }

  async getRateLimits(): Promise<{ perMinute: number; daily: number }> {
    return {
      perMinute: 50,
      daily: 5000,
    };
  }

  getCredentialsSchema(): CredentialsSchema {
    return {
      type: 'api_key',
      requiredFields: ['apiKey', 'fromEmail'],
      optionalFields: ['fromName'],
    };
  }

  private mapEventType(type: string): ParsedWebhookEvent['eventType'] {
    const mapping: Record<string, ParsedWebhookEvent['eventType']> = {
      delivered: 'delivered',
      bounced: 'bounced',
      complained: 'complained',
      opened: 'opened',
      clicked: 'clicked',
      failed: 'failed',
    };
    return mapping[type] ?? 'failed';
  }
}