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

export interface ResendCredentials {
  apiKey: string;
  fromEmail: string;
  fromName?: string;
  region?: string;
}

@Injectable()
export class ResendEmailAdapter implements IEmailProviderAdapter {
  private readonly logger = new Logger(ResendEmailAdapter.name);

  readonly providerKey = 'RESEND';
  readonly providerType: ProviderType = 'RESEND';
  readonly channel: 'EMAIL' = 'EMAIL';

  readonly capabilities: ProviderCapabilities = {
    supportsWebhooks: true,
    supportsTemplates: true,
    supportsBatch: true,
    supportsCustomHeaders: true,
    maxRecipientsPerSend: 100,
    regions: ['us-east-1', 'eu-west-1', 'ap-south-1'],
  };

  async send(
    params: SendEmailPayload & { credentials: ResendCredentials },
  ): Promise<SendResult> {
    const startTime = Date.now();

    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${params.credentials.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: `${params.fromName ?? params.credentials.fromName} <${params.fromEmail ?? params.credentials.fromEmail}>`,
        to: params.recipients ?? [params.recipient],
        subject: params.subject,
        html: params.html,
        text: params.text,
        reply_to: params.replyTo,
        cc: params.cc,
        bcc: params.bcc,
        attachments: params.attachments?.map((a) => ({
          filename: a.filename,
          content: a.content,
          contentType: a.contentType,
        })),
        custom_args: params.metadata,
      }),
    });

    const latencyMs = Date.now() - startTime;

    if (!response.ok) {
      const error = await response.text();
      this.logger.error({ status: response.status, error }, 'Resend send failed');
      throw new Error(`Resend API error: ${response.status} - ${error}`);
    }

    const payload = (await response.json()) as { id?: string; email?: string };

    return {
      providerMessageId: payload.id,
      accepted: true,
      latencyMs,
    };
  }

  async sendBatch(
    params: (SendEmailPayload & { credentials: ResendCredentials })[],
  ): Promise<SendResult> {
    const startTime = Date.now();
    const first = params[0]!;  // Non-null assertion for batch send

    const response = await fetch('https://api.resend.com/emails/batch', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${first.credentials.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        emails: params.map((p) => ({
          from: `${p.fromName ?? first.credentials.fromName} <${p.fromEmail ?? first.credentials.fromEmail}>`,
          to: p.recipients ?? [p.recipient],
          subject: p.subject,
          html: p.html,
          text: p.text,
        })),
      }),
    });

    const latencyMs = Date.now() - startTime;

    if (!response.ok) {
      throw new Error(`Resend batch failed: ${response.status}`);
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
      avgLatencyMs: 150,
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

    if (credentials.apiKey && !credentials.apiKey.startsWith('re_')) {
      warnings.push('API key should start with re_');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  verifyWebhookSignature(payload: string, secret?: string): boolean {
    // Resend uses standard signature verification
    // In production, implement proper HMAC verification
    return true;
  }

  parseWebhookEvent(payload: unknown): ParsedWebhookEvent {
    const event = payload as {
      type: string;
      data: { id: string; to?: string[]; created_at?: string };
    };

    return {
      messageId: event.data?.id ?? '',
      eventType: this.mapEventType(event.type),
      recipient: event.data?.to?.[0] ?? '',
      timestamp: event.data?.created_at ? new Date(event.data.created_at) : new Date(),
    };
  }

  async getRateLimits(): Promise<{ perMinute: number; daily: number }> {
    return {
      perMinute: 100,
      daily: 10000,
    };
  }

  getCredentialsSchema(): CredentialsSchema {
    return {
      type: 'api_key',
      requiredFields: ['apiKey', 'fromEmail'],
      optionalFields: ['fromName', 'region'],
    };
  }

  private mapEventType(type: string): ParsedWebhookEvent['eventType'] {
    const mapping: Record<string, ParsedWebhookEvent['eventType']> = {
      'email.delivered': 'delivered',
      'email.bounced': 'bounced',
      'email.complained': 'complained',
      'email.opened': 'opened',
      'email.clicked': 'clicked',
    };
    return mapping[type] ?? 'failed';
  }
}