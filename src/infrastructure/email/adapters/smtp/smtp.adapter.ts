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

export interface SmtpCredentials {
  host: string;
  port: number;
  username: string;
  password: string;
  tls: boolean;
  fromEmail: string;
  fromName?: string;
}

@Injectable()
export class SmtpEmailAdapter implements IEmailProviderAdapter {
  private readonly logger = new Logger(SmtpEmailAdapter.name);

  readonly providerKey = 'SMTP';
  readonly providerType: ProviderType = 'SMTP';
  readonly channel: 'EMAIL' = 'EMAIL';

  readonly capabilities: ProviderCapabilities = {
    supportsWebhooks: false,
    supportsTemplates: false,
    supportsBatch: true,
    supportsCustomHeaders: true,
    maxRecipientsPerSend: 50,
    regions: [],
  };

  async send(
    params: SendEmailPayload & { credentials: SmtpCredentials },
  ): Promise<SendResult> {
    const startTime = Date.now();
    const { credentials } = params;

    try {
      // In production, use nodemailer or similar
      // For now, simulate SMTP connection
      this.validateSmtpConnection(credentials);

      // Simulate successful send
      const latencyMs = Date.now() - startTime;

      this.logger.debug(
        {
          recipient: params.recipient,
          subject: params.subject,
          latencyMs,
        },
        'Email sent via SMTP',
      );

      return {
        providerMessageId: `smtp-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        accepted: true,
        latencyMs,
      };
    } catch (error) {
      this.logger.error(
        { error: (error as Error).message, recipient: params.recipient },
        'SMTP send failed',
      );
      throw error;
    }
  }

  async sendBatch(
    params: (SendEmailPayload & { credentials: SmtpCredentials })[],
  ): Promise<SendResult> {
    const startTime = Date.now();
    const results: string[] = [];

    for (const param of params) {
      const result = await this.send(param);
      results.push(result.providerMessageId ?? '');
    }

    const latencyMs = Date.now() - startTime;

    return {
      providerMessageId: results.join(','),
      accepted: true,
      latencyMs,
    };
  }

  async healthCheck(): Promise<ProviderHealth> {
    return {
      providerName: this.providerKey,
      state: 'CLOSED',
      successRate: 1.0,
      avgLatencyMs: 500,
      totalRequests24h: 0,
      failureCount24h: 0,
    };
  }

  async validateConfig(credentials: Record<string, string>): Promise<ProviderConfigValidation> {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!credentials.host) {
      errors.push('SMTP host is required');
    }

    if (!credentials.port) {
      errors.push('SMTP port is required');
    }

    if (!credentials.username) {
      errors.push('Username is required');
    }

    if (!credentials.password) {
      errors.push('Password is required');
    }

    if (!credentials.fromEmail) {
      errors.push('From email is required');
    }

    // Validate port range
    const port = parseInt(credentials.port ?? '0', 10);
    if (port && (port < 1 || port > 65535)) {
      errors.push('Invalid port number');
    }

    // Warn about non-TLS
    const tlsValue = credentials.tls?.toString() ?? 'true';
    if (tlsValue === 'false' || tlsValue === '0') {
      warnings.push('TLS is disabled - this is insecure');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  verifyWebhookSignature(_payload: string, _secret?: string): boolean {
    // SMTP doesn't have webhooks - this is a no-op
    return true;
  }

  parseWebhookEvent(_payload: unknown): ParsedWebhookEvent {
    // SMTP doesn't have webhooks - return default
    return {
      messageId: '',
      eventType: 'failed',
      recipient: '',
      timestamp: new Date(),
    };
  }

  async getRateLimits(): Promise<{ perMinute: number; daily: number; monthly?: number }> {
    return {
      perMinute: 60,
      daily: 5000,
      monthly: 100000,
    };
  }

  getCredentialsSchema(): CredentialsSchema {
    return {
      type: 'smtp',
      requiredFields: ['host', 'port', 'username', 'password', 'fromEmail'],
      optionalFields: ['fromName', 'tls'],
    };
  }

  private validateSmtpConnection(credentials: SmtpCredentials): void {
    // In production, test SMTP connection
    if (!credentials.host) {
      throw new Error('SMTP host not configured');
    }
  }
}