/**
 * Driven Port - Email Provider Interface (Legacy compatible)
 */

import { OtpPurpose } from './i-otp.port';

// Re-export from new adapter port
export type ProviderType = 'RESEND' | 'MAILEROO' | 'AWS_SES' | 'SENDGRID' | 'POSTMARK' | 'MAILGUN' | 'SMTP' | 'CUSTOM';

export interface ProviderCapabilities {
  supportsWebhooks: boolean;
  supportsTemplates: boolean;
  supportsBatch: boolean;
  supportsCustomHeaders: boolean;
  maxRecipientsPerSend: number;
  regions: string[];
}

export interface SendEmailPayload {
  tenantId: string;
  lineageId: string;
  idempotencyKey: string;
  recipient: string;
  recipients?: string[];
  subject: string;
  text: string;
  html: string;
  fromEmail: string;
  fromName?: string;
  replyTo?: string;
  cc?: string[];
  bcc?: string[];
  attachments?: Attachment[];
  customHeaders?: Record<string, string>;
  purpose: string;
  traceId: string;
  metadata?: Record<string, string>;
}

export interface Attachment {
  filename: string;
  content: string;
  contentType?: string;
  disposition?: string;
}

export interface SendResult {
  providerMessageId?: string;
  accepted: boolean;
  rejected?: string[];
  latencyMs: number;
}

export interface ProviderHealth {
  providerName: string;
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  successRate: number;
  avgLatencyMs: number;
  totalRequests24h: number;
  failureCount24h: number;
}

export interface ProviderConfigValidation {
  valid: boolean;
  errors: string[];
  warnings?: string[];
}

export interface ParsedWebhookEvent {
  messageId: string;
  eventType: 'delivered' | 'bounced' | 'complained' | 'opened' | 'clicked' | 'failed';
  recipient: string;
  timestamp: Date;
  metadata?: Record<string, unknown>;
}

export interface CredentialsSchema {
  type: 'api_key' | 'aws_credentials' | 'smtp';
  requiredFields: string[];
  optionalFields?: string[];
}

export interface IEmailProviderAdapter {
  readonly providerKey: string;
  readonly providerType: ProviderType;
  readonly capabilities: ProviderCapabilities;
  readonly channel: 'EMAIL';

  send(params: SendEmailPayload): Promise<SendResult>;
  sendBatch(params: SendEmailPayload[]): Promise<SendResult>;

  healthCheck(): Promise<ProviderHealth>;
  validateConfig(credentials: Record<string, string>): Promise<ProviderConfigValidation>;

  verifyWebhookSignature(payload: string, secret?: string): boolean;
  parseWebhookEvent(payload: unknown): ParsedWebhookEvent;

  getRateLimits(): Promise<{ perMinute: number; daily: number; monthly?: number }>;
  getCredentialsSchema(): CredentialsSchema;
}

// Legacy interface for existing code
export interface EmailDispatchParams {
  recipient: string;
  subject: string;
  text: string;
  html: string;
  purpose: OtpPurpose;
  tenantName?: string;
}

export interface IEmailProvider {
  readonly providerKey: string;
  readonly channel: 'EMAIL';
  isEnabled(): boolean;
  send(params: EmailDispatchParams): Promise<{ providerMessageId?: string }>;
}