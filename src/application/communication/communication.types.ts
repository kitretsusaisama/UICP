export type CommunicationChannel = 'SMS' | 'EMAIL' | 'WHATSAPP' | 'VOICE';

export type CommunicationPurpose =
  | 'LOGIN_OTP'
  | 'SIGNUP_OTP'
  | 'MFA'
  | 'PASSWORD_RESET'
  | 'VERIFY_EMAIL'
  | 'TENANT_INVITE'
  | 'SECURITY_ALERT';

export interface ProviderExecutionConfig {
  providerName: string;
  providerType: string;
  credentialsRef?: string;
  senderId?: string;
  fromEmail?: string;
  fromName?: string;
  region?: string;
  priority: number;
  circuitState: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
}

export interface ResolvedTemplate {
  templateKey: string;
  providerTemplateId?: string;
  subject?: string;
  text?: string;
  html?: string;
  sms?: string;
  locale: string;
  version: number;
}

export interface ResolvedSender {
  senderId?: string;
  fromEmail?: string;
  fromName?: string;
  replyTo?: string;
  domain?: string;
}

export interface TenantBranding {
  displayName: string;
  logoUrl?: string;
  primaryColor?: string;
}

export interface RuntimePolicy {
  resendCooldownSeconds: number;
  maxRetries: number;
  retryChannels: CommunicationChannel[];
  rateLimitPerMinute: number;
  dailyLimit: number;
}

export interface ProviderResolution {
  tenantId: string;
  channel: CommunicationChannel;
  purpose: CommunicationPurpose;
  primary: ProviderExecutionConfig;
  fallbacks: ProviderExecutionConfig[];
  template: ResolvedTemplate;
  sender: ResolvedSender;
  branding: TenantBranding;
  policy: RuntimePolicy;
  lineageId: string;
}

export interface ProviderSendPayload {
  tenantId: string;
  lineageId: string;
  idempotencyKey: string;
  channel: CommunicationChannel;
  purpose: CommunicationPurpose;
  recipient: string;
  subject?: string;
  text?: string;
  html?: string;
  code?: string;
  provider: ProviderExecutionConfig;
}

export interface ProviderSendResult {
  providerMessageId?: string;
  accepted: boolean;
}

export interface ProviderHealthResult {
  providerName: string;
  circuitState: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  successRate: number;
  failureRate: number;
  p95LatencyMs: number;
}

export interface ProviderConfigValidation {
  valid: boolean;
  errors: string[];
}

export interface ProviderWebhookEvent {
  tenantId?: string;
  providerName: string;
  eventId: string;
  eventType: string;
  messageId?: string;
  lineageId?: string;
  payload: unknown;
}

export interface CommunicationProvider {
  send(payload: ProviderSendPayload): Promise<ProviderSendResult>;
  healthCheck(config: ProviderExecutionConfig): Promise<ProviderHealthResult>;
  validateConfig(config: ProviderExecutionConfig): Promise<ProviderConfigValidation>;
  mapWebhook(payload: unknown, headers: Record<string, string>): ProviderWebhookEvent;
}

export interface CommunicationJobPayload {
  tenantId: string;
  lineageId: string;
  idempotencyKey: string;
  providerName: string;
  channel: CommunicationChannel;
  purpose: CommunicationPurpose;
  recipient: string;
  attempt: number;
  maxAttempts: number;
  createdAt: string;
  traceId: string;
  subject?: string;
  text?: string;
  html?: string;
  code?: string;
}
