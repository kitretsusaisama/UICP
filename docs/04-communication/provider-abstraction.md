# Provider Abstraction

## Metadata
```yaml
title: Provider Abstraction
domain: communication
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: MEDIUM
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - provider-runtime.md
  - communication-overview.md
related-docs:
  - provider-selection.md
  - fallback-policies.md
  - provider-health.md
related-queues:
  - email-delivery
  - sms-delivery
related-services:
  - ProviderRouter
  - ProviderAdapter
  - MessageSerializer
related-providers:
  - SES
  - Resend
  - Maileroo
  - Msg91
related-runtime-states:
  - adapter_initializing
  - adapter_ready
  - adapter_error
  - routing_in_progress
related-threat-models:
  - Provider API drift
  - Abstraction leak
```

---

## Overview

Provider Abstraction creates a unified interface for all email and SMS providers, enabling seamless provider switching, feature parity, and consistent error handling regardless of the underlying provider.

---

## Interface Design

### Core Interface

```typescript
interface ICommunicationProvider {
  // Channel type
  readonly channel: 'email' | 'sms';
  readonly providerId: string;

  // Send operations
  send(message: OutboundMessage): Promise<SendResult>;

  // Batch operations
  sendBatch(messages: OutboundMessage[]): Promise<BatchResult>;

  // Health and status
  getHealth(): Promise<ProviderHealth>;

  // Credential management
  validateCredentials(): Promise<boolean>;
  rotateCredentials(newCredentials: Credentials): Promise<void>;

  // Feature detection
  supportsFeature(feature: ProviderFeature): boolean;
}
```

### Email Provider Interface

```typescript
interface IEmailProvider extends ICommunicationProvider {
  sendEmail(params: EmailParams): Promise<EmailResult>;

  sendTemplateEmail(params: TemplateEmailParams): Promise<EmailResult>;

  getDeliveryStatus(messageId: string): Promise<DeliveryStatus>;
}
```

### SMS Provider Interface

```typescript
interface ISMSProvider extends ICommunicationProvider {
  sendSMS(to: string, message: string): Promise<SMSResult>;

  sendOTP(phoneNumber: string): Promise<OTPResult>;

  verifyOTP(phoneNumber: string, otp: string): Promise<boolean>;
}
```

---

## Feature Parity

### Email Features

| Feature | SES | Resend | Maileroo |
|---------|-----|--------|----------|
| HTML email | Yes | Yes | Yes |
| Plain text | Yes | Yes | Yes |
| Attachments | Yes | Yes | Yes |
| Templates | Yes | Yes | Partial |
| Custom headers | Yes | Yes | No |
| Tracking | Yes | Yes | Partial |
| Webhooks | Yes | Yes | Yes |
| Dedicated IPs | Yes | Yes | No |

### SMS Features

| Feature | Msg91 |
|---------|-------|
| OTP | Yes |
| Unicode | Yes |
| Binary | Yes |
| Scheduling | Yes |
| DLT | Yes |

---

## Error Normalization

### Unified Error Types

```typescript
type ProviderError =
  | AuthenticationError
  | RateLimitError
  | ValidationError
  | NetworkError
  | ProviderUnavailableError
  | MessageRejectedError;

interface ErrorResponse {
  code: string;
  message: string;
  provider: string;
  retryable: boolean;
  retryAfter?: number;
}
```

### Error Mapping

| Provider Error | Unified Error | Retryable |
|----------------|---------------|-----------|
| SignatureDoesNotMatch | AuthenticationError | No |
| ThrottlingException | RateLimitError | Yes |
| MessageRejected | MessageRejectedError | No |
| InternalError | ProviderUnavailableError | Yes |
| Network timeout | NetworkError | Yes |

---

## Adapter Implementation

### Base Adapter

```typescript
abstract class BaseProviderAdapter implements ICommunicationProvider {
  abstract readonly channel: 'email' | 'sms';
  abstract readonly providerId: string;

  protected abstract doSend(message: OutboundMessage): Promise<ProviderResponse>;
  protected abstract doGetHealth(): Promise<ProviderHealth>;

  async send(message: OutboundMessage): Promise<SendResult> {
    const response = await this.doSend(message);
    return this.normalizeResponse(response);
  }

  async getHealth(): Promise<ProviderHealth> {
    try {
      return await this.doGetHealth();
    } catch (error) {
      return { healthy: false, error: error.message };
    }
  }
}
```

---

## Configuration Management

### Provider Registry

```typescript
interface ProviderRegistry {
  register(adapter: ICommunicationProvider): void;
  unregister(providerId: string): void;
  get(providerId: string): ICommunicationProvider;
  getAll(channel?: 'email' | 'sms'): ICommunicationProvider[];
  getActive(): ICommunicationProvider[];
}
```

### Runtime Configuration

```typescript
interface ProviderRuntimeConfig {
  enabled: boolean;
  priority: number;
  maxRetries: number;
  timeout: number;
  rateLimit: {
    maxPerSecond: number;
    maxPerMinute: number;
  };
}
```

---

## Related Documents

- `04-communication/provider-runtime.md`
- `04-communication/provider-selection.md`
- `04-communication/fallback-policies.md`