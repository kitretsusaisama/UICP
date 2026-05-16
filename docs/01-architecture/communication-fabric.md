# Communication Fabric

## Metadata
```yaml
title: Communication Fabric
domain: integration
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: CRITICAL
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-first-design.md
  - smart-routing.md
related-docs:
  - communication-overview.md
  - provider-model_summary.md
related-queues:
  - email-delivery
  - sms-delivery
  - webhook-processing
related-services:
  - provider-router
  - communication-service
related-providers:
  - sendgrid
  - twilio
  - aws-ses
  - mailgun
```

---

## Overview

The communication fabric abstracts provider complexity while maintaining reliability. It provides a unified interface for sending messages across multiple channels (email, SMS, voice, webhooks) with smart provider routing.

---

## Architecture

### Provider Abstraction

```typescript
interface IProvider {
  // Common interface for all providers
  type: ProviderType; // email, sms, voice, webhook

  send(request: ProviderRequest): Promise<ProviderResponse>;
  sendBatch(requests: ProviderRequest[]): Promise<BatchResponse>;

  healthCheck(): Promise<ProviderHealth>;
  getCapabilities(): ProviderCapabilities;
}

interface ProviderRequest {
  to: string | string[];
  channel: Channel;
  content: MessageContent;
  metadata?: Record<string, unknown>;
}

interface ProviderResponse {
  success: boolean;
  messageId?: string;
  error?: ProviderError;
  provider: ProviderType;
  timestamp: Date;
}
```

### Supported Providers

| Channel | Providers | Priority Order |
|---------|-----------|----------------|
| Email | SendGrid, AWS SES, Mailgun | Cost → Reliability |
| SMS | Twilio, AWS SNS | Coverage → Cost |
| Voice | Twilio | Reliability only |
| Webhook | Custom endpoints | N/A |

---

## Provider Router

### Selection Logic

```typescript
class ProviderRouter {
  async selectProvider(
    channel: Channel,
    tenantId: TenantId,
    request: ProviderRequest
  ): Promise<IProvider> {
    // 1. Get tenant preferences
    const tenant = await this.tenantService.getTenant(tenantId);
    const preferences = tenant.settings.providerPreferences[channel];

    // 2. Get available providers for channel
    const providers = this.getProvidersForChannel(channel);

    // 3. Filter by tenant preferences
    const allowed = providers.filter(p =>
      preferences?.allowedProviders?.includes(p.type) ?? true
    );

    // 4. Sort by score (health * cost * performance)
    const scored = await Promise.all(
      allowed.map(async p => ({
        provider: p,
        score: await this.scoreProvider(p, channel, request),
      }))
    );

    // 5. Return highest scoring provider
    scored.sort((a, b) => b.score - a.score);
    return scored[0].provider;
  }

  async scoreProvider(
    provider: IProvider,
    channel: Channel,
    request: ProviderRequest
  ): Promise<number> {
    const health = await provider.healthCheck();
    const cost = await this.costService.estimate(provider, request);
    const performance = await this.metrics.getLatency(provider.type, channel);

    // Weighted score: 40% health, 30% cost, 30% performance
    return (health.score * 0.4) + (cost.score * 0.3) + (performance.score * 0.3);
  }
}
```

---

## Delivery Flow

### Email Delivery Flow

```
Request → API Gateway → Controller → Queue (email-delivery)
     ↓
Worker picks job → Provider Router → Select provider
     ↓
Provider adapter → External API (SendGrid/SES)
     ↓
Response → Update message status → Emit event
     ↓
Event Store records → Audit log → Metrics
```

### Retry and Fallback

```typescript
async function deliverWithFallback(
  request: ProviderRequest,
  channel: Channel
): Promise<ProviderResponse> {
  const providers = this.getProvidersForChannel(channel);

  for (const provider of providers) {
    try {
      const response = await provider.send(request);

      if (response.success) {
        return response;
      }

      // Try next provider on failure
      this.logger.warn(`Provider ${provider.type} failed, trying next`, response.error);
    } catch (error) {
      this.logger.error(`Provider ${provider.type} threw`, error);
      continue;
    }
  }

  // All providers failed
  throw new DeliveryException('All providers failed');
}
```

---

## Message Tracking

### Status Updates

```typescript
interface MessageStatus {
  messageId: string;
  tenantId: TenantId;
  channel: Channel;
  provider: ProviderType;

  // Timeline
  createdAt: Date;
  sentAt?: Date;
  deliveredAt?: Date;
  failedAt?: Date;

  // Details
  error?: string;
  providerMessageId?: string;
  metadata?: Record<string, unknown>;
}
```

### Webhook Callbacks

```typescript
// Provider sends callbacks for status updates
async function handleProviderWebhook(payload: ProviderWebhookPayload): Promise<void> {
  const message = await this.messageRepository.findByProviderMessageId(
    payload.providerMessageId
  );

  // Update status based on callback
  switch (payload.event) {
    case 'delivered':
      message.status = 'delivered';
      message.deliveredAt = new Date();
      break;
    case 'bounced':
      message.status = 'bounced';
      message.error = payload.error;
      break;
    case 'clicked':
      message.metadata.clicks = (message.metadata.clicks || 0) + 1;
      break;
  }

  await this.messageRepository.save(message);
}
```

---

## Cost Optimization

### Provider Selection by Cost

```typescript
async function getCostScore(provider: IProvider, request: ProviderRequest): Promise<number> {
  const rates = await this.costService.getRates(provider.type);

  switch (request.channel) {
    case 'email':
      // Cost per 1000 emails
      return 100 - (rates.perThousand * 10);
    case 'sms':
      // Cost per SMS
      return 100 - (rates.perMessage * 100);
    case 'voice':
      // Cost per minute
      return 100 - (rates.perMinute * 20);
  }
}
```

---

## Related Documents

- `queue-first-design.md`
- `smart-routing.md`
- `04-communication/communication-overview.md`
- `18-smart-tuning/provider-scoring.md`