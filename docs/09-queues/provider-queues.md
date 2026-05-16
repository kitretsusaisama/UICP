# Provider Queues

## Metadata
```yaml
title: Provider Queues
domain: queues
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
  - queue-overview.md
  - queue-topology.md
  - retry-engine.md
  - worker-concurrency.md
related-docs:
  - 11-external-services/twilio-integration.md
  - 11-external-services/sendgrid-integration.md
  - 16-failure-models/provider-outages.md
related-queues:
  - sms-delivery
  - email-delivery
  - webhook-processing
related-services:
  - BullMQ
  - Redis cluster
  - Provider API clients
related-providers:
  - Twilio (SMS)
  - SendGrid (Email)
  - Webhook endpoints
related-runtime-states:
  - PROVIDER_CALL_PENDING
  - PROVIDER_CALL_IN_PROGRESS
  - PROVIDER_CALL_COMPLETED
  - PROVIDER_CALL_FAILED
  - PROVIDER_RATE_LIMITED
related-threat-models:
  - Provider API abuse
  - Rate limit exhaustion
  - Credential leakage
```

---

## Overview

Provider queues handle integration with external service providers like Twilio for SMS and SendGrid for email. These queues require special handling due to external dependencies, rate limits, and provider-specific behaviors.

---

## Provider Configuration

### Twilio (SMS)

```typescript
const twilioConfig = {
  accountSid: process.env.TWILIO_ACCOUNT_SID,
  authToken: process.env.TWILIO_AUTH_TOKEN,
  fromNumber: process.env.TWILIO_FROM_NUMBER,
  rateLimit: {
    requestsPerSecond: 100,
    maxBurst: 200
  },
  timeout: 10000, // 10 seconds
  retry: {
    maxAttempts: 5,
    backoff: 'exponential'
  }
};
```

### SendGrid (Email)

```typescript
const sendGridConfig = {
  apiKey: process.env.SENDGRID_API_KEY,
  fromEmail: 'noreply@uicp.com',
  fromName: 'UICP',
  rateLimit: {
    requestsPerSecond: 100,
    maxBurst: 150
  },
  timeout: 15000, // 15 seconds
  retry: {
    maxAttempts: 5,
    backoff: 'exponential'
  }
};
```

### Webhooks (Outbound)

```typescript
const webhookConfig = {
  timeout: 5000, // 5 seconds
  rateLimit: {
    requestsPerSecond: 50,
    maxBurst: 100
  },
  retry: {
    maxAttempts: 3,
    backoff: 'linear'
  },
  signature: {
    algorithm: 'HMAC-SHA256',
    header: 'X-UICP-Signature'
  }
};
```

---

## Queue Provider Mapping

| Queue | Provider | Integration Type |
|-------|----------|------------------|
| sms-delivery | Twilio | Direct API |
| email-delivery | SendGrid | Direct API |
| webhook-processing | Custom | HTTP callbacks |
| otp-fastlane | Twilio/SendGrid | Direct API |

---

## Provider-Specific Handling

### Twilio Message Status

```typescript
async function handleTwilioStatus(job: Job): Promise<void> {
  const messageSid = job.data.messageSid;

  // Check delivery status
  const status = await twilio.messages(messageSid).fetch();

  switch (status.status) {
    case 'delivered':
      await completeJob(job);
      break;
    case 'failed':
    case 'undelivered':
      await failJob(job, new ProviderError(status.errorCode));
      break;
    case 'queued':
    case 'sending':
      // Still processing, wait
      break;
  }
}
```

### SendGrid Event Handling

```typescript
async function handleSendGridEvent(event: SendGridEvent): Promise<void> {
  switch (event.event) {
    case 'delivered':
      await updateJobStatus(event.messageId, 'DELIVERED');
      break;
    case 'bounce':
      await handleBounce(event);
      break;
    case 'spam_report':
      await handleSpamReport(event);
      break;
    case 'unsubscribe':
      await handleUnsubscribe(event);
      break;
  }
}
```

---

## Circuit Breaker Integration

### Provider Circuit Breaker

```typescript
const twilioCircuitBreaker = new CircuitBreaker({
  timeout: 10000,
  errorThreshold: 50, // 50% errors
  resetTimeout: 30000, // 30 seconds
  volumeThreshold: 10 // Minimum 10 requests
});

twilioCircuitBreaker.on('open', () => {
  alert('Twilio circuit breaker OPEN');
  scaleDownSmsWorkers();
});

twilioCircuitBreaker.on('half-open', () => {
  log('Testing Twilio connectivity');
});
```

### Circuit States

| State | Behavior | Recovery |
|-------|----------|----------|
| Closed | Normal operation | Auto |
| Open | Fail fast, no API calls | Wait resetTimeout |
| Half-open | Test requests allowed | Manual or auto |

---

## Rate Limit Management

### Per-Provider Rate Limiting

```typescript
class ProviderRateLimiter {
  private tokens: number;
  private maxTokens: number;
  private refillRate: number; // tokens per second
  private lastRefill: number;

  constructor(maxTokens: number, refillRate: number) {
    this.maxTokens = maxTokens;
    this.tokens = maxTokens;
    this.refillRate = refillRate;
    this.lastRefill = Date.now();
  }

  async acquire(): Promise<void> {
    this.refill();

    if (this.tokens < 1) {
      const waitTime = (1 - this.tokens) / this.refillRate * 1000;
      await sleep(waitTime);
      this.refill();
    }

    this.tokens -= 1;
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.maxTokens, this.tokens + elapsed * this.refillRate);
    this.lastRefill = now;
  }
}
```

---

## Provider Health Monitoring

### Health Check Endpoints

| Provider | Endpoint | Expected Response |
|----------|-----------|-------------------|
| Twilio | `/api/health/twilio` | `{ status: 'ok', latency: 45ms }` |
| SendGrid | `/api/health/sendgrid` | `{ status: 'ok', latency: 120ms }` |
| Webhook | `/api/health/webhooks` | `{ status: 'ok', latency: 30ms }` |

### Monitoring Dashboard

| Metric | Twilio | SendGrid | Webhooks |
|--------|--------|----------|----------|
| Availability | 99.9% | 99.9% | 99.5% |
| p50 Latency | 50ms | 150ms | 30ms |
| p99 Latency | 500ms | 2000ms | 200ms |
| Error Rate | 0.1% | 0.5% | 1% |

---

## Failover Strategy

### Multi-Provider Fallback

```typescript
async function sendSmsWithFallback(phone: string, message: string): Promise<void> {
  // Try primary (Twilio)
  try {
    await twilio.send(phone, message);
    return;
  } catch (error) {
    if (isRetryable(error)) {
      // Try backup (AWS SNS)
      try {
        await awsSns.send(phone, message);
        return;
      } catch (backupError) {
        throw new ProviderError('All SMS providers failed');
      }
    }
    throw error;
  }
}
```

---

## Related Documents

- `09-queues/queue-overview.md`
- `09-queues/retry-engine.md`
- `11-external-services/twilio-integration.md`
- `11-external-services/sendgrid-integration.md`
- `16-failure-models/provider-outages.md`