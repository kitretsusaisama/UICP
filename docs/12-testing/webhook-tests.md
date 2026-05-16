# Webhook Tests

## Metadata
```yaml
title: Webhook Tests
domain: webhooks
owner: Platform Team
criticality: MEDIUM
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: HIGH
provider-impact: LOW
tenant-impact: HIGH
ai-ingestable: true
review-cycle: bi-weekly
last-reviewed: 2026-05-16
depends-on:
  - src/application/services/webhook.service.ts
  - src/infrastructure/webhook/webhook-dispatcher.ts
  - src/application/ports/driven/i-webhook-retry.port.ts
related-docs:
  - docs/07-security/webhook-security.md
  - docs/06-architecture/webhook-design.md
related-queues:
  - webhook-delivery
  - webhook-retry
related-services:
  - WebhookService
  - WebhookDispatcher
  - WebhookRetryHandler
```

---

## Overview

Webhook tests validate that the system correctly delivers webhook events to registered endpoints. These tests cover delivery reliability, retry mechanisms, security signing, and event ordering.

---

## Test Coverage

### Delivery Reliability

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Successful delivery | POST to valid endpoint | 200 OK, event delivered |
| Retry on failure | Endpoint returns 500 | Event retried up to 5 times |
| Non-retryable error | Endpoint returns 404 | Event moved to DLQ after 1 attempt |
| Timeout handling | Endpoint doesn't respond in 30s | Retry triggered |

### Retry Mechanisms

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Exponential backoff | 3 consecutive failures | Retries at 1m, 5m, 25m |
| Maximum retries | 5 failed deliveries | Event moved to dead letter queue |
| Retry queue ordering | Multiple events for same endpoint | Delivered in order |
| Manual retry | Admin triggers retry | Event reprocessed |

### Security

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Valid signature | Request with correct HMAC | Event processed |
| Invalid signature | Tampered payload | 401 Unauthorized |
| Missing signature | No X-Signature header | 401 Unauthorized |
| Rotation support | Use new signing key | Event processed |

### Event Handling

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Provider created event | Provider created | webhook.delivery.created sent |
| Provider updated event | Provider updated | webhook.delivery.updated sent |
| Batch delivery | Create 100 providers | 100 events delivered |
| Duplicate prevention | Same event sent twice | Second event deduplicated |

---

## Test Implementation

```typescript
describe('Webhooks', () => {
  describe('Delivery', () => {
    it('should deliver webhook successfully', async () => {
      const endpoint = await createTestEndpoint();

      await webhookService.trigger('provider.created', {
        providerId: 'prov-123',
        name: 'test-provider'
      });

      const delivery = await waitForDelivery(endpoint, 'provider.created');
      expect(delivery.status).toBe(200);
    });

    it('should retry on server error', async () => {
      const flakyEndpoint = await createFlakyEndpoint();

      await webhookService.trigger('provider.created', testData);

      const attempts = await retryHandler.getAttempts(testEventId);
      expect(attempts.length).toBe(5);
      expect(attempts[4].status).toBe(200); // Eventually succeeds
    });
  });

  describe('Security', () => {
    it('should reject invalid signature', async () => {
      const response = await request(webhookReceiver)
        .post('/webhook')
        .set('X-Signature', 'invalid-signature')
        .send(testEvent);

      expect(response.status).toBe(401);
    });

    it('should accept valid HMAC signature', async () => {
      const signature = generateSignature(testEvent, secretKey);

      const response = await request(webhookReceiver)
        .post('/webhook')
        .set('X-Signature', signature)
        .send(testEvent);

      expect(response.status).toBe(200);
    });
  });

  describe('Retry Behavior', () => {
    it('should use exponential backoff', async () => {
      const retrySchedule = [];

      for (let i = 0; i < 5; i++) {
        await webhookService.trigger('provider.created', failingData);
        await waitForRetry(i + 1);
      }

      const schedule = await retryScheduler.getSchedule(eventId);
      expect(schedule.delays).toEqual([60, 300, 1500, 3600, 7200]);
    });
  });
});
```

---

## Performance Targets

- Delivery latency: < 500ms p95
- Retry success rate: > 90%
- Maximum delivery time: 24 hours
- Webhook queue throughput: 1,000/second

---

## Event Types

| Event | Payload | Retry Strategy |
|-------|----------|-----------------|
| provider.created | provider object | Exponential backoff |
| provider.updated | provider, changes | Exponential backoff |
| provider.deleted | provider_id | Exponential backoff |
| delivery.completed | delivery object | Fixed interval |
| delivery.failed | delivery, error | Aggressive retry |