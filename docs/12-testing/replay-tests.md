# Replay Tests

## Metadata
```yaml
title: Replay Tests
domain: idempotency
owner: Platform Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: bi-weekly
last-reviewed: 2026-05-16
depends-on:
  - src/application/services/idempotency.service.ts
  - src/infrastructure/cache/redis-cache.adapter.ts
  - src/domain/repositories/idempotency.repository.interface.ts
related-docs:
  - docs/05-architecture/idempotency-design.md
  - docs/09-operations/replay-procedures.md
related-queues:
  - idempotency-keys
  - replay-requests
related-services:
  - IdempotencyService
  - IdempotencyRepository
  - TokenRepository
```

---

## Overview

Replay tests validate that the system correctly handles duplicate requests using idempotency keys. These tests ensure that retried requests do not result in duplicate operations, token reuse, or inconsistent state.

---

## Test Coverage

### Idempotency Key Validation

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| New request | POST /api/v1/providers with new idempotency-key | Request processed normally |
| Duplicate request | POST /api/v1/providers with existing key | Original response returned |
| Expired key | POST with key older than 24 hours | Request processed as new |
| Invalid key format | POST with malformed idempotency-key | 400 Bad Request |

### Token Reuse Prevention

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Single token use | Use token once successfully | Token marked as consumed |
| Token reuse attempt | Use same token again | 409 Conflict, original result returned |
| Concurrent token use | Two requests with same token | Only one succeeds, one receives cached response |

### Duplicate Request Rejection

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Exact duplicate | Send identical request twice | Second request returns cached result |
| Payload mismatch | Duplicate key but different payload | 422 Unprocessable Entity |
| Partial replay | Replay request after 1 second | Original result returned within 200ms |

### Cache Invalidation

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| TTL expiration | Key expires after 24 hours | New request creates new entry |
| Manual invalidation | Admin deletes idempotency key | Next request processed as new |
| Cache eviction | Redis evicts key under memory pressure | Next request processed as new |

---

## Test Implementation

```typescript
describe('Idempotency', () => {
  describe('Duplicate Request Handling', () => {
    it('should return cached response for duplicate request', async () => {
      const idempotencyKey = 'idem-123456';
      const request = { provider: 'aws', region: 'us-east-1' };

      const firstResponse = await request(app)
        .post('/api/v1/providers')
        .set('Idempotency-Key', idempotencyKey)
        .send(request);

      const secondResponse = await request(app)
        .post('/api/v1/providers')
        .set('Idempotency-Key', idempotencyKey)
        .send(request);

      expect(secondResponse.status).toBe(firstResponse.status);
      expect(secondResponse.body).toEqual(firstResponse.body);
    });

    it('should reject duplicate with different payload', async () => {
      const idempotencyKey = 'idem-789012';

      await request(app)
        .post('/api/v1/providers')
        .set('Idempotency-Key', idempotencyKey)
        .send({ provider: 'aws' });

      const response = await request(app)
        .post('/api/v1/providers')
        .set('Idempotency-Key', idempotencyKey)
        .send({ provider: 'gcp' });

      expect(response.status).toBe(422);
    });
  });

  describe('Token Reuse Prevention', () => {
    it('should prevent token reuse in concurrent requests', async () => {
      const token = 'token-concurrent-test';

      const [first, second] = await Promise.all([
        request(app).post('/api/v1/send').send({ token, amount: 100 }),
        request(app).post('/api/v1/send').send({ token, amount: 100 })
      ]);

      expect([first.status, second.status]).toContain(200);
      expect([first.status, second.status]).toContain(409);
    });
  });
});
```

---

## Validation Criteria

- 100% of duplicate requests return cached responses
- < 50ms latency for cached response retrieval
- Zero cases of duplicate token usage
- Idempotency keys retained for 24 hours minimum