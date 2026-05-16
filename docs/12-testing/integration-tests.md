# Integration Tests

## Metadata
```yaml
title: Integration Tests
domain: integration
owner: Platform Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: per-release
last-reviewed: 2026-05-16
depends-on:
  - src/app.module.ts
  - src/infrastructure/db/mysql/database.module.ts
  - src/infrastructure/queue/sqs-queue.adapter.ts
related-docs:
  - docs/02-architecture/system-overview.md
  - docs/06-architecture/integration-patterns.md
related-queues:
  - integration-test-queue
  - end-to-end-flow
related-services:
  - DatabaseModule
  - QueueModule
  - AuthModule
```

---

## Overview

Integration tests validate that multiple components work together correctly. These tests verify end-to-end flows, data consistency across services, and proper error propagation.

---

## Test Coverage

### Database Integration

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| User creation | Create user via service layer | User persisted to MySQL |
| Transaction rollback | Simulate failure mid-transaction | No partial data committed |
| Migration execution | Run pending migrations | Schema updated successfully |
| Connection pooling | Execute 100 concurrent queries | All queries complete successfully |

### Queue Integration

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Message publish | Publish to SQS queue | Message visible in queue |
| Message consumption | Process queue message | Message deleted, result stored |
| DLQ routing | Process failed message | Message moved to dead letter queue |
| Ordering guarantee | Publish 100 ordered messages | Messages processed in order |

### Auth Integration

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Login flow | User logs in with credentials | JWT issued, session stored |
| Token validation | Request with valid token | User context available in handler |
| Session invalidation | User logs out | Session removed, token blacklisted |

### Multi-Service Integration

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Provider provisioning | Create provider end-to-end | DB record, queue message, API key generated |
| Webhook delivery | Trigger webhook | HTTP POST sent, retry on failure |
| Cross-region replication | Write to primary region | Replica syncs within 5 seconds |

---

## Test Implementation

```typescript
describe('Integration Tests', () => {
  describe('Provider Provisioning Flow', () => {
    it('should create provider end-to-end', async () => {
      const providerData = {
        name: 'test-aws',
        type: 'aws',
        region: 'us-east-1',
        credentials: encryptedCredentials
      };

      const created = await providerService.create(providerData);

      expect(created.id).toBeDefined();
      expect(created.apiKey).toBeDefined();

      const fromDb = await providerRepository.findById(created.id);
      expect(fromDb.name).toBe('test-aws');

      const queueMessage = await queueService.receive('provider-creation');
      expect(queueMessage.providerId).toBe(created.id);
    });

    it('should rollback on failure', async () => {
      jest.spyOn(db, 'commit').mockRejectedValue(new Error('Connection lost'));

      await expect(providerService.create(invalidProvider))
        .rejects.toThrow();

      const count = await providerRepository.count();
      expect(count).toBe(0);
    });
  });

  describe('Cross-Region Replication', () => {
    it('should replicate data within SLA', async () => {
      await primaryDb.write('users', testUser);

      await waitFor(5000);

      const replica = await secondaryDb.read('users', testUser.id);
      expect(replica).toEqual(testUser);
    });
  });
});
```

---

## Test Environment

- Real MySQL database (test container)
- Real SQS queue (local stack)
- Mock external providers
- Isolated tenant data

---

## Performance Targets

- Integration test suite: < 15 minutes
- Average test duration: < 500ms
- Parallel test execution: 10 concurrent
- Flakiness rate: < 1%