# Queue Tests

## Metadata
```yaml
title: Queue Tests
domain: message-queue
owner: Platform Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: LOW
queue-impact: CRITICAL
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: weekly
last-reviewed: 2026-05-16
depends-on:
  - src/application/ports/driven/i-queue.port.ts
  - src/infrastructure/queue/sqs-queue.adapter.ts
  - src/application/services/message-processor.service.ts
related-docs:
  - docs/06-architecture/message-queue-architecture.md
  - docs/09-operations/queue-monitoring.md
related-queues:
  - message-processing
  - notification-queue
  - webhook-delivery
related-services:
  - QueueService
  - MessageProcessor
  - DeadLetterQueueHandler
```

---

## Overview

Queue tests validate the reliability and correctness of message processing, retry mechanisms, dead letter queue handling, and race condition prevention. These tests ensure the system can handle high-throughput message processing without data loss.

---

## Test Coverage

### Message Processing

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Valid message | Process single valid message | Message ACKed, output produced |
| Invalid payload | Process message with malformed JSON | Message rejected, logged to error queue |
| Large message | Process message exceeding 256KB | Message chunked or rejected with 413 |
| Priority ordering | Send high-priority message after low | High-priority processed first |

### Retry Behavior

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Transient failure | Message processing fails with 500 | Message retried up to 5 times |
| Permanent failure | Message processing fails with 400 after 3 retries | Message moved to DLQ |
| Exponential backoff | Simulate 3 consecutive failures | Retry at 1s, 5s, 25s intervals |
| Max retries exceeded | Message fails 5 times | Moved to dead letter queue |

### Dead Letter Queue (DLQ) Handling

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| DLQ message receipt | Process message from DLQ | Message processed with DLQ flag |
| DLQ max size | Add 10,000 messages to DLQ | DLQ throttles new entries |
| DLQ retention | Message in DLQ for 14 days | Message automatically purged |

### Race Condition Prevention

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Concurrent processing | 10 messages processed simultaneously | Each message processed exactly once |
| Duplicate detection | Send same message ID twice | Second message deduplicated |
| Partial failure | 5 of 10 messages fail mid-batch | 5 successful, 5 retried |

---

## Test Implementation

```typescript
describe('Queue Processing', () => {
  describe('Message Processing', () => {
    it('should process valid message successfully', async () => {
      const message = { id: 'msg-001', payload: validPayload };
      await queueService.send('message-processing', message);

      const processed = await messageProcessor.processNext();

      expect(processed.success).toBe(true);
      expect(processed.messageId).toBe('msg-001');
    });

    it('should move message to DLQ after max retries', async () => {
      jest.spyOn(processor, 'process').mockRejectedValue(new Error('Permanent'));

      await queueService.send('message-processing', failingMessage);

      await waitForRetries(5);

      const dlqMessage = await dlqService.receive();
      expect(dlqMessage).toBeDefined();
    });
  });

  describe('Retry Behavior', () => {
    it('should use exponential backoff between retries', async () => {
      const retryTimes: number[] = [];
      jest.spyOn(queueService, 'scheduleRetry').mockImplementation(
        (delay) => { retryTimes.push(delay); return Promise.resolve(); }
      );

      await queueService.send('message-processing', failingMessage);
      await waitForRetries(3);

      expect(retryTimes[0]).toBe(1000);
      expect(retryTimes[1]).toBe(5000);
      expect(retryTimes[2]).toBe(25000);
    });
  });
});
```

---

## Performance Targets

- Message processing latency: < 100ms p95
- Queue throughput: 10,000 messages/second
- Retry success rate: > 95%
- DLQ diversion rate: < 1% of total messages