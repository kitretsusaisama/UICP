# Queue Lineage

## Metadata
```yaml
title: Queue Lineage
domain: messaging
owner: Infrastructure Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: CRITICAL
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - queue-service
  - message-broker
  - worker-pool
related-docs:
  - 12-messaging/queue-architecture.md
  - 15-runtime-lineage/retry-lineage.md
related-queues:
  - email-outbound
  - sms-outbound
  - webhook-delivery
  - provider-routing
related-services:
  - queue-processor
  - worker-service
  - message-broker
related-providers:
  - twilio
  - sendgrid
  - aws-sns
```

---

## Overview

Queue lineage tracks every message from submission through processing completion. This enables message replay during outages, latency analysis, and delivery confirmation across provider boundaries.

---

## Queue Processing Flow

### Message Submission Lineage

```
API Request Received
    ↓
Message Validation (Schema Check)
    ↓
Tenant Context Extraction
    ↓
Priority Determination (Normal/High/Low)
    ↓
Queue Selection (By Provider Type)
    ↓
Message Enqueue (with metadata)
    ↓
Acknowledgment Return to Client
```

### Message Processing Lineage

```
Worker Poll (Batch Fetch)
    ↓
Message Dequeue
    ↓
Processing Start Timestamp
    ↓
Provider Routing Decision
    ↓
Provider API Call
    ↓
Provider Response Processing
    ↓
Success/Failure Determination
    ↓
Message Acknowledgment
    ↓
Completion Log
```

---

## Message Correlation

Each queued message captures:
- **messageId**: Unique ULID for deduplication
- **traceId**: Parent request correlation
- **tenantId**: Tenant isolation context
- **correlationId**: Business process linking
- **priority**: Processing urgency level
- **attemptCount**: Retry attempt number
- **enqueueTime**: Original submission timestamp

---

## Queue Types and Lineage

### Outbound Communication Queues

The system maintains distinct queues for each communication channel:

**Email Queue (email-outbound)**
- Template resolution
- Recipient validation
- SendGrid/SMTP routing
- Delivery status polling

**SMS Queue (sms-outbound)**
- Phone number formatting
- Carrier determination
- Twilio/Vonage routing
- Delivery receipt processing

**Webhook Queue (webhook-delivery)**
- Endpoint validation
- Retry configuration
- HTTP delivery attempts
- Response correlation

---

## Tracing and Debugging

Queue lineage supports debugging through:

1. **Message Stuck Detection**: Identify messages queued beyond expected processing time
2. **Duplicate Analysis**: Detect message redelivery patterns
3. **Latency Attribution**: Isolate queue wait time from processing time
4. **Provider Bottleneck Detection**: Identify queue buildup before provider failures

---

## Failure Recovery

When processing failures occur:
1. Messages remain in queue until acknowledgment
2. Failed messages move to dead-letter queue after max retries
3. Dead-letter messages preserve full lineage for manual inspection
4. Replay capability allows queue restart from failure point

---

## Related Documents

- `15-runtime-lineage/retry-lineage.md` - Retry mechanism details
- `15-runtime-lineage/provider-lineage.md` - Provider routing
- `12-messaging/queue-architecture.md` - Queue system design