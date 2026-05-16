# Delivery Lineage

## Metadata
```yaml
title: Delivery Lineage
domain: delivery-tracking
owner: Platform Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: LOW
queue-impact: MEDIUM
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - provider-api
  - delivery-webhook
  - status-poller
related-docs:
  - 13-delivery/delivery-tracking.md
  - 15-runtime-lineage/provider-lineage.md
  - 15-runtime-lineage/webhook-lineage.md
related-queues:
  - delivery-status
  - email-outbound
  - sms-outbound
related-services:
  - delivery-tracker
  - status-poller
  - webhook-handler
related-providers:
  - sendgrid
  - twilio
  - aws-sns
```

---

## Overview

Delivery lineage tracks message status from provider API submission through final delivery confirmation. This lineage enables SLA compliance verification, delivery failure diagnosis, and customer notification of message outcomes.

---

## Delivery Status Flow

### Initial Submission Lineage

```
Message Queued for Delivery
    ↓
Provider API Call (POST Request)
    ↓
Provider Acknowledgment Received
    ↓
Message ID Mapping (System ↔ Provider)
    ↓
Initial Status: QUEUED/SENT
    ↓
Delivery Tracking Enabled
    ↓
Completion Timeout Started
```

### Status Update Processing

```
Provider Webhook Received
    ↓
Delivery Event Parsing
    ↓
Message Correlation (Provider ID → System ID)
    ↓
Status Mapping (Provider Status → System Status)
    ↓
Delivery Record Update
    ↓
Customer Notification Trigger (if configured)
    ↓
Lineage Completion Flag Set
```

---

## Delivery Status Types

### Email Delivery States

| Status | Description | Lineage Complete |
|--------|-------------|------------------|
| QUEUED | Accepted by provider | No |
| SENT | Dispatched to recipient | No |
| DELIVERED | Received by mail server | Partial |
| OPENED | Recipient opened email | Yes |
| BOUNCED | Delivery failed | Yes |
| SPAM_REPORTED | Marked as spam | Yes |
| UNSUBSCRIBED | Opt-out recorded | Yes |

### SMS Delivery States

| Status | Description | Lineage Complete |
|--------|-------------|------------------|
| QUEUED | Accepted by carrier | No |
| SENT | Dispatched to device | Partial |
| DELIVERED | Received by device | Yes |
| FAILED | Delivery permanently failed | Yes |
| UNDELIVERABLE | Number invalid/unreachable | Yes |

---

## Trace Correlation

Each delivery event captures:
- **messageId**: System message identifier
- **providerMessageId**: Provider reference
- **status**: Current delivery state
- **timestamp**: Event occurrence time
- **provider**: Originating provider
- **recipient**: Target endpoint (anonymized for privacy)
- **failureReason**: Error classification (if failed)
- **attemptCount**: Delivery attempt number

---

## Status Polling Integration

For providers without webhooks:
1. Scheduled polling at configured intervals
2. Query provider API for message status
3. Update delivery record with latest state
4. Mark complete when terminal state reached
5. Close tracking after timeout threshold

---

## SLA Tracking

Delivery lineage enables SLA measurement:
- Time to provider acceptance (P1)
- Time to delivery confirmation (P2)
- Bounce rate by provider and message type
- Average delivery latency by region

---

## Failure Analysis

Delivery failures traced through:
1. Provider error code mapping
2. Failure categorization (technical/functional)
3. Retry eligibility determination
4. Customer impact notification
5. Support ticket correlation

---

## Related Documents

- `15-runtime-lineage/provider-lineage.md` - Provider interactions
- `15-runtime-lineage/webhook-lineage.md` - Webhook processing
- `15-runtime-lineage/queue-lineage.md` - Queue processing
- `13-delivery/delivery-tracking.md` - Delivery system design