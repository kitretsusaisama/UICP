# Webhook Lineage

## Metadata
```yaml
title: Webhook Lineage
domain: event-processing
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - webhook-handler
  - signature-verification
  - event-repository
related-docs:
  - 14-webhooks/webhook-security.md
  - 15-runtime-lineage/delivery-lineage.md
  - 15-runtime-lineage/auth-lineage.md
related-queues:
  - webhook-processing
  - delivery-status
related-services:
  - webhook-receiver
  - signature-validator
  - event-processor
related-providers:
  - sendgrid
  - twilio
  - aws-sns
```

---

## Overview

Webhook lineage tracks incoming webhook events from provider delivery through processing completion. This lineage enables security verification, event correlation, and delivery confirmation for system-integrated communication channels.

---

## Webhook Processing Flow

### Receipt and Validation Lineage

```
Webhook HTTP POST Received
    ↓
Request Header Extraction (Signature/Timestamp)
    ↓
Tenant Identification (URL Path/Header)
    ↓
Signature Verification (HMAC Check)
    ↓
Payload Validation (Schema)
    ↓
Duplicate Detection (Message ID Cache)
    ↓
Event Type Determination
    ↓
Processing Queue Enqueue
```

### Event Processing Lineage

```
Event Dequeued from Processing Queue
    ↓
Event Type Routing (Bounce/Delivery/Click/Open)
    ↓
Payload Parsing and Normalization
    ↓
Message Correlation (Provider ID → System ID)
    ↓
Delivery Record Update
    ↓
Customer Webhook Delivery (if configured)
    ↓
Processing Completion Log
```

---

## Security Verification Lineage

### Signature Validation Flow

```
Webhook Signature Header Present
    ↓
Extract Timestamp and Signature
    ↓
Check Timestamp Freshness (5-minute window)
    ↓
Construct Payload String (canonical form)
    ↓
Retrieve Provider Secret (KMS)
    ↓
Compute HMAC-SHA256
    ↓
Constant-time Comparison
    ↓
Verification Result (Pass/Fail)
```

### Security Event Handling

```
Signature Verification Failed
    ↓
Reject Webhook Request
    ↓
Log Security Event (with details)
    ↓
Alert Security Team
    ↓
Increment Failure Counter
    ↓
Potential IP Block Decision
```

---

## Trace Correlation

Each webhook event captures:
- **webhookId**: Unique event identifier
- **traceId**: Original message trace
- **tenantId**: Tenant context
- **provider**: Originating provider
- **eventType**: Webhook event type
- **signatureValid**: Verification result
- **processingTime**: Total handling duration
- **customerDelivered**: User webhook status

---

## Duplicate Detection

Webhook processing includes deduplication:
1. Cache stores recent webhook IDs (24-hour TTL)
2. Duplicate requests ignored without reprocessing
3. Duplicate count logged for abuse detection
4. Idempotency ensured for retry scenarios

---

## Customer Webhook Delivery

After processing, customer webhooks triggered:
1. Customer webhook URL lookup (per-tenant configuration)
2. Payload construction with event data
3. HTTPS POST with signature header
4. Retry on failure (up to 3 attempts)
5. Delivery confirmation logged

---

## Incident Reconstruction

Webhook lineage enables:
1. Complete event timeline from provider to customer
2. Security incident root cause (signature failures)
3. Delivery confirmation evidence
4. Customer notification verification

---

## Related Documents

- `15-runtime-lineage/delivery-lineage.md` - Delivery tracking
- `15-runtime-lineage/auth-lineage.md` - Authentication context
- `14-webhooks/webhook-security.md` - Security configuration
- `15-runtime-lineage/queue-lineage.md` - Queue processing