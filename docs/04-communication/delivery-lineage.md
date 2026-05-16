# Delivery Lineage

## Metadata
```yaml
title: Delivery Lineage
domain: communication
owner: Platform Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: LOW
queue-impact: LOW
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - delivery-intelligence.md
  - webhook-reconciliation.md
related-docs:
  - communication-overview.md
  - communication-security.md
related-queues:
  - lineage-update
related-services:
  - DeliveryLineageService
  - EventStore
  - AuditLogger
related-providers:
  - SES
  - Resend
  - Maileroo
  - Msg91
related-runtime-states:
  - lineage_created
  - lineage_updated
  - lineage_completed
  - lineage_failed
related-threat-models:
  - Lineage data corruption
  - Audit log tampering
```

---

## Overview

Delivery Lineage tracks the complete lifecycle of every message from creation to final delivery status. This comprehensive audit trail enables troubleshooting, compliance reporting, and analytics.

---

## Lineage Events

### Event Types

| Event | Description | Source |
|-------|-------------|--------|
| CREATED | Message queued | Queue system |
| SENT | Sent to provider | Provider API |
| DELIVERED | Delivered to recipient | Webhook |
| BOUNCED | Delivery failed | Webhook |
| COMPLAINED | Marked as spam | Webhook |
| OPENED | Recipient opened | Tracking |
| CLICKED | Recipient clicked | Tracking |
| FAILED | Permanent failure | Retry logic |

### Event Schema

```typescript
interface LineageEvent {
  messageId: string;
  eventType: LineageEventType;
  timestamp: Date;
  source: 'provider' | 'queue' | 'internal';
  provider?: string;
  metadata: Record<string, any>;
  actor?: string;
  correlationId: string;
}
```

---

## Lineage Storage

### Data Model

```typescript
interface DeliveryLineage {
  messageId: string;
  tenantId: string;
  channel: 'email' | 'sms';
  createdAt: Date;
  completedAt?: Date;

  // Message details
  sender: string;
  recipients: string[];
  subject?: string;

  // Provider details
  provider: string;
  providerMessageId: string;

  // Current state
  currentStatus: DeliveryStatus;
  events: LineageEvent[];

  // Metadata
  metadata: Record<string, any>;
}
```

### Storage Architecture

```
┌────────────────────────────────────┐
│       Message Sent                 │
├────────────────────────────────────┤
│  Write lineage: CREATED           │
│  ↓                                 │
│  Read provider status              │
│  ↓                                 │
│  Webhook received                 │
│  ↓                                 │
│  Update lineage: DELIVERED        │
│  ↓                                 │
│  Archive to cold storage           │
└────────────────────────────────────┘
```

---

## Query Interface

### Query by Message ID

```typescript
async function getLineage(messageId: string): Promise<DeliveryLineage> {
  return await lineageStore.findOne({ messageId });
}
```

### Query by Tenant

```typescript
async function getTenantLineage(
  tenantId: string,
  options: QueryOptions
): Promise<LineageList> {
  return await lineageStore.find({
    tenantId,
    createdAt: {
      $gte: options.startDate,
      $lte: options.endDate
    },
    status: options.status
  }).limit(options.limit);
}
```

---

## Compliance and Audit

### Retention Policy

| Data Type | Retention | Storage |
|-----------|-----------|---------|
| Active lineage | 30 days | Hot storage |
| Recent lineage | 1 year | Warm storage |
| Historical | 7 years | Cold storage |
| Audit logs | 7 years | Immutable |

### Audit Requirements

- All events are append-only
- Cryptographic signatures for integrity
- Tamper-evident logging
- Export capabilities for compliance

---

## Analytics Integration

### Delivery Metrics

| Metric | Calculation |
|--------|-------------|
| Delivery rate | Delivered / Sent |
| Bounce rate | Bounced / Sent |
| Complaint rate | Complained / Sent |
| Open rate | Opened / Delivered |
| Click rate | Clicked / Opened |

### Time-to-Delivery

```typescript
function calculateTimeToDelivery(lineage: DeliveryLineage): number | null {
  const created = lineage.events.find(e => e.eventType === 'CREATED');
  const delivered = lineage.events.find(e => e.eventType === 'DELIVERED');

  if (!created || !delivered) return null;

  return delivered.timestamp.getTime() - created.timestamp.getTime();
}
```

---

## Tracing Integration

### OpenTelemetry Integration

```typescript
const tracer = trace.getTracer('communication');

async function recordLineageEvent(
  messageId: string,
  event: LineageEvent
): Promise<void> {
  const span = tracer.startSpan('lineage.record', {
    attributes: {
      'message.id': messageId,
      'event.type': event.eventType
    }
  });

  try {
    await lineageStore.insert(event);
    span.setAttribute('success', true);
  } catch (error) {
    span.setAttribute('success', false);
    throw error;
  } finally {
    span.end();
  }
}
```

---

## Related Documents

- `04-communication/delivery-intelligence.md`
- `04-communication/webhook-reconciliation.md`
- `04-communication/communication-security.md`