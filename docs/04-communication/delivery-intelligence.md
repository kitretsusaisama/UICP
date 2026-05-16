# Delivery Intelligence

## Metadata
```yaml
title: Delivery Intelligence
domain: communication
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: MEDIUM
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - provider-runtime.md
  - webhook-reconciliation.md
related-docs:
  - communication-overview.md
  - provider-selection.md
  - delivery-lineage.md
related-queues:
  - delivery-analytics
related-services:
  - CommunicationService
  - ProviderRouter
  - DeliveryTracker
related-providers:
  - SES
  - Resend
  - Maileroo
  - Msg91
related-runtime-states:
  - provider_healthy
  - provider_degraded
  - provider_failed
  - delivery_pending
  - delivery_confirmed
  - delivery_failed
related-threat-models:
  - Provider data leakage
  - Delivery tracking evasion
```

---

## Overview

Delivery Intelligence provides real-time visibility into message delivery states across all providers. The system aggregates provider responses, webhook events, and queue metrics to construct a comprehensive delivery lineage for each message.

---

## Core Components

### Delivery Tracker

The DeliveryTracker maintains the state machine for each message:

```
States: PENDING → SENT → DELIVERED | BOUNCED | FAILED | SPAM
```

State transitions are recorded with timestamps, provider references, and metadata.

### Intelligence Aggregation

The system aggregates metrics from multiple sources:

| Source | Data Type | Update Frequency |
|--------|-----------|------------------|
| Provider API | Send confirmation | Real-time |
| Webhooks | Delivery events | On event |
| Queue metrics | Processing status | 1 min |
| Bounce receipts | Hard/soft bounce | On receipt |

---

## Key Metrics

### Provider Health Scores

```typescript
interface ProviderHealth {
  providerId: string;
  score: number;          // 0-100
  deliveryRate: number;  // percentage
  avgLatencyMs: number;
  lastHealthyAt: Date;
  issuesDetected: string[];
}
```

### Delivery Success Rate

Calculated per provider, per tenant, per time window:

```
Success Rate = (Delivered / Sent) × 100
```

Bounces and spam reports are excluded from denominator for accuracy.

---

## Intelligence Pipeline

```
Provider Response → Event Normalizer → State Machine → Analytics DB
                                            ↓
                                      Alert Manager
                                            ↓
                                      Auto-remediation
```

### Event Normalizer

Converts provider-specific event schemas to UICP canonical format:

```typescript
interface CanonicalEvent {
  messageId: string;
  eventType: 'sent' | 'delivered' | 'bounced' | 'complained' | 'failed';
  timestamp: Date;
  provider: string;
  metadata: Record<string, unknown>;
}
```

---

## Alerting Rules

| Condition | Severity | Action |
|-----------|----------|--------|
| Provider delivery rate < 90% | WARNING | Alert on-call |
| Provider delivery rate < 70% | CRITICAL | Auto-failover |
| Bounce rate > 5% | WARNING | Review sender reputation |
| Latency > 5s | WARNING | Check provider status |

---

## Data Retention

- Active deliveries: 30 days
- Historical metrics: 1 year
- Aggregated reports: 3 years

---

## Related Documents

- `04-communication/communication-overview.md`
- `04-communication/provider-runtime.md`
- `04-communication/delivery-lineage.md`