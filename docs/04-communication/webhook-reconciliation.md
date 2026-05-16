# Webhook Reconciliation

## Metadata
```yaml
title: Webhook Reconciliation
domain: communication
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - delivery-intelligence.md
  - communication-overview.md
related-docs:
  - provider-runtime.md
  - delivery-lineage.md
  - communication-security.md
related-queues:
  - webhook-processing
related-services:
  - WebhookReceiver
  - EventReconciler
  - DeliveryTracker
related-providers:
  - SES
  - Resend
  - Maileroo
  - Msg91
related-runtime-states:
  - webhook_received
  - webhook_validated
  - event_reconciled
  - state_conflict_detected
related-threat-models:
  - Webhook spoofing
  - Replay attacks
  - Event injection
```

---

## Overview

Webhook Reconciliation ensures that provider delivery events are correctly received, validated, and matched to original message requests. This process maintains accurate delivery state and enables reliable tracking across the entire message lifecycle.

---

## Architecture

### Webhook Flow

```
Provider → Webhook Endpoint → Signature Validation → Event Parser → Reconciler → State Update
                                              ↓
                                      Rate Limiter
```

### Components

| Component | Responsibility |
|-----------|----------------|
| WebhookReceiver | HTTP endpoint for provider callbacks |
| SignatureValidator | Verify webhook authenticity |
| EventParser | Normalize provider-specific payloads |
| EventReconciler | Match events to sent messages |
| StateManager | Update delivery state atomically |

---

## Signature Validation

All webhooks are validated using provider-specific signature schemes:

### SES Signatures

```typescript
// Verify SES webhook signature
function validateSESWebhook(payload: string, signature: string, secret: string): boolean {
  const expected = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('base64');
  return timingSafeEqual(expected, signature);
}
```

### Resend Signatures

Resend uses Ed25519 signatures for webhook verification.

### Msg91 Signatures

Msg91 uses HMAC-SHA256 with a shared secret.

---

## Reconciliation Process

### Event Matching

The reconciler matches incoming events to messages using:

1. **Message ID correlation** - Provider-supplied message ID
2. **Custom metadata** - Tenant-specific tracking IDs
3. **Timestamp window** - Events within 24h of send
4. **Sender identity** - Verified sender address

### State Conflict Resolution

When conflicts occur between API responses and webhooks:

| Scenario | Resolution |
|----------|------------|
| API says delivered, no webhook | Trust webhook, mark pending |
| Webhook arrives after timeout | Accept if within 24h window |
| Multiple conflicting events | Use latest timestamp |

---

## Timeout Handling

| Event Type | Expected Window | Timeout Action |
|------------|-----------------|----------------|
| Sent confirmation | 0-30s | Mark sent after 30s |
| Delivery | 0-5min | Mark delivered after 5min |
| Bounce | 0-1h | Mark bounced after 1h |
| Complaint | 0-24h | Mark as spam after 24h |

---

## Security Measures

### Replay Protection

- Timestamp validation (reject events > 5min old)
- Event deduplication using unique event IDs
- Idempotency keys stored for 24h

### Rate Limiting

- Per-provider rate limits
- Burst allowance: 10x normal rate
- Backpressure when queue depth > 1000

### IP Allowlisting

```
Allowed webhook sources:
- SES: 3.25.0.0/16, 3.27.0.0/16, 3.30.0.0/16
- Resend: 159.89.0.0/16
- Msg91: Configured per tenant
```

---

## Observability

### Metrics

| Metric | Description |
|--------|-------------|
| webhook_received_total | All webhooks received |
| webhook_validation_failed | Invalid signatures |
| reconciliation_success | Events matched to messages |
| reconciliation_conflict | State conflicts detected |

### Logging

All webhook processing includes:
- Request ID for tracing
- Provider and event type
- Processing duration
- Validation result

---

## Related Documents

- `04-communication/delivery-intelligence.md`
- `04-communication/provider-runtime.md`
- `04-communication/communication-security.md`