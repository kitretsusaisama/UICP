# Communication Overview

## Metadata
```yaml
title: Communication Overview
domain: communication
criticality: HIGH
provider-impact: HIGH
ai-ingestable: true
```

---

## Overview

UICP provides a provider-agnostic communication fabric for email and SMS delivery. The system automatically routes messages to the best available provider based on cost, reliability, and region.

---

## Supported Channels

| Channel | Providers | Use Cases |
|---------|-----------|------------|
| **Email** | SES (primary), Resend, Maileroo | Notifications, verification, marketing |
| **SMS** | Msg91 | OTP, MFA, alerts |

---

## Provider Routing

### Selection Algorithm

```
1. Get active providers with health > threshold
2. Filter by:
   - Region match (lowest latency)
   - Cost optimization (cheapest within SLA)
   - Quota availability (has capacity)
3. Sort by composite score
4. Select highest-scoring provider
```

### Provider Scores

| Provider | Base Score | Factors |
|----------|------------|---------|
| SES | 100 | Reliability, global reach |
| Resend | 95 | Cost, modern API |
| Maileroo | 80 | Fallback |
| Msg91 | 100 | India coverage |

Scores adjust dynamically based on:
- Delivery success rate
- Latency
- Error rate
- Quota usage

---

## Delivery Flow

```
Client Request
     ↓
Communication Service
     ↓
Provider Router (select provider)
     ↓
Queue (BullMQ) - for async
     ↓
Worker processes message
     ↓
Provider API call
     ↓
Delivery confirmation
     ↓
Webhook (optional)
     ↓
Delivery status update
```

---

## Queue Configuration

| Queue | Priority | Retry | DLQ |
|-------|----------|-------|-----|
| `email-delivery` | MEDIUM | 3x exponential | Yes |
| `sms-delivery` | HIGH | 3x exponential | Yes |
| `otp-fastlane` | CRITICAL | 1x immediate | No |

---

## Observability

### Metrics

| Metric | Description |
|--------|-------------|
| `uicp.provider.delivery_success` | Successful deliveries |
| `uicp.provider.delivery_failure` | Failed deliveries |
| `uicp.provider.latency` | Provider response time |
| `uicp.queue.backlog` | Messages pending |

### Health Endpoint

```bash
GET /v1/providers/health

{
  "providers": {
    "ses": { "healthy": true, "latencyMs": 120, "quotaRemaining": "80%" },
    "resend": { "healthy": true, "latencyMs": 95, "quotaRemaining": "95%" },
    "msg91": { "healthy": true, "latencyMs": 200, "quotaRemaining": "60%" }
  }
}
```

---

## Template System

Templates support variable substitution:

```
Template: "Hello {{name}}, your verification code is {{code}}"

Variables: { name: "John", code: "123456" }

Result: "Hello John, your verification code is 123456"
```

---

## Related Documents

- `04-communication/provider-runtime.md`
- `04-communication/delivery-intelligence.md`
- `04-communication/webhook-reconciliation.md`
- `16-failure-models/provider-outages.md`

