# Provider Context - AI Context

## Metadata
```yaml
title: Provider Context
domain: ai-context
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: CRITICAL
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - system-summary.md
  - fallback-model.md
  - queue-context.md
related-docs:
  - 08-message-delivery/provider-routing.md
  - 09-delivery-status/webhooks.md
related-queues:
  - sms-delivery
  - email-delivery
related-services:
  - provider-router
  - notification-service
related-runtime-states:
  - available
  - degraded
  - unavailable
related-providers:
  - ses
  - resend
  - maileroo
  - msg91
```

---

## Provider Overview

### Email Providers

| Provider | Priority | Region | Quota | Health |
|----------|----------|--------|-------|--------|
| SES | 1 | us-east-1 | 100k/day | Primary |
| Resend | 2 | global | 10k/day | Secondary |
| Maileroo | 3 | eu-west | 5k/day | Fallback |

### SMS Providers

| Provider | Priority | Region | Quota | Health |
|----------|----------|--------|-------|--------|
| Msg91 | 1 | IN | 50k/day | Primary |
| Twilio | 2 | global | 10k/day | Secondary |

---

## Provider Selection Algorithm

**Selection Order**:
1. Region match (lowest latency)
2. Cost optimization (cheapest available)
3. Quota availability (check remaining)
4. Health score (availability > 99%)
5. Configured default (fallback)

---

## Provider Abstraction Interface

```typescript
interface IProviderPort {
  send(options: SendOptions): Promise<SendResult>;
  getStatus(): Promise<ProviderStatus>;
  getQuota(): Promise<QuotaInfo>;
}
```

**Rule**: Never call provider APIs directly, always use ProviderRouter.

---

## Provider Failure Modes

| Scenario | Detection | Action |
|----------|-----------|--------|
| Quota exceeded | API response | Auto-switch provider |
| Rate limited | HTTP 429 | Backoff + retry |
| Timeout | 30s threshold | Failover |
| Auth failure | HTTP 401 | Alert + fallback |
| Region down | Health check | Route to alternate |

---

## Tenant Provider Configuration

| Tenant Type | Provider Config | Fallback |
|-------------|-----------------|----------|
| Enterprise | Dedicated quota | Auto-failover |
| Standard | Shared pool | Auto-failover |
| Trial | Limited quota | Single provider |

---

## Related Context Files

- `fallback-model.md` - Failover logic
- `queue-context.md` - Queue processing
- `system-summary.md` - Provider summary

---

*AI-Ingestible: true | Provider context for AI understanding*