# Fallback Model - AI Context

## Metadata
```yaml
title: Fallback Model
domain: ai-context
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: CRITICAL
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - system-summary.md
  - provider-context.md
  - queue-context.md
related-docs:
  - 08-message-delivery/failover.md
  - 09-delivery-status/callbacks.md
related-queues:
  - sms-delivery
  - email-delivery
related-services:
  - provider-router
  - notification-service
related-runtime-states:
  - primary
  - degraded
  - fallback
```

---

## Fallback Triggers

| Condition | Trigger | Fallback Action |
|-----------|---------|-----------------|
| Provider quota exceeded | HTTP 429 | Switch to next provider |
| Provider timeout | > 30s | Retry then failover |
| Provider auth error | HTTP 401 | Alert, use fallback |
| Provider region down | Health check | Route to alternate region |
| Provider unavailable | Connection failure | Failover chain |

---

## Email Fallback Chain

```
SES (primary)
  → Resend (secondary)
    → Maileroo (tertiary)
      → Queue for later (DLQ if all fail)
```

## SMS Fallback Chain

```
Msg91 (primary)
  → Twilio (secondary)
    → Queue for later (DLQ if all fail)
```

---

## Fallback Rules

1. **Always try primary first**: Cost optimization
2. **Fail fast on auth**: Immediate switch on 401
3. **Retry before fallback**: 3 retries with backoff
4. **Log every fallback**: For monitoring and analysis
5. **Alert on chain exhaustion**: When all providers fail

---

## Degraded Mode Operations

| Mode | Impact | Behavior |
|------|--------|----------|
| Single provider | Higher latency | Queue messages, retry |
| Reduced retry | Faster failure | 2 retries instead of 3 |
| Sync to async | Delayed delivery | Queue instead of direct |

---

## Fallback Metrics

| Metric | Target | Alert |
|--------|--------|-------|
| Fallback rate | < 5% | > 10% |
| Fallback latency | < 200ms | > 500ms |
| Chain exhaustion | 0 | Any occurrence |

---

## Related Context Files

- `provider-context.md` - Provider selection
- `queue-context.md` - Queue processing
- `retry-model.md` - Retry policies

---

*AI-Ingestible: true | Fallback context for AI reasoning*