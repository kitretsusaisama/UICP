# Operational Constraints - AI Context

## Metadata
```yaml
title: Operational Constraints
domain: ai-context
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - system-summary.md
  - auth-context.md
  - queue-context.md
related-docs:
  - 02-architecture/constraints.md
  - 06-operations/sla-requirements.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
related-services:
  - all-services
related-runtime-states:
  - normal
  - constrained
```

---

## Time-Based Constraints

| Parameter | Value | Purpose |
|-----------|-------|---------|
| JWT Access Token | 900s (15 min) | Limit replay window |
| JWT Refresh Token | 604800s (7 days) | Session continuity |
| Session TTL | 86400s (24 hours) | Activity-based expiry |
| OTP TTL | 300s (5 minutes) | Prevent brute force |
| API Key Grace Period | 3600s (1 hour) | Key rotation buffer |
| Idempotency Key TTL | 86400s (24 hours) | Duplicate detection |
| Audit Log Retention | 2555 days (7 years) | Compliance |

---

## Rate Constraints

| Resource | Limit | Scope |
|----------|-------|-------|
| API Requests | 1000/min | Per API key |
| OTP Requests | 10/min | Per phone number |
| Login Attempts | 5/min | Per user |
| Token Refresh | 100/day | Per user |
| Provider Calls | Varies | Per provider quota |

---

## Capacity Constraints

| Component | Limit | Scaling |
|-----------|-------|---------|
| Concurrent Sessions | 100k | Redis Cluster |
| Queue Depth | 10k | Backpressure |
| Worker Pool | 20 | Vertical scale |
| DB Connections | 100 | Connection pool |
| API Gateway | 10 instances | Horizontal |

---

## Operational Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| API Latency | > 200ms | > 500ms |
| Queue Lag | > 1 min | > 5 min |
| Error Rate | > 1% | > 5% |
| CPU Usage | > 70% | > 90% |
| Memory Usage | > 80% | > 95% |

---

## Constraint Enforcement

| Constraint | Mechanism | Action |
|-----------|-----------|--------|
| Token expiry | Auto-expiry | Re-authenticate |
| Rate limit | Token bucket | 429 response |
| Capacity | Backpressure | Queue rejection |
| SLA breach | Alert | On-call notification |

---

## Related Context Files

- `system-summary.md` - Constraints summary
- `scaling-model.md` - Scaling constraints
- `queue-context.md` - Queue constraints

---

*AI-Ingestible: true | Operational limits for AI context*