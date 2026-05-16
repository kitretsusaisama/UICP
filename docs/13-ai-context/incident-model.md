# Incident Model - AI Context

## Metadata
```yaml
title: Incident Model
domain: ai-context
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - system-summary.md
  - retry-model.md
  - fallback-model.md
related-docs:
  - 06-operations/incident-response.md
  - 16-failure-models/categorization.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
related-services:
  - all-services
related-runtime-states:
  - healthy
  - degraded
  - offline
  - recovering
```

---

## Incident Categories

### 1. Authentication Incidents
| Incident | Severity | Impact | Resolution |
|----------|----------|--------|------------|
| Redis down | CRITICAL | All sessions lost | In-memory fallback |
| Token service down | HIGH | Login failures | Restart service |
| API key leak | CRITICAL | Unauthorized access | Revoke + rotate |

### 2. Queue Incidents
| Incident | Severity | Impact | Resolution |
|----------|----------|--------|------------|
| Queue storm | HIGH | Backlog | DLQ, backpressure |
| Worker crash | MEDIUM | Processing delay | Auto-restart |
| Queue full | HIGH | Message rejection | Scale consumers |

### 3. Provider Incidents
| Incident | Severity | Impact | Resolution |
|----------|----------|--------|------------|
| Provider down | HIGH | Delivery failure | Auto-failover |
| Quota exceeded | MEDIUM | Rate limiting | Route to backup |
| Region outage | CRITICAL | Regional failure | Cross-region routing |

### 4. Database Incidents
| Incident | Severity | Impact | Resolution |
|----------|----------|--------|------------|
| MySQL down | CRITICAL | Full outage | Read replicas |
| Replication lag | MEDIUM | Stale reads | Alert + monitor |
| Connection pool | HIGH | Request failures | Optimize queries |

---

## Incident Response Flow

```
Detection → Triage → Containment → Resolution → Post-mortem
   │            │            │            │          │
   ▼            ▼            ▼            ▼          ▼
 Alert       Severity    Isolate      Fix root   Document
             assessment  impact       cause      lessons
```

---

## Severity Levels

| Level | Response Time | Example |
|-------|---------------|---------|
| P0 - Critical | < 15 min | Full outage |
| P1 - High | < 1 hour | Major feature down |
| P2 - Medium | < 4 hours | Degraded performance |
| P3 - Low | < 24 hours | Minor issues |

---

## Related Context Files

- `failure-propagation.md` - Failure impact
- `retry-model.md` - Retry handling
- `fallback-model.md` - Failover

---

*AI-Ingestible: true | Incident context for AI understanding*