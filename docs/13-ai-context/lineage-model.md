# Lineage Model - AI Context

## Metadata
```yaml
title: Lineage Model
domain: ai-context
owner: Platform Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - system-summary.md
  - auth-context.md
related-docs:
  - 03-data-lineage/audit-logging.md
  - 15-runtime-lineage/request-tracing.md
related-queues: []
related-services:
  - audit-service
  - event-store
related-runtime-states:
  - traced
  - correlated
```

---

## Lineage Components

### 1. Request Lineage
- Trace ID propagation across services
- Correlation ID for multi-step operations
- Parent-child relationship tracking

### 2. Data Lineage
- Entity create/update/delete events
- Field-level change tracking
- Version history

### 3. Audit Lineage
- User action logging
- System event tracking
- Compliance evidence

---

## Lineage Event Schema

```typescript
interface LineageEvent {
  id: string;              // ULID
  trace_id: string;       // Request trace
  tenant_id: string;      // Tenant context
  user_id: string;        // Actor
  action: string;         // CRUD operation
  entity_type: string;    // Resource type
  entity_id: string;      // Resource identifier
  changes: object;        // Before/after
  timestamp: string;      // ISO 8601
  metadata: object;       // Additional context
}
```

---

## Lineage Storage

| Store | Purpose | Retention |
|-------|---------|-----------|
| MySQL Event Store | Entity changes | 7 years |
| Redis Stream | Real-time trace | 24 hours |
| Elasticsearch | Searchable audit | 1 year |

---

## Trace Propagation

```
Client Request
     │
     ▼ (add trace_id header)
[API Gateway]
     │
     ▼ (propagate trace_id)
[Application Services]
     │
     ▼ (emit lineage events)
[Event Store]
```

---

## Query Patterns

| Query | Use Case | Store |
|-------|----------|-------|
| User activity timeline | Audit | MySQL |
| Request flow | Debugging | Redis Stream |
| Entity history | Compliance | MySQL |
| Search by trace | Debugging | Elasticsearch |

---

## Related Context Files

- `system-summary.md` - Architecture
- `incident-model.md` - Debugging context
- `runtime-map.md` - Service flow

---

*AI-Ingestible: true | Lineage context for AI reasoning*