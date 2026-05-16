---
title: Data Schema Overview
domain: data
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 03-architecture/database-patterns.md
  - 07-security/data-classification.md
related-docs:
  - entity-relationships.md
  - migrations.md
  - consistency-model.md
related-queues:
  - outbox-events
  - audit-events
related-services:
  - mysql-database
  - redis-cache
---

# Data Schema Overview

## Metadata
```yaml
title: Data Schema Overview
domain: data
criticality: HIGH
ai-ingestable: true
```

---

## Overview

UICP uses MySQL as the primary data store with Redis for caching and sessions.

---

## Core Entities

### User
```sql
id: UUID (primary)
tenant_id: UUID (index)
email: VARCHAR(320)
phone: VARCHAR(20)
status: ENUM(active, suspended, deleted)
created_at: TIMESTAMP
updated_at: TIMESTAMP
```

### Tenant
```sql
id: UUID (primary)
name: VARCHAR(255)
domain: VARCHAR(255)
plan: ENUM(free, standard, enterprise)
status: ENUM(active, suspended)
created_at: TIMESTAMP
```

### ApiKey
```sql
id: UUID (primary)
tenant_id: UUID (index)
key_hash: VARCHAR(64) (index)
prefix: CHAR(2)
scope: JSON
status: ENUM(active, rotated, revoked)
expires_at: TIMESTAMP
created_at: TIMESTAMP
```

### Session
```sql
id: UUID (primary)
tenant_id: UUID (index)
user_id: UUID (index)
token_hash: VARCHAR(64)
ip_hash: VARCHAR(64)
device_fingerprint: VARCHAR(64)
expires_at: TIMESTAMP
created_at: TIMESTAMP
```

---

## Event Store

All mutations logged to event store for audit and replay:

```sql
event_store:
  - id: UUID
  - tenant_id: UUID
  - entity_type: VARCHAR
  - entity_id: UUID
  - action: ENUM(created, updated, deleted)
  - payload: JSON
  - metadata: JSON
  - created_at: TIMESTAMP
```

---

## Related Documents

- `08-data/entity-relationships.md`
- `08-data/migrations.md`

