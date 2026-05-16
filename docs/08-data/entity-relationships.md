---
title: Entity Relationships
domain: data
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: LOW
provider-impact: LOW
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - schema-overview.md
  - 03-architecture/database-patterns.md
related-docs:
  - schema-overview.md
  - partitioning.md
  - indexing.md
related-queues:
  - outbox-events
related-services:
  - mysql-database
  - api-gateway
---

# Entity Relationships

## Overview

The UICP data model follows a tenant-isolated design where every core entity references a tenant_id foreign key. This ensures logical data separation while enabling efficient cross-tenant analytics when properly authorized. The relationship model employs a hybrid approach combining relational integrity with event-driven synchronization.

## Core Relationships

### Tenant to User

The tenant-user relationship uses a one-to-many pattern where each user belongs to exactly one tenant. The foreign key constraint enforces referential integrity, and a composite index on (tenant_id, email) ensures uniqueness within a tenant while enabling efficient tenant-scoped queries. Users cannot exist without an active tenant, implementing a cascade delete policy that removes all user data when a tenant is soft-deleted.

### User to Session

User sessions maintain a one-to-many relationship with automatic expiration handling. Each session references both the user and tenant, enabling session enumeration during security audits. The token_hash field stores bcrypt-encrypted session tokens with a 24-hour default TTL. Sessions are partitioned by tenant to maintain query performance at scale.

### Tenant to ApiKey

API keys implement a one-to-many relationship with support for key rotation without service interruption. Each key maintains a prefix for identification, a key_hash for secure storage, and scope definitions in JSON format. The composite index on (tenant_id, status) enables efficient key enumeration during access reviews.

### User to AuditLog

Audit logs follow an event-sourcing pattern where each user action generates an immutable audit record. The relationship uses async insertion via the outbox queue to prevent blocking user operations. Audit entries reference the user, tenant, and include comprehensive metadata about the action performed.

### Event Store Relationships

The event store maintains a many-to-one relationship with entities, capturing all state changes for replay and auditing. Events reference entity_type and entity_id to enable reconstruction of any entity's state at any point in time. The append-only design ensures event immutability and supports event replay for data recovery scenarios.

## Foreign Key Strategy

All foreign key constraints use CASCADE or SET NULL policies depending on the relationship semantics. Soft deletes preserve referential integrity by marking records as deleted rather than physically removing them. Indexes on foreign key columns follow the "index on read" principle, prioritizing query patterns over write optimization.

## Join Patterns

Application queries primarily use inner joins for authenticated operations where entity existence is guaranteed. Outer joins appear in administrative reports where referenced entities may have been deleted. The query layer implements TenantContext to automatically inject tenant_id filters, preventing cross-tenant data leakage at the application level.