---
title: Database Indexing Strategy
domain: data
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: LOW
queue-impact: LOW
provider-impact: LOW
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - schema-overview.md
  - entity-relationships.md
  - partitioning.md
related-docs:
  - partitioning.md
  - entity-relationships.md
  - consistency-model.md
related-queues: []
related-services:
  - mysql-database
---

# Database Indexing Strategy

## Overview

The indexing strategy balances query performance against write overhead, prioritizing the access patterns observed in production workloads. Index design follows the principle of covering frequent queries while avoiding redundant indexes that increase storage and maintenance costs. The strategy employs composite indexes optimized for tenant-scoped queries common in multi-tenant architectures.

## Primary Indexes

The primary key indexes use UUID values for all core entities, providing uniform distribution and preventing sequential hot-spotting. UUID generation uses ULID format for time-sortable identifiers, enabling efficient time-range queries on primary keys when combined with created_at ordering. The primary key constraint automatically creates a clustered index organizing physical storage in primary key order.

## Tenant-Scoped Indexes

Every table implementing multi-tenant data includes a composite index with tenant_id as the leading column. These indexes enable efficient filtering across all tenant-scoped operations and prevent cross-tenant data leakage by ensuring queries always include the tenant context. The composite index ordering places tenant_id first, followed by frequently filtered columns in descending order of query frequency.

## Composite Index Design

The user table includes a composite index on (tenant_id, email) supporting the unique constraint and common lookup patterns. The session table uses (tenant_id, user_id, expires_at) to support session enumeration and expiration cleanup queries. The api_key table implements (tenant_id, status, created_at) for active key enumeration and access review queries. Each composite index is carefully designed to cover the most frequent query patterns without unnecessary column inclusion.

## Partial Indexes for Performance

Partial indexes optimize filtered queries common in UICP workloads. An index on active sessions excludes expired records, reducing index size while improving query performance for the majority of session lookups. The audit_log table includes filtered indexes for each action type, enabling efficient retrieval of creation, update, or deletion events without scanning the full table.

## Index Maintenance

Index usage is monitored through query execution plans and slow query analysis. Unused indexes are identified quarterly and removed after validating they do not impact query performance. Index fragmentation is managed through scheduled reorganization during low-traffic periods. Covering indexes are implemented for frequently accessed query patterns to eliminate table lookups.