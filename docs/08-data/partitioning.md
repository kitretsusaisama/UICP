---
title: Database Partitioning Strategy
domain: data
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: LOW
queue-impact: LOW
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: yearly
last-reviewed: 2026-05-16
depends-on:
  - schema-overview.md
  - entity-relationships.md
  - 03-architecture/database-patterns.md
related-docs:
  - entity-relationships.md
  - indexing.md
  - retention.md
related-queues:
  - outbox-events
related-services:
  - mysql-database
---

# Database Partitioning Strategy

## Overview

UICP implements strategic database partitioning to maintain query performance and manage data lifecycle at enterprise scale. The partitioning approach uses a combination of horizontal sharding by tenant and range-based partitioning by time, optimized for the access patterns observed in multi-tenant SaaS environments.

## Tenant-Based Sharding

The primary partitioning strategy shards data by tenant_id across multiple database nodes. This approach ensures that each tenant's data remains isolated while enabling efficient tenant-scoped queries. The sharding key uses a consistent hash algorithm based on tenant_id, distributing tenants uniformly across available database nodes. This design prevents hot-spotting and ensures no single tenant can monopolize database resources.

Tenant sharding is implemented at the application layer, with the TenantContext determining the target database node for each operation. Connection pooling is per-shard to optimize resource utilization. The sharding function uses MD5 hash modulo against the configured shard count, allowing dynamic shard addition without data migration when scaling horizontally.

## Time-Based Range Partitioning

Large tables implement time-based range partitioning for efficient data lifecycle management. The session table uses monthly partitions based on created_at, enabling partition-level archival and retention enforcement. Each partition contains approximately one month of data, with future partitions automatically created as needed. Historical partitions become read-only after the retention window closes.

The audit_log and event_store tables use daily partitions to support fine-grained retention policies. Daily granularity enables efficient deletion of old partitions without impacting active data. Partition pruning occurs automatically when queries include date range filters on the partition column, significantly reducing query execution time for historical data lookups.

## Partition Management

Partition maintenance operations run during low-traffic windows using scheduled jobs. Old partitions are exchanged for archival storage before physical deletion. New partition creation happens automatically through a background scheduler that maintains a rolling 90-day window of active partitions. Partition analysis runs weekly to identify fragmentation and optimize space utilization.

## Query Routing Implications

All application queries must include tenant_id and time-range predicates to leverage partition pruning. The query layer automatically appends these filters based on the TenantContext and request parameters. Queries that span multiple tenants or time ranges execute as scatter-gather operations against relevant partitions, with result aggregation at the application layer.