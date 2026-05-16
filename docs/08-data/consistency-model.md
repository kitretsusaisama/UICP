---
title: Data Consistency Model
domain: data
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - schema-overview.md
  - replication.md
  - event-store.md
related-docs:
  - replication.md
  - event-store.md
  - audit-storage.md
related-queues:
  - outbox-events
  - consistency-events
related-services:
  - mysql-database
  - redis-cache
  - message-queue
---

# Data Consistency Model

## Overview

UICP implements eventual consistency with tunable consistency guarantees depending on operation criticality. The consistency model balances performance requirements against data integrity, supporting both strong consistency for financial operations and eventual consistency for high-throughput scenarios. The model leverages the outbox pattern for reliable event publishing while maintaining database consistency.

## Consistency Levels

Strong consistency ensures read operations return the most recent write results. User authentication and authorization decisions require strong consistency to prevent unauthorized access. Financial transactions and billing operations use strong consistency preventing double-charging scenarios. Strong consistency operations incur latency costs from synchronous replication completion.

Eventual consistency enables high-throughput scenarios where slight staleness is acceptable. Session data and cached information accept eventual consistency for performance optimization. Analytics aggregations update asynchronously with eventual consistency guarantees. The eventual consistency window typically completes within seconds under normal operations.

Read-your-writes consistency provides session-level guarantees ensuring writes are immediately visible to the author. User profile updates appear immediately in subsequent reads by the same user. API key creation enables immediate usage without propagation delays. Session invalidation propagates within the same request context.

## Transaction Boundaries

Single-database transactions use ACID guarantees for operations within one database. The transaction isolation level prevents dirty reads and non-repeatable queries. Optimistic locking detects concurrent modifications preventing lost updates. Transaction timeouts prevent long-running operations from blocking resources.

Cross-database operations use the saga pattern with compensating transactions for failure recovery. Each step in a saga executes as an independent transaction with compensation logic for rollback. The outbox table maintains pending operations ensuring eventual execution even if service restarts. Saga orchestrator tracks progress enabling resumption after interruptions.

## Consistency Verification

Consistency verification jobs periodically scan for anomalies in distributed data.Checksum comparison between primary and replicas detects replication inconsistencies. Event ordering validation ensures event-store sequence matches database state. Violation alerts trigger investigation and remediation procedures.

## Conflict Handling

Concurrent updates to the same entity use optimistic concurrency control with version tracking. Version conflicts return error responses enabling client retry with fresh data. Last-write-wins provides deterministic resolution for non-critical fields. Custom conflict resolution handlers support business-specific merge logic.