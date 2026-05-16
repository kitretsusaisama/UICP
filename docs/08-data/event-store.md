---
title: Event Store Architecture
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
  - entity-relationships.md
  - consistency-model.md
related-docs:
  - consistency-model.md
  - replay-storage.md
  - audit-storage.md
related-queues:
  - outbox-events
  - event-store-write
related-services:
  - mysql-database
  - event-handler-service
---

# Event Store Architecture

## Overview

UICP implements an event-sourced architecture where every state change produces an immutable event stored in the event store. The event store serves as the system of record enabling event replay for state reconstruction, audit trails for compliance, and integration with downstream systems through event consumption. All events follow the event sourcing pattern with strict append-only semantics.

## Event Schema

Every event includes a globally unique identifier using ULID format for time-sortable identification. The event metadata contains entity_type, entity_id, action, and timestamp enabling efficient event filtering. The payload section stores the delta state representing the change in JSON format. Event versioning enables schema evolution while maintaining backward compatibility for consumers.

Events include correlation_id and causation_id fields linking related events across service boundaries. The user_id field identifies the actor responsible for the change. Tenant context ensures event isolation enabling multi-tenant event processing. The sequence_number field maintains ordering within an entity's event stream.

## Event Flow

Application operations generate domain events during state transitions. Events are persisted to the event store within the same database transaction as state changes, ensuring atomicity. The outbox pattern guarantees event publishing even if the service crashes after state persistence. Background processors consume outbox entries and publish to message queues for downstream processing.

Event consumers subscribe to relevant event types and implement handler logic for side effects. Consumer offsets track processing progress enabling resume after interruptions. Event filtering by tenant ensures data isolation in multi-tenant deployments. Dead letter queues capture events that fail processing after retry limits.

## Event Retention

Hot storage maintains recent events in the primary database for real-time access. Events newer than the retention threshold support immediate query and replay operations. Archive storage moves older events to cost-optimized storage while maintaining catalog entries. Archive events can be restored for compliance and debugging scenarios.

## Query Patterns

Entity reconstruction queries events by entity_id ordering by sequence_number. Temporal queries filter events by timestamp ranges enabling point-in-time state reconstruction. Aggregate queries group events by entity_type for cross-entity analysis. Full-text search on event payloads enables finding events by content.

## Performance Considerations

Event writes use batch processing for high-throughput scenarios. Partitioning by tenant distributes write load across database nodes. Indexes on (entity_type, entity_id, sequence_number) optimize entity replay queries. Snapshotting periodically captures entity state reducing replay time for entities with long event histories.