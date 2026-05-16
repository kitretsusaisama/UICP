# Observability - Lineage

## Metadata
```yaml
title: Observability - Lineage
domain: observability
owner: Data Engineering
criticality: MEDIUM
runtime-impact: LOW
security-impact: LOW
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: LOW
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 10-observability/tracing
  - 10-observability/metrics
related-docs:
  - 10-observability/telemetry-pipelines
  - 10-observability/distributed-tracing
related-queues:
  - audit-queue
  - outbox-queue
related-services:
  - lineage-collector
  - metadata-store
```

---

## Overview

Lineage tracking captures the flow of data through UICP systems, enabling impact analysis, data provenance, and compliance auditing. This document defines the lineage data model, collection mechanisms, and consumption patterns for the platform.

---

## Lineage Data Model

Lineage information is captured at three granularities. Event-level lineage tracks individual data transformations within a single operation. Flow-level lineage tracks data movement between services and queue topics. Process-level lineage tracks end-to-end business workflows spanning multiple operations.

Each lineage node represents a processing step with input and output artifacts. Nodes include service name, operation type, timestamp, and processing metadata. Edges connect nodes representing data flow, with edge metadata including data volume, format, and transformation rules.

---

## Collection Mechanisms

Automatic collection uses instrumentation in service code to capture lineage during request processing. Every service operation that processes user data emits lineage events to a dedicated topic. The lineage collector subscribes to this topic and builds the lineage graph.

Manual collection captures business-level lineage for workflows not visible in system traces. Data stewards can register process definitions defining expected data flows. The lineage system correlates manual definitions with automatic traces to produce complete lineage graphs.

---

## Data Flow Tracking

User credential data flows through authentication, validation, storage, and audit logging stages. The lineage for a credential validation operation traces through the API gateway, authentication service, identity provider adapter, and audit logger. Each stage captures input data characteristics and output data produced.

API key lifecycle tracking captures key creation, rotation, usage, and revocation events. Lineage connects key operations to the originating user, tenant, and access policies. This enables impact analysis when key rotation or revocation occurs.

Queue message lineage tracks messages from producer to consumer, including retry and dead letter handling. Each message carries provenance metadata enabling end-to-end trace reconstruction. Failed message analysis uses lineage to identify the originating operation and data context.

---

## Use Cases

Impact analysis uses lineage to determine affected systems when a data change occurs. When a tenant requests data deletion, lineage identifies all systems and services that hold the tenant's data, enabling coordinated deletion across the platform.

Root cause analysis leverages lineage to trace error propagation through the system. A validation failure in a downstream service can be traced back to the originating request and data source. Lineage complements distributed tracing by focusing on data dependencies rather than call relationships.

Compliance auditing uses lineage to demonstrate data handling compliance. For data residency requirements, lineage shows where tenant data is processed and stored. For retention policies, lineage identifies data that has exceeded retention thresholds.

---

## Storage and Query

Lineage data is stored in a graph database optimized for traversal queries. The schema supports both forward queries (what systems consume this data) and backward queries (where did this data originate). Query APIs support both programmatic access and interactive exploration.

Lineage retention follows data retention policies, with lineage data retained for the longest applicable policy among its constituent data. Lineage for deleted data is retained for 30 days to support post-deletion impact analysis.

---

## Related Documents

- `10-observability/tracing`
- `10-observability/distributed-tracing`
- `10-observability/telemetry-pipelines`