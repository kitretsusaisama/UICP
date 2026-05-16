# Replay Tuning

## Metadata
```yaml
title: Replay Tuning
domain: smart-tuning
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: HIGH
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 02-runtime/replay-runtime
  - 16-failure-models/replay-attacks
  - 03-auth/replay-prevention
related-docs:
  - 18-smart-tuning/retry-tuning.md
  - 18-smart-tuning/operational-guardrails.md
  - 18-smart-tuning/recovery-behavior.md
related-queues:
  - Replay Queue
  - Dead Letter Queue
related-services:
  - Replay Manager
  - Idempotency Checker
related-providers:
  - All providers
```

---

## Overview

Replay tuning configures the system's ability to safely replay failed or interrupted operations without causing duplicate deliveries, data corruption, or security vulnerabilities. This is essential for maintaining exactly-once delivery guarantees while supporting robust recovery from failures at any point in the delivery pipeline.

The replay system operates as a deterministic mechanism that reproduces previous operations using preserved state, ensuring that every replay produces identical outcomes to the original attempt. This determinism is fundamental to achieving exactly-once semantics in a distributed system.

---

## Idempotency Architecture

Idempotency keys form the foundation of safe replay behavior:

**Key Structure**: `{tenant_id}:{message_hash}:{sequence_number}:{timestamp}`

The tenant ID component ensures complete isolation between tenants. The message hash (SHA-256 of canonical message content) ensures identical messages produce identical keys. The sequence number handles scenarios where the same tenant sends multiple messages within the same second. The timestamp prevents key reuse across different validity windows.

**Key Storage**: Idempotency keys are stored in Redis with configurable TTL (default 24 hours), enabling rapid duplicate detection while limiting storage requirements. Keys include metadata about the original request including provider used, recipient count, and delivery status.

---

## Replay Safeguards

Multiple safeguards prevent replay-related security issues:

**Request Fingerprinting** captures a hash of the complete request state (headers, body, routing decisions) alongside the idempotency key. Replays must match the original fingerprint exactly, preventing manipulation attacks where attackers modify request parameters during replay.

**Timestamp Validation** rejects replays outside a sliding window (default 5 minutes for API requests, 1 hour for queued messages), preventing both ancient replays and clock manipulation attacks.

**Token Binding** ties replay capability to the original authentication context, ensuring that replays cannot be initiated by different credentials than the original request. Any authentication token reuse triggers automatic rejection.

---

## Replay Logging and Audit

Every replay operation is logged for security and debugging purposes:

**Audit Trail** records the original request identifier, replay request identifier, timestamp delta, authentication context, and outcome. This trail enables forensic analysis of any replay-related issues while providing evidence for compliance requirements.

**Replay Counter** tracks how many times each idempotent operation has been replayed, with configurable thresholds (default 3) that trigger alerts when excessive replays occur. High replay counts indicate potential systemic issues requiring investigation.

**State Preservation** maintains complete request context in the replay log, enabling exact reproduction of any historical operation without requiring reconstruction from partial data.

---

## Recovery Point Configuration

Recovery points define how much work can be lost during failure recovery:

| Operation Type | Recovery Point | RPO Target |
|----------------|----------------|------------|
| Message Send | At delivery attempt | 30 seconds |
| Batch Send | At message boundary | 5 minutes |
| Template Render | At render completion | 1 minute |
| Provider API Call | At API response | 30 seconds |

These recovery points balance the cost of recomputation against the risk of lost work, with different thresholds appropriate for operations with different computational costs and business impact.

---

## Replay Conflict Resolution

When concurrent replays occur, conflict resolution ensures consistent outcomes:

**Last-Write-Wins** with vector clocks resolves conflicts between concurrent updates to the same resource. The system tracks logical timestamps for all state changes, enabling detection of concurrent modifications.

**Conflict Detection** triggers alerts when concurrent modifications are detected, enabling manual review of potentially conflicting replays. The alerting threshold is configurable based on the criticality of the affected operation.

**Compensation Actions** automatically execute when conflicts are detected, ensuring that the final state represents a valid merge of concurrent operations rather than arbitrary winner selection.

---

## Related Documents

- `02-runtime/replay-runtime.md`
- `16-failure-models/replay-attacks.md`
- `03-auth/replay-prevention.md`