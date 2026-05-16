```yaml
title: Reconciliation Runtime
domain: execution
owner: platform-runtime
criticality: high
runtime-impact: cross-component
security-impact: low
queue-impact: medium
provider-impact: medium
tenant-impact: medium
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - request-lifecycle.md
  - delivery-runtime.md
  - session-runtime.md
related-docs:
  - request-lifecycle.md
  - delivery-runtime.md
  - session-runtime.md
related-queues:
  - reconciliation-tasks
  - discrepancy-reports
related-services:
  - reconciliation-engine
  - discrepancy-detector
  - balance-resolver
related-providers:
  - all-configured-providers
related-runtime-states:
  - pending
  - reconciling
  - discrepancy-found
  - resolved
  - escalated
related-threat-models:
  - reconciliation-fraud
  - data-corruption
```

# Reconciliation Runtime

The reconciliation-runtime ensures consistency between internal system state and provider records, detecting discrepancies and initiating correction procedures to maintain data integrity across the entire request lifecycle.

## Reconciliation Triggers

The reconciliation-engine initiates reconciliation checks based on multiple conditions. Scheduled reconciliation performs periodic full-state comparisons at configured intervals. Event-driven reconciliation triggers when significant state changes occur. On-demand reconciliation allows manual initiation when issues are suspected. Continuous reconciliation performs incremental checks during normal operation.

## Discrepancy Detection

The discrepancy-detector identifies differences between system and provider state. Response validation compares provider responses against expected schemas and values. Status verification confirms provider recorded status matches system records. Balance reconciliation compares transaction totals across systems. Completion verification confirms requests reached final states in both systems.

## Resolution Procedures

The balance-resolver implements correction procedures for detected discrepancies. Auto-correction applies predefined fixes for known discrepancy patterns. Manual escalation routes complex discrepancies to operator review. Dispute initiation creates formal discrepancy records for provider communication. Recovery procedures restore consistent state through state reconstruction.

## Reconciliation Scope

Reconciliation operates at multiple granularities. Transaction-level reconciliation compares individual request records. Session-level reconciliation verifies session continuity across multiple requests. Account-level reconciliation validates overall account balances and limits. Audit-level reconciliation ensures complete audit trail integrity.

## Reporting and Analytics

Comprehensive reconciliation reporting provides operational visibility. Discrepancy trending identifies patterns in reconciliation failures. Resolution time metrics measure reconciliation efficiency. False positive analysis tunes detection algorithms to reduce noise. Reconciliation coverage reports show percentage of transactions verified.
```