# UICP Architecture: Consistency Graph Engine

## System Classification
Distributed Consistency Engine

## Architectural Philosophy
Track event lineage, projection freshness, and queue propagation in realtime. We must KNOW exactly when nodes are stale.

## Consistency Graph Architecture
- A unified view that tracks causality across distributed nodes.
- Tracks `Event A -> Outbox -> Worker -> Redis -> Edge`.
- Real-time heatmaps for divergence analysis.

## Replay Risks
Without consistency tracking, replay attacks can hit stale edge nodes that haven't received revocation events.

## Self-Healing Architecture
If divergence reaches a critical threshold (e.g., > 200ms lag on critical revocation topics), the system must auto-quarantine the stale region and redirect traffic.

## Observability Requirements
- Vector clocks or Lamport timestamps across all outbox messages and RPC calls to trace causality.