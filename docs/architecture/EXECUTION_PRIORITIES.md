# UICP Execution Priorities

## Phase 1 — Foundation (IMMEDIATE FOCUS)
Stabilize core correctness before introducing distributed chaos.
- **CLS (Continuation Local Storage)**: Ensure absolute safety across all async boundaries (WebSockets, Queues).
- **Eventing & Outbox**: Guarantee deterministic replay, snapshotting, and strict ordering guarantees.
- **Multi-Tenancy Enforcement**: Ensure repository and encryption isolation cannot be bypassed.
- **Replay Protection**: Lock down replay safety via exact nonce management and idempotency.
- **Session Lineage**: Establish rock-solid revocation consistency and token families.
- **Observability Foundation**: Ensure trace propagation and structured audit lineage.

## Phase 2 — Runtime Intelligence
Introduce intelligence layers based on stable foundations.
- **Consistency Engine**: Track staleness of caches and replicas.
- **Identity Graph Runtime**: Migrate relational trust logic to graph traversals.
- **Adaptive Runtime**: Begin predictive orchestration (scaling, backpressure).

## Phase 3 — Edge & Scale
Push execution closer to the user.
- **Edge Identity Fabric**: Deploy regional verification.
- **Regional Propagation**: Sync configuration across global boundaries.
- **Edge Replay Detection**: Shift replay detection from origin to edge.

## Phase 4 — Governance & Intelligence
Enterprise posture management.
- **Operational Intelligence**: Global health monitoring and automated circuit breakers.
- **Governance Runtime**: Enterprise rollout, approvals, break-glass workflows.
- **Forensic Engine**: Lineage recovery and attack simulation.