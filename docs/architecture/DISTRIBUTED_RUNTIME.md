# UICP Architecture: Distributed Runtime

## System Classification
Distributed Session Fabric & Runtime Orchestrator

## Architectural Philosophy
Do NOT trust eventual consistency blindly. Do NOT trust Redis as a source of truth. The distributed runtime must remain operational even when caches are severed.

## Microservice/Module Topology
- State resides in MySQL as the ultimate Source of Truth (SoT).
- Redis acts as an optimistic view and session fast-path.
- BullMQ queue acts as asynchronous state propagator.

## Data Plane Design
- Writers connect to a strongly consistent database cluster.
- Event sourcing handles state mutations deterministically.
- Outbox pattern ensures atomic persistence of domain events to message brokers.

## Operational Complexity Analysis
High. Requires careful handling of Redis split-brain scenarios, queue pressure, and stale replicas.

## Failure Containment Strategy
- If Redis is down, circuit breakers open, routing strictly to MySQL (fail-open for sessions, fail-closed for tokens if necessary based on security requirements).
- If queues overflow, adaptive multi-signal backpressure rejects requests at the edge (HTTP 503).

## Recovery Strategy
- Cold start re-hydration of Redis from the relational database via event streaming.

## Observability Requirements
- Trace context across every boundary (HTTP -> CLS -> Redis -> Queue -> Worker).