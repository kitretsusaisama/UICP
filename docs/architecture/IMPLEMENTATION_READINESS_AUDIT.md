# UICP Implementation Readiness Audit

## Safe to Implement NOW (Phase 1 Focus)
- **Transactional Outbox Determinism**: Validating that outbox relays strictly guarantee at-least-once delivery and idempotency keys correctly reject duplicates.
- **Session Lineage Correctness**: Ensuring that when an identity is marked 'revoked' in MySQL, all corresponding session cache entries are deterministically purged and a SOC alert is enqueued via the Outbox.
- **CLS Enforcement**: Bolstering `ClsContextInterceptor` tests to prove that contexts survive BullMQ transitions and WebSocket connections.
- **Tenant Isolation**: Adding repository-level guards that strictly require tenant scopes for all UPDATE/DELETE queries.

## NOT Ready for Implementation (Require Architecture Stabilization)
- ❌ **Edge Runtime Fabric**: DO NOT build edge synchronization logic until the consistency of the underlying Redis-to-MySQL fallback is mathematically proven.
- ❌ **Adaptive Runtime Orchestration**: DO NOT build scaling heuristics before base metric collection and backpressure behavior is rock solid.
- ❌ **Graph Intelligence**: DO NOT build graph traversal engines until the event sourcing (which will feed the graph) is perfectly ordered and replay-safe.
- ❌ **Governance Approval Workflows**: DO NOT build complex enterprise workflows before basic RBAC/ABAC propagation is hardened.