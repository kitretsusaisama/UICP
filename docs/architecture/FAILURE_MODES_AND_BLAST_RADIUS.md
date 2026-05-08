# UICP Failure Modes and Blast Radius

## Subsystem: Transactional Outbox
- **Failure Mode**: Worker crashes mid-batch; `status='PENDING'`.
- **Propagation Path**: Events delay -> Async downstream logic (audit, webhooks) pauses.
- **Blast Radius**: High latency on secondary systems, primary auth succeeds.
- **Recovery Strategy**: Lock release on TCP disconnect. Worker restarts and reclaims batch.
- **Auto-Healing Strategy**: Idle worker heartbeat detection spins up new relays.
- **Observability Requirements**: Metrics tracking Outbox `pending_count` and `max_latency`.

## Subsystem: Redis Session Cache
- **Failure Mode**: Split-brain or total loss of cluster.
- **Propagation Path**: Edge queries cache -> Timeout -> Rejects or falls back to DB.
- **Blast Radius**: Increased DB load; potential for delayed revocation of active sessions.
- **Recovery Strategy**: Open circuit breaker, route to MySQL. Rehydrate Redis from event stream once recovered.
- **Auto-Healing Strategy**: Circuit breakers auto-ping Redis every 5s; transition to `HALF_OPEN` -> `CLOSED` when latency normalizes.
- **Observability Requirements**: Circuit breaker state transitions logged as SOC events.

## Subsystem: CLS Context
- **Failure Mode**: Context lost across an async boundary (e.g. nested callbacks).
- **Propagation Path**: Repositories lack `tenant_id` -> Data spillage or DB errors.
- **Blast Radius**: CATASTROPHIC. Multi-tenant data breach.
- **Recovery Strategy**: Fail-Closed immediately. If `cls.get('tenantId')` is null during a scoped query, throw `FatalIsolationError`.
- **Auto-Healing Strategy**: Cannot auto-heal bad code.
- **Observability Requirements**: AST checks in CI/CD; aggressive chaos testing on async queues.