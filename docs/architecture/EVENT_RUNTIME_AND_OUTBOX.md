# UICP Architecture: Event Runtime and Outbox

## System Classification
Identity Event Fabric

## Event Flow
1. API accepts request -> `ClsContextInterceptor` establishes trace.
2. Aggregate mutates -> Generates Domain Event.
3. Database Transaction -> Commits state AND Outbox Event concurrently.
4. Relay Worker (Queue) -> Reads Outbox -> Broadcasts Event -> Marks Outbox Published.

## Failure Containment Strategy
The Transactional Outbox strictly guarantees At-Least-Once delivery. Idempotency on the consumer side prevents duplication errors.

## Scalability Bottlenecks
Polling the Outbox table. Mitigated by `SELECT ... FOR UPDATE SKIP LOCKED LIMIT N`.