# ADR-003: Queue-First Runtime Design

## Metadata
- **ID**: ADR-003
- **Title**: Queue-First Runtime Design
- **Status**: Accepted
- **Date**: 2026-05-15
- **Author**: Architecture Team
- **Domain**: runtime

## Context
External operations (email, SMS, webhooks) must be reliable. Options:
1. Synchronous - fast but no retry
2. Background jobs - fire-and-forget
3. Queues with retry - reliable but complex

## Decision
All external I/O flows through BullMQ queues:
- **Email delivery** → `email-delivery` queue
- **SMS delivery** → `sms-delivery` queue  
- **OTP processing** → `otp-fastlane` queue (priority)
- **Webhook events** → `webhook-processing` queue
- **Audit logging** → `audit-logging` queue

Retry policy: 3x exponential backoff with dead-letter queue.

## Consequences
### Positive
- Guaranteed delivery with retry
- Backpressure handling during load
- Operational visibility into queue depth
- Graceful degradation via DLQ

### Negative
- Added latency (async vs sync)
- Complexity in error handling
- Queue infrastructure required

## Observability
- `uicp.queue.backlog` - queue depth metrics
- `uicp.queue.processing_time` - latency metrics
- `uicp.queue.failed` - failure metrics

## Related ADRs
- ADR-004: Provider Abstraction
