# ADR-005: Session Model

## Metadata
- **ID**: ADR-005
- **Title**: Session Model
- **Status**: Accepted
- **Date**: 2026-05-15

## Context
Need secure, performant session management for web/mobile clients.

## Decision
Redis-backed sessions with:
- 24-hour TTL
- Token rotation on refresh
- Password change = session invalidation

## Consequences
- Fast validation (<1ms)
- Horizontal scaling via Redis Cluster
- Requires Redis for full functionality

## Related ADRs
- ADR-002: Domain Resolution

