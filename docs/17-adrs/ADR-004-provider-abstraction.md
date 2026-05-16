# ADR-004: Provider Abstraction

## Metadata
- **ID**: ADR-004
- **Title**: Provider Abstraction
- **Status**: Accepted
- **Date**: 2026-05-15

## Context
Multiple email/SMS providers with different APIs and capabilities.

## Decision
Create provider abstraction layer (interface) with adapter pattern.

## Consequences
- Single interface for all providers
- Easy to add new providers
- Failover handled automatically

## Related ADRs
- ADR-003: Queue-First Runtime

