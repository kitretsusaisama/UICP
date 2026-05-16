# ADR-007: Runtime Lineage

## Metadata
- **ID**: ADR-007
- **Title**: Runtime Lineage
- **Status**: Accepted
- **Date**: 2026-05-15

## Context
Need traceability for debugging and audit.

## Decision
1. Correlation ID on every request
2. Trace spans in all services
3. Event store for audit
4. Lineage queries for debugging

## Consequences
- Full request traceability
- Easy incident reproduction
- Storage overhead for logs

