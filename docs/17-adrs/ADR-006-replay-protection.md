# ADR-006: Replay Protection

## Metadata
- **ID**: ADR-006
- **Title**: Replay Protection
- **Status**: Accepted
- **Date**: 2026-05-15

## Context
Prevent reuse of authentication tokens and duplicate API requests.

## Decision
1. Idempotency keys for all mutations
2. Short token lifespan (15 min access, 7 day refresh)
3. Token rotation on every refresh
4. Session invalidation on password change
5. HMAC validation with timestamp nonce

## Consequences
- Prevents duplicate operations
- Limits token reuse window
- Requires additional infrastructure (Redis blocklist)

## Related ADRs
- ADR-001: API Key Runtime

