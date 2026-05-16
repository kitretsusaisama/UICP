# ADR-001: API Key Runtime Architecture

## Metadata
- **ID**: ADR-001
- **Title**: API Key Runtime Architecture
- **Status**: Accepted
- **Date**: 2026-05-15
- **Author**: Architecture Team
- **Domain**: authentication

## Context
UICP requires tenant context resolution without relying on explicit X-Tenant-ID headers. The architecture must support:
- ULID-based key formats for uniqueness
- HMAC signature validation for security
- Environment separation (live/dev)
- Publishable vs secret key distinction

## Decision
Use ULID-based API keys with HMAC-SHA256 signatures:
- **Format**: `{prefix}{ULID26}{optional HMAC44}`
- **Prefixes**: uF (live publishable), sF (live secret), pB (dev publishable), tB (dev secret)
- **Validation**: HMAC signature verification using API_KEY_HMAC_SECRET

## Consequences
### Positive
- Tenant ID extracted from key itself (no header dependency)
- Cryptographic verification prevents tampering
- ULID provides sortable, time-ordered identifiers
- Environment distinction prevents dev keys in production

### Negative
- Secret keys must be stored securely (HMAC prevents reverse-engineering)
- Key rotation requires grace period for migration

## Trust Boundaries
- API Key Service: Trusted (generates/validates keys)
- API Key Repository: Trusted (persists keys)
- HMAC Secret: CRITICAL - compromise allows tenant impersonation

## Related ADRs
- ADR-002: Domain Resolution
- ADR-006: Replay Protection
