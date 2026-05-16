# ADR-002: Domain Resolution Strategy

## Metadata
- **ID**: ADR-002
- **Title**: Domain Resolution Strategy
- **Status**: Accepted
- **Date**: 2026-05-15
- **Author**: Architecture Team
- **Domain**: tenant-resolution

## Context
Multi-tenant system must resolve tenant context from incoming requests. Options:
1. Header-based (X-Tenant-ID)
2. Path-based (/tenants/:id/...)
3. Credential-based (API key, JWT)

## Decision
Use credential-based resolution with priority order:
1. **API Key** → tenantId embedded in key
2. **JWT** → tenantId from `tid` claim
3. **Session** → tenantId from session data

No header fallback for authenticated endpoints.

## Consequences
### Positive
- Tenant context follows credential (true zero-trust)
- API keys work without tenant header
- Consistent tenant resolution across auth methods

### Negative
- Unauthenticated endpoints still require header
- Migration from header-based requires code changes

## Trust Boundaries
- UnifiedAuthGuard: Trusted (resolves tenant)
- Tenant Repository: Trusted (validates tenant exists)

## Related ADRs
- ADR-001: API Key Runtime
- ADR-005: Session Model
