# Auth Lineage

## Metadata
```yaml
title: Auth Lineage
domain: authentication
owner: Platform Team
criticality: HIGH
runtime-impact: CRITICAL
security-impact: CRITICAL
queue-impact: LOW
provider-impact: NONE
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - identity-repository
  - token-service
  - session-manager
related-docs:
  - 10-security/authentication.md
  - 15-runtime-lineage/request-lineage.md
related-queues: []
related-services:
  - identity-service
  - token-service
  - api-gateway
related-providers: []
```

---

## Overview

Auth lineage tracks all authentication operations from initial credential submission through session termination. This lineage enables security incident reconstruction, credential compromise detection, and access pattern analysis across tenants.

---

## Authentication Flow Lineage

### Credential Validation Chain

```
User Login Attempt
    ↓
Credential Received (API Gateway)
    ↓
Identity Lookup (Database Query)
    ↓
Credential Verification (Password/Hash Check)
    ↓
Authentication Result (Success/Failure)
    ↓
Token Generation (JWT/ULID)
    ↓
Session Creation
    ↓
Audit Log Entry
```

### Multi-Factor Authentication Lineage

```
Primary Auth Success
    ↓
MFA Challenge Generation
    ↓
MFA Method Selection (TOTP/SMS/Email)
    ↓
MFA Code Delivery
    ↓
MFA Verification
    ↓
Secondary Auth Result
```

---

## API Key Authentication Lineage

The ULID-based dual key authentication system introduces additional lineage paths:

```
API Key Creation
    ↓
Key Hash Storage (bcrypt/scrypt)
    ↓
Key ID Distribution (readable, non-secret)
    ↓
Key Secret Verification (opaque, one-way)
    ↓
Access Token Generation
    ↓
Request Authentication
```

---

## Trace Correlation

Each authentication event captures:
- **traceId**: Full request correlation ID
- **authMethod**: Credential type used (password/api-key/jwt/session)
- **tenantId**: Tenant context for multi-tenant isolation
- **userId**: Target user identifier
- **ipAddress**: Source IP for geo-location and anomaly detection
- **userAgent**: Client identification for device fingerprinting

---

## Security Considerations

Auth lineage directly supports:
- Credential stuffing detection through failed auth pattern analysis
- Privileged access monitoring for compliance audits
- Session hijacking detection via geographic anomaly flagging
- API key abuse identification through usage pattern tracking

---

## Incident Reconstruction

During security incidents, auth lineage enables:
1. Timeline reconstruction of account compromise
2. Identification of all active sessions at breach time
3. Scope determination for credential rotation requirements
4. Attribution of unauthorized access attempts

---

## Related Documents

- `15-runtime-lineage/request-lineage.md` - Overall request tracking
- `15-runtime-lineage/delivery-lineage.md` - Provider delivery lineage
- `10-security/authentication.md` - Authentication architecture