# API Authentication

## Metadata
```yaml
title: API Authentication
domain: api
criticality: CRITICAL
security-impact: CRITICAL
ai-ingestable: true
```

---

## Overview

All authenticated endpoints require valid credentials. Tenant context derived from credentials, NOT from headers.

---

## Authentication Methods

### 1. Bearer Token (JWT)

```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

Validates RS256 signature, expiration, issuer, audience.

### 2. API Key (ULID)

```http
Authorization: Bearer uF01ARJHbn1YWMgx1x2Example
```

Validates ULID format, HMAC signature, status.

### 3. API Key (Alternate Header)

```http
X-API-Key: sF01ARJHbn1YWMgx1x2HMAC44Signature
```

### 4. Session Token

```http
X-Session-Token: session-uuid-here
```

Validates in Redis, checks expiration.

---

## Auth Priority

1. API Key `tenantId` (highest priority)
2. JWT `tid` claim
3. Session `tenantId`

---

## Response Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 401 | Invalid/missing credentials |
| 429 | Rate limit exceeded |

