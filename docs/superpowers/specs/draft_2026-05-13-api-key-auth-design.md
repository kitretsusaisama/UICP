# API Key Authentication Design

## Overview

Production-ready, MNC-grade API key authentication system using ULID-based dual keys with O(1) Redis validation. Replaces tenant-id header with secure API key authentication.

## Key Format

### Structure

| Type | Format | Length |
|------|--------|--------|
| Live Publishable | `uF` + ULID26 + `xl` | 28 chars |
| Live Secret | `sF` + ULID26 + HMAC44 | 70 chars |
| Dev Publishable | `pB` + ULID26 | 28 chars |
| Dev Secret | `tB` + ULID26 + HMAC44 | 70 chars |

### Prefix Encoding

- `uF` = Live publishable (u = publishable, F = live/fixed)
- `pB` = Dev publishable (p = publishable, B = beta/dev)
- `sF` = Live secret (s = secret, F = live)
- `tB` = Dev secret (t = secret, B = beta/dev)

### HMAC Signature

Secret keys include embedded HMAC-SHA256 signature for zero-DB validation:
```
signature = HMAC-SHA256(ulid + tenantId + secretKeyId, serverSecret)
```

## Data Flow

```
1. Request arrives: Authorization: Bearer {apiKey}
2. Parse first 2 chars → determine env/type
3. Extract ULID (chars 3-28)
4. Redis GET: api_key:{ulid} → cache miss? → DB fallback
5. Validate HMAC signature (for secret keys)
6. Check IP allowlist, rate limit, expiration
7. Inject tenant context into request
```

## Redis Data Model

```json
{
  "api_key:01ARZ3NDEKTSV4RRFFQ69G1FAV": {
    "tenantId": "tenant_abc123",
    "type": "secret",
    "env": "live",
    "scopes": ["read", "write", "admin"],
    "ipAllowlist": ["10.0.0.0/8"],
    "rateLimit": 1000,
    "createdAt": 1705123456000,
    "expiresAt": 1710455456000,
    "metadata": { "name": "Production Key" }
  }
}
```

## Components

| Component | File | Responsibility |
|-----------|------|----------------|
| ApiKeyService | `src/application/services/api-key.service.ts` | CRUD, generation, rotation |
| ApiKeyGuard | `src/interface/http/guards/api-key.guard.ts` | Route protection |
| ApiKeyInterceptor | `src/interface/http/interceptors/api-key.interceptor.ts` | Tenant context injection |
| ApiKeyRepository | `src/infrastructure/db/mysql/mysql-api-key.repository.ts` | Persistence |

## Security Features

1. **Zero-DB validation** - HMAC in key validates without Redis/DB
2. **IP allowlist per key** - CIDR notation with CIDR-block matching
3. **Rate limit per key** - Independent of tenant quota
4. **Instant revocation** - Redis pub/sub invalidation
5. **Auto-rotation** - 90-day expiry, grace period for migration
6. **Audit logging** - All key operations tracked

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/api-keys` | Create new key pair |
| GET | `/v1/api-keys` | List keys for tenant |
| GET | `/v1/api-keys/:id` | Get key details |
| POST | `/v1/api-keys/:id/rotate` | Rotate key |
| DELETE | `/v1/api-keys/:id` | Revoke key |

## Migration Path

1. Add `ApiKeyGuard` alongside existing tenant-id guard
2. Support both authentication methods during transition
3. Deprecate x-tenant-id header after migration
4. Remove legacy tenant-id logic in v2.0

## Performance Targets

- Key validation: < 1ms (p99)
- Redis lookup: < 0.5ms (p99)
- HMAC verification: < 0.1ms