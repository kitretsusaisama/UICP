# Domain Resolution

## Metadata
```yaml
title: Domain Resolution
domain: tenant-management
owner: Security Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: LOW
provider-impact: LOW
tenant-impact: CRITICAL
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - api-key-runtime.md
  - runtime-context.md
related-docs:
  - ADR-002-domain-resolution.md
  - tenant-runtime.md
```

---

## Overview

Domain resolution maps incoming requests to tenant context. UICP uses credential-based resolution—the tenant ID comes from the authenticated credential, not from HTTP headers. This enforces zero-trust security.

---

## Resolution Strategy

### Priority Order

UICP resolves tenant context in this priority order:

1. **API Key** → tenantId embedded in key
2. **JWT** → tenantId from `tid` claim
3. **Session** → tenantId from session data

No header fallback for authenticated endpoints. This prevents header injection attacks.

### Resolution Flow

```
Request arrives
     ↓
Extract credential (Authorization header / X-API-Key / X-Session-Token)
     ↓
Detect credential type
     ↓
[API Key] → Parse format → Validate HMAC → Lookup key → Extract tenantId
[JWT]     → Verify signature → Extract tid claim → Validate tenant exists
[Session]→ Validate token → Lookup session → Extract tenantId
     ↓
Build TenantContext
     ↓
Attach to request
     ↓
Continue to controller
```

---

## API Key Resolution

### Key Parsing

```typescript
function parseApiKey(key: string): ApiKeyParsed {
  const prefix = key.slice(0, 2);
  const ulid = key.slice(2, 28);
  const hmac = key.length > 28 ? key.slice(28) : null;

  // Validate format
  if (!VALID_PREFIXES.includes(prefix)) {
    throw new BadRequestException('Invalid key prefix');
  }

  if (!isValidUlid(ulid)) {
    throw new BadRequestException('Invalid key format');
  }

  return { prefix, ulid, hmac };
}
```

### Key Lookup and Tenant Extraction

```typescript
async function resolveFromApiKey(key: string): Promise<TenantContext> {
  // 1. Parse key
  const parsed = parseApiKey(key);

  // 2. Validate HMAC if secret key
  if (parsed.hmac) {
    const valid = await verifyHmac(parsed.ulid, parsed.hmac);
    if (!valid) throw new UnauthorizedException('Invalid signature');
  }

  // 3. Lookup key in repository
  const apiKey = await this.apiKeyRepository.findByKey(key);
  if (!apiKey || apiKey.status !== 'active') {
    throw new UnauthorizedException('Invalid or inactive key');
  }

  // 4. Extract tenant from key record
  return {
    tenantId: apiKey.tenantId,
    userId: apiKey.userId,
    permissions: apiKey.permissions,
    scopes: apiKey.scopes,
    authMethod: 'API_KEY',
    rateLimit: apiKey.rateLimit,
  };
}
```

---

## JWT Resolution

### Claim Extraction

```typescript
async function resolveFromJwt(token: string): Promise<TenantContext> {
  // 1. Verify JWT signature
  const payload = await this.jwtService.verify(token);

  // 2. Validate required claims
  if (!payload.tid) {
    throw new UnauthorizedException('Missing tenant claim (tid)');
  }

  if (!payload.sub) {
    throw new UnauthorizedException('Missing subject claim (sub)');
  }

  // 3. Validate tenant exists and is active
  const tenant = await this.tenantRepository.findById(payload.tid);
  if (!tenant || tenant.status !== 'active') {
    throw new UnauthorizedException('Invalid tenant');
  }

  // 4. Build context
  return {
    tenantId: payload.tid,
    userId: payload.sub,
    permissions: payload.permissions || [],
    authMethod: 'JWT',
    tokenIssuedAt: new Date(payload.iat * 1000),
  };
}
```

### Token Claims Structure

```typescript
interface JwtPayload {
  // Required
  sub: string;        // User ID
  tid: string;       // Tenant ID
  iat: number;       // Issued at
  exp: number;       // Expiration

  // Optional
  permissions?: string[];
  scopes?: string[];
  roles?: string[];
}
```

---

## Session Resolution

### Session Validation

```typescript
async function resolveFromSession(token: string): Promise<TenantContext> {
  // 1. Lookup session in Redis
  const sessionData = await this.redis.get(`session:${token}`);
  if (!sessionData) {
    throw new UnauthorizedException('Invalid session');
  }

  // 2. Parse session
  const session = JSON.parse(sessionData);

  // 3. Validate not expired
  if (session.expiresAt < Date.now()) {
    throw new UnauthorizedException('Session expired');
  }

  // 4. Validate tenant still active
  const tenant = await this.tenantRepository.findById(session.tenantId);
  if (!tenant || tenant.status !== 'active') {
    throw new UnauthorizedException('Tenant not active');
  }

  // 5. Build context
  return {
    tenantId: session.tenantId,
    userId: session.userId,
    permissions: session.permissions,
    authMethod: 'SESSION',
    sessionId: session.sessionId,
  };
}
```

---

## Security Considerations

### Header Injection Prevention

Since tenant is extracted from credential, not header, attackers cannot inject fake tenant IDs:

```typescript
// ❌ BAD: Trust header
const tenantId = request.headers['x-tenant-id'];

// ✅ GOOD: Extract from credential
const tenantId = credential.tenantId;
```

### Environment Enforcement

Dev credentials rejected in production:

```typescript
function validateEnvironment(prefix: string, currentEnv: string): void {
  const isDevPrefix = ['pB', 'tB'].includes(prefix);
  const isProdEnv = currentEnv === 'production';

  if (isDevPrefix && isProdEnv) {
    throw new ForbiddenException('Dev keys not allowed in production');
  }

  const isLivePrefix = ['uF', 'sF'].includes(prefix);
  const isDevEnv = currentEnv === 'development';

  if (isLivePrefix && isDevEnv) {
    throw new ForbiddenException('Live keys not allowed in development');
  }
}
```

---

## Related Documents

- `api-key-runtime.md`
- `runtime-context.md`
- `tenant-runtime.md`
- `ADR-002-domain-resolution.md`