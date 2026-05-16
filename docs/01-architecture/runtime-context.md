# Runtime Context

## Metadata
```yaml
title: Runtime Context
domain: security
owner: Security Team
criticality: CRITICAL
runtime-impact: CRITICAL
security-impact: CRITICAL
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: CRITICAL
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - api-key-runtime.md
  - domain-resolution.md
  - trust-boundaries.md
related-docs:
  - runtime-summary.md
  - zero-trust-model.md
  - api-key-auth-design.md
related-queues:
  - all-queues
related-services:
  - api-gateway
  - all-services
related-runtime-states:
  - starting
  - running
  - degraded
```

---

## Overview

Runtime context is the tenant, user, and permission information attached to every request. UICP enforces zero-trust by extracting context from credentials, never from headers.

---

## Context Structure

### TenantContext

```typescript
interface TenantContext {
  // Core identifiers
  tenantId: TenantId;        // CRITICAL: Isolates tenant data
  userId?: UserId;            // Optional: Authenticated user
  identityId?: IdentityId;    // Optional: External identity

  // Permission data
  permissions: Permission[]; // What the principal can do
  scopes: ApiKeyScope[];     // API key scopes (if key auth)

  // Security metadata
  authMethod: AuthMethod;    // How authenticated (API_KEY, JWT, SESSION)
  sessionId?: SessionId;      // Session identifier
  tokenIssuedAt: Date;        // When credential was issued

  // Rate limiting
  rateLimit: RateLimitConfig;
  quota: QuotaConfig;
}
```

### Request Context Flow

```
Request arrives
     ↓
Extract credential (Bearer / X-API-Key / X-Session-Token)
     ↓
Detect auth method (JWT / API_KEY / SESSION / INTERNAL_SERVICE)
     ↓
Validate credential (signature / HMAC / token lookup)
     ↓
Extract tenantId from credential (NOT from header!)
     ↓
Build TenantContext
     ↓
Attach to request (NestJS Request object)
     ↓
Controller/Service accesses context
```

---

## Context Extraction Methods

### From API Key

```typescript
async function extractFromApiKey(key: string): Promise<TenantContext> {
  // 1. Parse key format
  const parsed = parseApiKey(key); // { prefix, ulid, hmac? }

  // 2. Validate HMAC (if secret key)
  if (parsed.hmac) {
    const valid = await verifyHmac(key, parsed.hmac);
    if (!valid) throw new UnauthorizedException('Invalid signature');
  }

  // 3. Look up key in repository
  const apiKey = await this.apiKeyRepository.findByKey(key);
  if (!apiKey || !apiKey.isActive()) {
    throw new UnauthorizedException('Invalid key');
  }

  // 4. Extract tenant context from key record
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

### From JWT

```typescript
async function extractFromJwt(token: string): Promise<TenantContext> {
  // 1. Verify JWT signature
  const payload = await this.jwtService.verify(token);

  // 2. Extract tenant ID from `tid` claim
  const tenantId = payload.tid;
  if (!tenantId) {
    throw new UnauthorizedException('Missing tenant claim');
  }

  // 3. Validate tenant exists
  const tenant = await this.tenantRepository.findById(tenantId);
  if (!tenant) {
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

### From Session

```typescript
async function extractFromSession(token: string): Promise<TenantContext> {
  // 1. Look up session in Redis
  const session = await this.redis.get(`session:${token}`);
  if (!session) {
    throw new UnauthorizedException('Invalid session');
  }

  // 2. Parse session data
  const data = JSON.parse(session);

  // 3. Validate session not expired
  if (data.expiresAt < Date.now()) {
    throw new UnauthorizedException('Session expired');
  }

  // 4. Build context
  return {
    tenantId: data.tenantId,
    userId: data.userId,
    permissions: data.permissions,
    authMethod: 'SESSION',
    sessionId: data.sessionId,
  };
}
```

---

## Context Propagation

### HTTP Context

In NestJS, context attached to request object:

```typescript
@Controller()
export class MyController {
  @Get()
  getData(@Req() req: Request) {
    const context = req['tenantContext'] as TenantContext;
    // Use context.tenantId for data access
  }
}
```

### Queue Job Context

Context serialized into job data:

```typescript
await this.queueService.add('send-email', {
  // Job data
  to: 'user@example.com',

  // Context (CRITICAL for isolation)
  tenantId: context.tenantId,
  userId: context.userId,
  permissions: context.permissions,
});
```

### Event Context

Context included in domain events:

```typescript
class MessageSentEvent {
  tenantId: TenantId;
  messageId: MessageId;
  provider: ProviderType;
  timestamp: Date;
}
```

---

## Security Boundaries

### Context Validation Rules

1. **Tenant ID Required**: Every authenticated request must have tenant ID
2. **Credential Binding**: Tenant ID extracted from credential, never from header
3. **Permission Check**: Every operation validates against permissions
4. **Scope Enforcement**: API key operations check scopes

### Data Isolation

All database queries include tenant ID filter:

```typescript
async function findUsers(tenantId: TenantId): Promise<User[]> {
  return this.userRepository.find({
    where: { tenantId },
  });
}
```

---

## Related Documents

- `api-key-runtime.md`
- `domain-resolution.md`
- `trust-boundaries.md`
- `03-auth/auth-overview.md`