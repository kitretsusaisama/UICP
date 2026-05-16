# Runtime Invariants

## Metadata
```yaml
title: Runtime Invariants
domain: correctness
owner: Architecture Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: CRITICAL
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - domain-driven-design.md
  - trust-boundaries.md
  - replay-safe-design.md
related-docs:
  - system-architecture.md
  - runtime-summary.md
```

---

## Overview

Runtime invariants are properties that must always hold during execution. These are enforced through code, database constraints, and runtime checks. Violating an invariant indicates a bug or security issue.

---

## Tenant Isolation Invariants

### Invariant 1: Every Entity Has Tenant ID

```typescript
// All domain entities include tenant ID
abstract class TenantAwareEntity {
  abstract readonly tenantId: TenantId;
}

// Database constraint ensures no null tenant IDs
@Index(['tenantId'])
@Entity()
abstract class BaseEntity {
  @Column({ nullable: false })
  tenantId: TenantId;
}
```

**Enforcement:**
- Database NOT NULL constraint on tenantId column
- Application validates tenantId not null before save
- Query builders enforce tenantId filter

### Invariant 2: Queries Always Include Tenant Filter

```typescript
// Repository enforces tenant filter
class TenantAwareRepository<T extends TenantAwareEntity> {
  async findById(id: string, tenantId: TenantId): Promise<T | null> {
    return this.repository.findOne({
      where: { id, tenantId }, // ALWAYS include tenantId
    });
  }

  async findAll(tenantId: TenantId): Promise<T[]> {
    return this.repository.find({
      where: { tenantId }, // ALWAYS filter by tenantId
    });
  }
}
```

**Enforcement:**
- Code review requirement for tenant filter in all queries
- Automated tests verify tenant isolation
- Database query audit logs

---

## Authentication Invariants

### Invariant 3: Tenant Context Extracted from Credential

```typescript
// Never trust header for tenant ID
function getTenantId(request: Request): TenantId {
  // ❌ BAD: From header
  // const tenantId = request.headers['x-tenant-id'];

  // ✅ GOOD: From credential (validated in guard)
  const context = request['tenantContext'] as TenantContext;
  return context.tenantId;
}
```

**Enforcement:**
- UnifiedAuthGuard sets tenant context
- Controller receives pre-validated context
- No endpoint accepts tenant ID from headers

### Invariant 4: All Credentials Validated

```typescript
// Every request must have valid authentication
@UseGuards(UnifiedAuthGuard)
@Controller()
export class SecuredController {
  // All endpoints require auth guard
}
```

**Enforcement:**
- AuthGuard applied globally or per-controller
- No bypass mechanisms for authentication
- Invalid credentials always rejected with 401/403

---

## Data Consistency Invariants

### Invariant 5: Idempotency Keys Prevent Duplicates

```typescript
// Every mutation request must have idempotency key
async function handleRequest(request: MutationRequest): Promise<Response> {
  const key = request.idempotencyKey;

  // Check if already processed
  const exists = await this.idempotencyStore.exists(key);
  if (exists) {
    throw new ConflictException('Duplicate request');
  }

  // Process and mark as done
  const result = await this.process(request);
  await this.idempotencyStore.set(key, 'processed', { ttl: 86400 });

  return result;
}
```

**Enforcement:**
- All mutation endpoints require idempotency key
- Redis check before processing
- Duplicate requests return existing result

### Invariant 6: Transactions Are Atomic

```typescript
// Related operations in single transaction
async function createUserWithKey(input: CreateUserInput): Promise<void> {
  await this.dataSource.transaction(async (manager) => {
    // Both operations succeed or fail together
    await manager.save(User, user);
    await manager.save(ApiKey, apiKey);
  });
}
```

**Enforcement:**
- Database transactions for related operations
- Rollback on any failure
- No partial state visible to other transactions

---

## Security Invariants

### Invariant 7: API Key HMAC Cannot Be Forged

```typescript
// HMAC secret never exposed in logs or errors
function validateKey(key: string): boolean {
  const hmac = key.slice(28);
  const expected = crypto
    .createHmac('sha256', API_KEY_HMAC_SECRET) // Secret from env
    .update(key.slice(0, 28))
    .digest('base64')
    .slice(0, 44);

  return hmac === expected;
}
```

**Enforcement:**
- HMAC secret in environment variable only
- No logging of secret values
- Timing-safe comparison to prevent timing attacks

### Invariant 8: Sessions Bound to Tenant

```typescript
// Session always associated with specific tenant
async function createSession(userId: UserId, tenantId: TenantId): Promise<Session> {
  const session = await this.sessionRepository.save({
    userId,
    tenantId, // Always set
    // ... other properties
  });

  return session;
}
```

**Enforcement:**
- Database constraint ensures tenantId not null
- Session validation checks tenant matches request
- Cross-tenant session access blocked

---

## Queue Processing Invariants

### Invariant 9: Jobs Have Tenant Context

```typescript
// All queue jobs include tenant ID
await this.queue.add('process-message', {
  tenantId: context.tenantId, // CRITICAL
  userId: context.userId,
  data: messageData,
});
```

**Enforcement:**
- Job schema validates tenantId present
- Worker checks tenant context before processing
- DLQ for invalid tenant context jobs

### Invariant 10: Failed Jobs Move to DLQ

```typescript
// Jobs exhausted retries move to dead letter queue
async function handleJobFailure(job: Job, error: Error): Promise<void> {
  if (job.attemptsMade >= job.opts.attempts) {
    await job.moveToFailed(error);
    await this.alert.send('job_failed', { jobId: job.id, error: error.message });
  }
}
```

**Enforcement:**
- BullMQ configured with DLQ
- Monitoring for DLQ size
- Manual intervention required for DLQ jobs

---

## Rate Limiting Invariants

### Invariant 11: Rate Limits Cannot Be Bypassed

```typescript
// Rate limiting enforced before any processing
@UseGuards(RateLimitGuard)
@Controller()
export class LimitedController {
  // Rate limit checked first
}
```

**Enforcement:**
- Guard runs before controller logic
- Redis atomic operations for counters
- No way to disable rate limits per request

---

## Testing Invariants

### Invariant Tests

```typescript
// Test that tenant isolation always holds
it('should always filter by tenantId', async () => {
  // Create entities in different tenants
  const entity1 = await createEntity({ tenantId: 'tenant-1' });
  const entity2 = await createEntity({ tenantId: 'tenant-2' });

  // Query should only return tenant-1's entity
  const results = await repository.findByTenant('tenant-1');

  expect(results).toHaveLength(1);
  expect(results[0].id).toBe(entity1.id);
  expect(results[0].id).not.toBe(entity2.id);
});
```

---

## Related Documents

- `domain-driven-design.md`
- `trust-boundaries.md`
- `replay-safe-design.md`
- `system-architecture.md`