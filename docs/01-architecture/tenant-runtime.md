# Tenant Runtime

## Metadata
```yaml
title: Tenant Runtime
domain: tenant-management
owner: Platform Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: CRITICAL
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - domain-resolution.md
  - runtime-context.md
related-docs:
  - domain-driven-design.md
  - trust-boundaries.md
```

---

## Overview

The tenant runtime enforces multi-tenant isolation at every layer. Each tenant operates in its own logical boundary with dedicated quotas, configurations, and security policies.

---

## Tenant Model

### Entity Structure

```typescript
interface Tenant {
  // Identity
  id: TenantId;           // ULID
  name: string;
  domain?: string;       // Custom domain for tenant

  // Configuration
  plan: TenantPlan;      // free, starter, growth, enterprise
  status: TenantStatus; // active, suspended, terminated

  // Limits
  quota: TenantQuota;
  settings: TenantSettings;

  // Billing
  billingEmail: string;
  stripeCustomerId?: string;

  // Metadata
  createdAt: Date;
  updatedAt: Date;
}

interface TenantQuota {
  // Rate limits
  requestsPerMinute: number;
  requestsPerDay: number;

  // Storage
  storageMb: number;

  // Usage
  emailLimit: number;
  smsLimit: number;
  webhookLimit: number;

  // Features
  maxUsers: number;
  maxApiKeys: number;
  customDomains: number;
}
```

---

## Isolation Mechanisms

### Data Isolation

All queries include tenant ID filter:

```typescript
class TenantAwareRepository<T> {
  async findByTenant(tenantId: TenantId): Promise<T[]> {
    return this.repository.find({
      where: { tenantId },
    });
  }

  async save(entity: T & { tenantId: TenantId }): Promise<T> {
    // Enforce tenant ID cannot be changed
    return this.repository.save(entity);
  }
}
```

### Cache Isolation

Redis keys namespace by tenant:

```typescript
function getCacheKey(tenantId: TenantId, key: string): string {
  return `tenant:${tenantId}:${key}`;
}

// Examples:
// tenant:01ARZ3NDEKTSV4RRFFQ69G7FAK:session:abc123
// tenant:01ARZ3NDEKTSV4RRFFQ69G7FAK:ratelimit:api-key-xyz
// tenant:01ARZ3NDEKTSV4RRFFQ69G7FAK:cache:users
```

### Queue Isolation

Jobs include tenant ID for isolation:

```typescript
await this.queue.add('send-email', {
  // Job data
  to: 'user@example.com',
  subject: 'Welcome',
  // Tenant context (CRITICAL)
  tenantId: context.tenantId,
  tenantQuota: context.quota,
}, {
  // Queue options
  removeOnComplete: true,
  removeOnFail: false,
  // Rate limit by tenant
  limits: {
    maxJobsPerSecond: context.rateLimit.emailPerSecond,
  },
});
```

---

## Quota Enforcement

### Request Quota

```typescript
async function checkQuota(tenantId: TenantId, operation: string): Promise<void> {
  const tenant = await this.tenantRepository.findById(tenantId);

  // Check per-minute rate limit
  const minKey = `quota:${tenantId}:minute:${operation}`;
  const minCurrent = await this.redis.incr(minKey);
  if (minCurrent === 1) {
    await this.redis.expire(minKey, 60);
  }
  if (minCurrent > tenant.quota.requestsPerMinute) {
    throw new TooManyRequestsException('Minute quota exceeded');
  }

  // Check per-day limit
  const dayKey = `quota:${tenantId}:day:${operation}`;
  const dayCurrent = await this.redis.incr(dayKey);
  if (dayCurrent === 1) {
    await this.redis.expire(dayKey, 86400);
  }
  if (dayCurrent > tenant.quota.requestsPerDay) {
    throw new TooManyRequestsException('Daily quota exceeded');
  }
}
```

### Usage Tracking

```typescript
async function trackUsage(tenantId: TenantId, operation: string, count: number = 1): Promise<void> {
  const tenant = await this.tenantRepository.findById(tenantId);

  // Increment usage counters
  await this.redis.incrby(`usage:${tenantId}:${operation}`, count);

  // Check if approaching limit
  const currentUsage = await this.redis.get(`usage:${tenantId}:${operation}`);
  const limit = tenant.quota[`${operation}Limit` as keyof TenantQuota] as number;

  if (currentUsage >= limit * 0.9) {
    // Send warning at 90%
    await this.notification.send(tenantId, 'quota_warning', {
      operation,
      current: currentUsage,
      limit,
    });
  }
}
```

---

## Tenant Lifecycle

### Creation

```typescript
async function createTenant(input: CreateTenantInput): Promise<Tenant> {
  // 1. Validate domain availability
  if (input.domain) {
    const exists = await this.tenantRepository.findByDomain(input.domain);
    if (exists) {
      throw new ConflictException('Domain already taken');
    }
  }

  // 2. Create tenant with default quota
  const tenant = await this.tenantRepository.save({
    id: ulid(),
    name: input.name,
    domain: input.domain,
    plan: 'free',
    status: 'active',
    quota: getDefaultQuota('free'),
    settings: getDefaultSettings(),
    createdAt: new Date(),
  });

  // 3. Emit domain event
  this.eventEmitter.emit('tenant.created', { tenantId: tenant.id });

  return tenant;
}
```

### Suspension

```typescript
async function suspendTenant(tenantId: TenantId, reason: string): Promise<void> {
  // 1. Update status
  await this.tenantRepository.update(tenantId, { status: 'suspended' });

  // 2. Revoke all API keys
  await this.apiKeyRepository.updateMany(tenantId, { status: 'suspended' });

  // 3. Invalidate all sessions
  await this.redis.del(`tenant:${tenantId}:session:*`);

  // 4. Stop accepting new requests
  await this.redis.set(`tenant:${tenantId}:suspended`, '1');

  // 5. Log event
  await this.auditLog.log({
    action: 'tenant.suspended',
    tenantId,
    reason,
    timestamp: new Date(),
  });
}
```

---

## Tenant Settings

### Configurable Options

```typescript
interface TenantSettings {
  // Security
  mfaRequired: boolean;
  ipAllowlistEnabled: boolean;
  allowedIpRanges: string[];

  // Notifications
  emailNotificationEmail: string;
  slackWebhookUrl?: string;

  // Branding
  logoUrl?: string;
  primaryColor?: string;

  // Webhooks
  webhookUrl?: string;
  webhookEvents: string[];

  // Advanced
  customDomain?: string;
  ssoEnabled: boolean;
  ssoProvider?: string;
}
```

---

## Related Documents

- `domain-resolution.md`
- `runtime-context.md`
- `trust-boundaries.md`
- `domain-driven-design.md`