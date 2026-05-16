# Domain-Driven Design

## Metadata
```yaml
title: Domain-Driven Design
domain: architecture
owner: Architecture Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: MEDIUM
queue-impact: LOW
provider-impact: LOW
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - hexagonal-architecture.md
related-docs:
  - system-architecture.md
  - domain-resolution.md
  - tenant-runtime.md
```

---

## Overview

UICP applies Domain-Driven Design (DDD) principles to model business concepts accurately. The domain layer encapsulates business rules, ensuring the system reflects real-world behavior of communication platforms.

---

## Bounded Contexts

### Authentication Context

Manages credentials, sessions, and authentication flows.

**Entities:**
- ApiKey: ULID-based credentials with HMAC validation
- Session: Token-based authentication state
- User: Identity and access rights

**Value Objects:**
- ApiKeyFormat: Parsed key structure (prefix, ULID, HMAC)
- TenantId: Multi-tenant isolation boundary
- Credential: JWT, API key, or session token

### Communication Context

Handles message delivery across providers.

**Entities:**
- Message: Email, SMS, or webhook content
- ProviderConfig: Provider settings and credentials
- DeliveryAttempt: Tracking for each delivery try

**Value Objects:**
- ProviderResponse: Provider-specific response
- DeliveryStatus: Pending, sent, failed, bounced

### Tenant Context

Manages tenant configuration and isolation.

**Entities:**
- Tenant: Tenant configuration and settings
- TenantUser: User association with tenant
- TenantQuota: Usage limits and billing

---

## Aggregate Roots

### ApiKey Aggregate

```typescript
class ApiKey {
  // Aggregate root
  private id: ApiKeyId;
  private tenantId: TenantId;
  private name: string;
  private scopes: ApiKeyScope[];
  private status: ApiKeyStatus;

  // Business rules
  validate(): boolean; // Enforces key constraints
  canAccess(operation: string): boolean; // Scope check
  isExpired(): boolean; // Expiration check
  isActive(): boolean; // Status check
}
```

### Tenant Aggregate

```typescript
class Tenant {
  // Aggregate root
  private id: TenantId;
  private name: string;
  private plan: TenantPlan;
  private settings: TenantSettings;

  // Business rules
  addUser(user: User): TenantUser; // User association
  withinQuota(usage: Usage): boolean; // Quota check
  canUseFeature(feature: string): boolean; // Feature flag
}
```

---

## Domain Services

Domain services contain business logic that doesn't naturally fit within entities.

```typescript
class ApiKeyValidationService {
  validateKeyFormat(key: string): ApiKeyParseResult;
  verifyHmac(key: string, secret: string): boolean;
  extractTenantId(key: string): TenantId;
}

class TenantResolutionService {
  resolveFromCredential(credential: Credential): TenantContext;
  validateTenantAccess(tenantId: TenantId, userId: UserId): boolean;
}
```

---

## Repository Interfaces

Ports defined in domain layer for data access:

```typescript
interface IApiKeyRepository {
  findById(id: ApiKeyId): Promise<ApiKey | null>;
  findByTenant(tenantId: TenantId): Promise<ApiKey[]>;
  findByKey(key: string): Promise<ApiKey | null>;
  save(apiKey: ApiKey): Promise<void>;
  update(apiKey: ApiKey): Promise<void>;
  delete(id: ApiKeyId): Promise<void>;
}

interface ITenantRepository {
  findById(id: TenantId): Promise<Tenant | null>;
  findByDomain(domain: string): Promise<Tenant | null>;
  save(tenant: Tenant): Promise<void>;
  update(tenant: Tenant): Promise<void>;
}
```

---

## Domain Events

Domain events capture significant occurrences:

```typescript
class ApiKeyCreatedEvent {
  tenantId: TenantId;
  keyId: ApiKeyId;
  keyName: string;
  timestamp: Date;
}

class TenantQuotaExceededEvent {
  tenantId: TenantId;
  quotaType: string;
  currentUsage: number;
  limit: number;
  timestamp: Date;
}
```

---

## Invariants

Business rules that must always hold:

1. **Tenant Isolation**: Every entity belongs to exactly one tenant
2. **Key Uniqueness**: No two API keys have the same key value
3. **Credential Binding**: Sessions always linked to authenticated user
4. **Quota Enforcement**: Usage cannot exceed tenant quota

---

## Related Documents

- `hexagonal-architecture.md`
- `domain-resolution.md`
- `tenant-runtime.md`
- `api-key-runtime.md`