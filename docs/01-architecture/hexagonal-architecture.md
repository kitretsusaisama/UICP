# Hexagonal Architecture

## Metadata
```yaml
title: Hexagonal Architecture
domain: architecture
owner: Architecture Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: MEDIUM
queue-impact: LOW
provider-impact: LOW
tenant-impact: LOW
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - domain-driven-design.md
related-docs:
  - system-architecture.md
  - dependency-model.md
related-services:
  - api-gateway
  - all-domain-services
```

---

## Overview

UICP follows hexagonal (ports and adapters) architecture to separate business logic from infrastructure concerns. This enables testability, flexibility, and maintainability.

---

## Layer Structure

### Domain Layer (Core)

The innermost layer contains business logic independent of any framework or infrastructure.

**Components:**
- Entities: Tenant, User, ApiKey, Session
- Value Objects: ApiKeyFormat, TenantId, UserId
- Domain Services: Business rules, invariants
- Repository Interfaces: Ports for data access

```typescript
// Example: Repository Interface (Port)
interface IUserRepository {
  findById(id: UserId): Promise<User | null>;
  findByTenant(tenantId: TenantId): Promise<User[]>;
  save(user: User): Promise<void>;
  delete(id: UserId): Promise<void>;
}
```

### Application Layer

Coordinates domain objects and orchestrates use cases. Contains command and query handlers following CQRS pattern.

**Components:**
- Command Handlers: Process write operations
- Query Handlers: Process read operations
- Application Services: Orchestration logic
- Port Interfaces: Driven ports (cache, email, queue)

```typescript
// Example: Driven Port Interface
interface IEmailProvider {
  sendEmail(to: string, subject: string, body: string): Promise<EmailResult>;
  sendBatch(emails: EmailRequest[]): Promise<BatchResult>;
}
```

### Infrastructure Layer (Adapters)

Implements the port interfaces defined in inner layers. Adapters connect to external systems.

**Adapters:**
- MySQL User Repository: Implements IUserRepository
- Redis Cache Adapter: Implements ICachePort
- SendGrid Adapter: Implements IEmailProvider
- BullMQ Adapter: Implements IQueuePort

---

## Dependency Rule

Dependencies point inward only. Domain layer has zero dependencies on outer layers. Application layer depends on domain, not infrastructure.

```
┌─────────────────────────────────────────────┐
│            Infrastructure Layer             │
│  (MySQL, Redis, BullMQ, SendGrid, Twilio)   │
└─────────────────────┬───────────────────────┘
                      │ implements
┌─────────────────────┴───────────────────────┐
│            Application Layer                 │
│         (Commands, Queries, Services)       │
└─────────────────────┬───────────────────────┘
                      │ depends on
┌─────────────────────┴───────────────────────┐
│              Domain Layer                    │
│        (Entities, Services, Ports)           │
└─────────────────────────────────────────────┘
```

---

## Port Types

### Driven Ports (Primary)

Define what the application can do. Implemented by infrastructure.

```typescript
// Driven port - infrastructure implements this
interface IQueuePort {
  enqueue(job: QueueJob): Promise<string>;
  dequeue(queue: string): Promise<QueueJob | null>;
  getStatus(jobId: string): Promise<JobStatus>;
}
```

### Driving Ports (Secondary)

Define how the application is invoked. Implemented by application layer.

```typescript
// Driving port - application implements this
interface ITenantService {
  resolveTenant(credential: Credential): Promise<TenantContext>;
  validateTenantAccess(tenantId: TenantId, userId: UserId): Promise<boolean>;
}
```

---

## Benefits for UICP

### Testability

Domain logic tested in isolation without infrastructure. Mock adapters replace real implementations.

### Flexibility

Infrastructure components swapped without changing business logic. Example: switch from SendGrid to AWS SES by implementing new adapter.

### Maintainability

Clear boundaries between concerns. Changes in infrastructure don't ripple to domain logic.

---

## Implementation in NestJS

NestJS modules align with hexagonal architecture:

- **DomainModule**: Entities, interfaces, services (imports nothing)
- **ApplicationModule**: Commands, queries, use cases (imports DomainModule)
- **InfrastructureModule**: Adapters, repositories (imports ApplicationModule, implements ports)

---

## Related Documents

- `system-architecture.md`
- `domain-driven-design.md`
- `dependency-model.md`