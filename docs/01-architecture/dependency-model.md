# Dependency Model

## Metadata
```yaml
title: Dependency Model
domain: architecture
owner: Architecture Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: MEDIUM
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: LOW
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - hexagonal-architecture.md
  - domain-driven-design.md
related-docs:
  - system-architecture.md
  - dependency-model.md
```

---

## Overview

The dependency model defines how components depend on each other. UICP follows clean architecture principles where dependencies point inward—domain has no infrastructure dependencies.

---

## Dependency Graph

### High-Level Dependencies

```
┌──────────────────────────────────────────────────────────────────┐
│                        HTTP Requests                              │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                      UnifiedAuthGuard                            │
│                   (Authentication, Tenant Context)                │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Controller/Handler                           │
│                  (Request/Response Handling)                      │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Application Services                          │
│                  (Business Logic Orchestration)                  │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
                     ┌─────────────┴─────────────┐
                     │                           │
                     ▼                           ▼
┌──────────────────────────────┐  ┌──────────────────────────────────┐
│        Domain Layer         │  │         Domain Services          │
│    (Entities, Value Objects)│  │    (Business Rules, Logic)      │
└──────────────┬───────────────┘  └──────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Port Interfaces                               │
│       (Repository, Cache, Queue, Email, SMS interfaces)          │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                  Infrastructure Adapters                        │
│     (MySQL, Redis, BullMQ, SendGrid, Twilio implementations)     │
└──────────────────────────────────────────────────────────────────┘
```

---

## Dependency Rules

### Rule 1: Domain Independence

The domain layer has zero dependencies on outer layers:

```typescript
// Domain entity - NO imports from infrastructure
export class ApiKey {
  private readonly id: ApiKeyId;
  private readonly tenantId: TenantId;
  private readonly scopes: ApiKeyScope[];

  // Business logic in domain
  canAccess(operation: Operation): boolean {
    return this.scopes.includes(operation.requiredScope);
  }
}
```

### Rule 2: Application Depends on Domain

```typescript
// Application service depends on domain, not implementation
export class ApiKeyService {
  constructor(
    private readonly apiKeyRepository: IApiKeyRepository, // Port, not adapter
    private readonly eventEmitter: EventEmitter2,
  ) {}

  async createKey(input: CreateApiKeyInput): Promise<ApiKey> {
    // Use domain entity
    const apiKey = new ApiKey({
      tenantId: input.tenantId,
      scopes: input.scopes,
      // ... other properties
    });

    // Validate using domain rules
    apiKey.validate();

    // Save through port (implemented by adapter)
    await this.apiKeyRepository.save(apiKey);

    // Emit domain event
    this.eventEmitter.emit('api-key.created', { apiKey });

    return apiKey;
  }
}
```

### Rule 3: Infrastructure Implements Ports

```typescript
// Infrastructure adapter implements port interface
@Injectable()
export class MySqlApiKeyRepository implements IApiKeyRepository {
  constructor(
    @InjectRepository(ApiKeyEntity)
    private readonly repository: Repository<ApiKeyEntity>,
  ) {}

  async findById(id: ApiKeyId): Promise<ApiKey | null> {
    const entity = await this.repository.findOne({ where: { id } });
    return entity ? this.mapToDomain(entity) : null;
  }

  async save(apiKey: ApiKey): Promise<void> {
    const entity = this.mapToEntity(apiKey);
    await this.repository.save(entity);
  }
}
```

---

## Port Definitions

### Driven Ports (Infrastructure Implements)

```typescript
// Cache port - implemented by Redis adapter
interface ICachePort {
  get<T>(key: string): Promise<T | null>;
  set(key: string, value: unknown, ttl?: number): Promise<void>;
  del(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
}

// Queue port - implemented by BullMQ adapter
interface IQueuePort {
  enqueue<T>(queue: string, data: T, options?: QueueOptions): Promise<string>;
  dequeue<T>(queue: string): Promise<Job<T> | null>;
  getJobStatus(jobId: string): Promise<JobStatus>;
}

// Email provider port - implemented by SendGrid, SES, etc.
interface IEmailProviderPort {
  sendEmail(request: EmailRequest): Promise<EmailResponse>;
  sendBatch(requests: EmailRequest[]): Promise<BatchResponse>;
  getHealth(): Promise<ProviderHealth>;
}
```

### Driving Ports (Application Implements)

```typescript
// Tenant service port - implemented by NestJS controller
interface ITenantServicePort {
  resolveTenant(credential: Credential): Promise<TenantContext>;
  validateAccess(tenantId: TenantId, userId: UserId): Promise<boolean>;
}

// Authentication port
interface IAuthPort {
  login(credentials: LoginCredentials): Promise<AuthResult>;
  logout(sessionId: SessionId): Promise<void>;
  validateToken(token: string): Promise<TokenPayload>;
}
```

---

## Module Dependencies

### NestJS Module Structure

```typescript
// Domain module - imports nothing
@Module({
  providers: [
    ApiKeyService,
    TenantService,
    // ... domain services
  ],
  exports: [
    ApiKeyService,
    TenantService,
  ],
})
export class DomainModule {}

// Application module - imports DomainModule
@Module({
  imports: [DomainModule],
  providers: [
    CreateApiKeyHandler,
    LoginHandler,
    // ... command/query handlers
  ],
  exports: [
    CreateApiKeyHandler,
  ],
})
export class ApplicationModule {}

// Infrastructure module - imports ApplicationModule
@Module({
  imports: [
    ApplicationModule,
    TypeOrmModule.forFeature([ApiKeyEntity]),
  ],
  providers: [
    MySqlApiKeyRepository,
    RedisCacheAdapter,
    BullMqQueueAdapter,
    SendGridEmailAdapter,
  ],
})
export class InfrastructureModule {}
```

---

## Dependency Injection

### Provider Resolution

```typescript
// Main module wires everything together
@Module({
  imports: [
    DomainModule,
    ApplicationModule,
    InfrastructureModule,
  ],
})
export class AppModule {}
```

---

## Related Documents

- `hexagonal-architecture.md`
- `domain-driven-design.md`
- `system-architecture.md`
- `hexagonal-architecture.md`