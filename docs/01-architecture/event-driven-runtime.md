# Event-Driven Runtime

## Metadata
```yaml
title: Event-Driven Runtime
domain: runtime
owner: Runtime Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-first-design.md
  - replay-safe-design.md
related-docs:
  - runtime-summary.md
  - communication-fabric.md
  - orchestration-model.md
related-queues:
  - email-delivery
  - sms-delivery
  - webhook-processing
  - audit-logging
related-runtime-states:
  - running
  - degraded
  - recovering
```

---

## Overview

UICP uses an event-driven runtime model where operations are modeled as events that flow through the system. This enables loose coupling, horizontal scaling, and resilience.

---

## Event Types

### Domain Events

Business events that represent meaningful occurrences in the domain:

```typescript
// Domain events
class ApiKeyCreatedEvent {
  eventType: 'API_KEY_CREATED';
  tenantId: TenantId;
  keyId: ApiKeyId;
  timestamp: Date;
}

class MessageSentEvent {
  eventType: 'MESSAGE_SENT';
  messageId: MessageId;
  provider: ProviderType;
  timestamp: Date;
}

class SessionCreatedEvent {
  eventType: 'SESSION_CREATED';
  tenantId: TenantId;
  userId: UserId;
  sessionId: SessionId;
  timestamp: Date;
}
```

### Integration Events

Events that communicate between services or with external systems:

```typescript
// Integration events
class ProviderDeliveryEvent {
  eventType: 'PROVIDER_DELIVERY';
  provider: ProviderType;
  messageId: MessageId;
  status: DeliveryStatus;
  timestamp: Date;
}

class TenantConfigChangedEvent {
  eventType: 'TENANT_CONFIG_CHANGED';
  tenantId: TenantId;
  changes: ConfigChange[];
  timestamp: Date;
}
```

---

## Event Flow

### Synchronous Event Flow

For operations requiring immediate response:

```
1. Client sends request
2. API Gateway validates credential
3. Domain service processes command
4. Domain event emitted
5. Event handler updates state
6. Response returned to client
```

### Asynchronous Event Flow

For operations requiring guaranteed delivery:

```
1. Client sends request
2. API Gateway validates, enqueues job
3. Worker picks up job
4. Provider router selects provider
5. External provider called
6. Delivery event emitted
7. Event store records lineage
```

---

## Event Processing

### At-Least-Once Delivery

Queue workers process jobs with retry logic. Jobs may be processed multiple times if failures occur between processing and acknowledgment.

**Retry Configuration:**
- **otp-fastlane**: 1x immediate retry
- **email-delivery**: 3x exponential backoff
- **sms-delivery**: 3x exponential backoff
- **webhook-processing**: 5x linear backoff

### Event Ordering

Within a tenant, events are processed in order. Across tenants, events process in parallel for throughput.

---

## Event Store

The event store maintains an immutable log of all events for auditing and replay capability:

```typescript
interface IEventStore {
  append(event: DomainEvent): Promise<void>;
  getEvents(aggregateId: string): Promise<DomainEvent[]>;
  getEventsByType(type: string, from: Date): Promise<DomainEvent[]>;
  getEventsByTenant(tenantId: TenantId): Promise<DomainEvent[]>;
}
```

**Event Store Schema:**
- event_id: Unique identifier
- aggregate_id: Entity the event relates to
- event_type: Type of event
- payload: Event data (JSON)
- tenant_id: Tenant context
- timestamp: When event occurred
- metadata: Correlation IDs, tracing

---

## Event Handlers

Handlers react to events and perform side effects:

```typescript
class AuditEventHandler {
  @OnEvent('API_KEY_CREATED')
  async handleApiKeyCreated(event: ApiKeyCreatedEvent) {
    await this.auditLog.log({
      action: 'api_key.created',
      tenantId: event.tenantId,
      keyId: event.keyId,
      timestamp: event.timestamp,
    });
  }

  @OnEvent('MESSAGE_SENT')
  async handleMessageSent(event: MessageSentEvent) {
    await this.metrics.increment('messages.sent', {
      provider: event.provider,
    });
  }
}
```

---

## Benefits

### Loose Coupling

Services communicate through events, not direct calls. Services can be added, removed, or scaled independently.

### Scalability

Event processing scales horizontally. More workers process more events without changing producer code.

### Resilience

Events can be replayed after failures. The event store provides an immutable record for recovery.

### Observability

Events provide a complete audit trail. Every action recorded with tenant context and timestamp.

---

## Related Documents

- `queue-first-design.md`
- `replay-safe-design.md`
- `communication-fabric.md`
- `02-runtime/request-lifecycle.md`