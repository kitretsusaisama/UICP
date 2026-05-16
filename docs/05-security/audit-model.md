# Audit Model

## Metadata
```yaml
title: Audit Model
domain: security
owner: Compliance Team
criticality: CRITICAL
runtime-impact: LOW
security-impact: CRITICAL
queue-impact: LOW
provider-impact: LOW
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/zero-trust-model.md
  - 05-security/incident-response.md
related-docs:
  - 05-security/threat-model.md
  - 15-runtime-lineage/request-lineage.md
related-queues: []
related-services:
  - AuditService
  - AuditLogger
  - AuditQueryService
related-runtime-states:
  - event-logged
  - event-queried
  - event-exported
```

---

## Executive Summary

The audit model ensures all security-relevant events are logged with sufficient detail for compliance, forensics, and monitoring. Audit logs are immutable and retained for 7 years.

---

## Audit Event Categories

### Authentication Events

| Event | Data Captured |
|-------|---------------|
| Login success | tenantId, userId, method, IP, timestamp |
| Login failure | tenantId, userId, method, reason, IP, timestamp |
| Logout | tenantId, userId, sessionId, timestamp |
| Token refresh | tenantId, userId, tokenId, timestamp |
| API key created | tenantId, keyId, permissions, createdBy, timestamp |
| API key revoked | tenantId, keyId, revokedBy, reason, timestamp |

### Authorization Events

| Event | Data Captured |
|-------|---------------|
| Access granted | tenantId, userId, resource, action, timestamp |
| Access denied | tenantId, userId, resource, action, reason, timestamp |
| Permission changed | tenantId, userId, oldPerms, newPerms, changedBy, timestamp |

### Data Events

| Event | Data Captured |
|-------|---------------|
| Data created | tenantId, userId, resourceType, resourceId, timestamp |
| Data modified | tenantId, userId, resourceType, resourceId, changes, timestamp |
| Data deleted | tenantId, userId, resourceType, resourceId, timestamp |

### Security Events

| Event | Data Captured |
|-------|---------------|
| Rate limit exceeded | tenantId, keyId, limit, current, timestamp |
| Suspicious activity | tenantId, userId, activityType, details, timestamp |
| Credential compromised | tenantId, keyId, detectionMethod, timestamp |
| Emergency revocation | tenantId, keyId, revokedBy, reason, timestamp |

---

## Log Structure

```typescript
interface AuditEvent {
  // Identity
  eventId: string;           // ULID
  eventType: string;        // AUTH_LOGIN_SUCCESS
  timestamp: string;        // ISO 8601

  // Context
  tenantId: string;
  userId?: string;
  sessionId?: string;
  apiKeyId?: string;

  // Request details
  ipAddress: string;
  userAgent?: string;
  endpoint?: string;
  method?: string;

  // Event data
  outcome: 'success' | 'failure' | 'denied';
  reason?: string;
  details: Record<string, any>;

  // Attribution
  actorId?: string;
  actorType?: 'user' | 'system' | 'admin';
}
```

---

## Immutable Storage

### Write Path

```
Application
    │
    ▼
Audit Logger (synchronous)
    │
    ▼
Kafka Topic (audit-events) ←─────────────── Partitioned by tenantId
    │
    ├──→ Consumer Group 1: Long-term Storage (S3/Iceberg)
    │
    └──→ Consumer Group 2: Real-time Analytics (ClickHouse)
```

### Retention Policy

| Storage | Retention | Access |
|---------|-----------|--------|
| Hot (ClickHouse) | 90 days | Standard queries |
| Warm (S3) | 1 year | Archive access |
| Cold (Glacier) | 7 years | Compliance only |

---

## Query Interface

### Standard Queries

```typescript
// Get authentication events for tenant
const authEvents = await auditQuery.query({
  tenantId: 'tenant_abc',
  eventType: ['AUTH_LOGIN_SUCCESS', 'AUTH_LOGIN_FAILURE'],
  startTime: '2024-01-01',
  endTime: '2024-01-31'
});

// Get failed access attempts
const deniedEvents = await auditQuery.query({
  tenantId: 'tenant_abc',
  eventType: 'ACCESS_DENIED',
  reason: 'permission_denied'
});
```

---

## Compliance Requirements

### GDPR Article 30

- Purpose: Legal basis for processing
- Data minimization: Only necessary fields
- Retention: 7 years (regulatory requirement)
- Security: Encryption at rest and in transit

### SOC 2 Type II

- Audit logging: All system accesses
- Integrity: Tamper-proof logs
- Availability: 99.9% SLA
- Retention: 1 year hot, 7 years total

---

## Failure Modes

| Mode | Impact | Mitigation |
|------|--------|------------|
| Kafka unavailable | Events lost | Local buffer, retry |
| Log corruption | Incomplete audit | Checksum validation |
| Storage full | Events rejected | Archival automation |
| Query timeout | Slow investigation | Index optimization |

---

## Trust Boundaries

| Component | Trust Level |
|-----------|------------|
| Application | SOURCE - generates events |
| Kafka | TRANSPORT - encrypted |
| Storage | REPOSITORY - immutable |
| Query Service | CONSUMER - read-only |

---

## Related Documents

- `05-security/zero-trust-model.md`
- `05-security/incident-response.md`
- `15-runtime-lineage/request-lineage.md`