# Credential Lineage

## Metadata
```yaml
title: Credential Lineage
domain: security
owner: Platform Team
criticality: HIGH
runtime-impact: LOW
security-impact: HIGH
queue-impact: NONE
provider-impact: NONE
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/api-key-security.md
  - 05-security/audit-model.md
  - 15-runtime-lineage/request-lineage.md
related-docs:
  - 05-security/emergency-revocation.md
  - 05-security/secret-management.md
  - 17-adrs/ADR-001-api-key-runtime.md
related-queues: []
related-services:
  - CredentialLineageService
  - AuditService
  - RequestLineageService
related-runtime-states:
  - created
  - rotated
  - revoked
  - expired
```

---

## Executive Summary

Credential lineage tracks the complete lifecycle of credentials from creation through rotation to revocation. This enables forensic analysis, compliance auditing, and impact assessment during security incidents.

---

## Lineage Data Model

### Core Entities

```
┌─────────────────────────────────────────────────────────────────┐
│                    CREDENTIAL LIFECYCLE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐ │
│  │ Created │────▶│ Rotated │────▶│ Rotated │────▶│ Revoked │ │
│  │  t=0    │     │  t=90d  │     │ t=180d  │     │ t=185d  │ │
│  └─────────┘     └─────────┘     └─────────┘     └─────────┘ │
│       │                                                     │  │
│       │         EVENT CHAIN (linked list)                   │  │
│       │                                                     │  │
│       ▼                                                     ▼  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              LINEAGE RECORD                           │    │
│  │  - credential_id: 01ARZ3NDEKTSV4RRFFQ69G5FAV        │    │
│  │  - tenant_id: tenant_abc                             │    │
│  │  - type: API_KEY                                    │    │
│  │  - created_at: 2024-01-01                           │    │
│  │  - previous_id: null (first version)               │    │
│  │  - next_id: 02ARZ3NDEKTSV4RRFFQ69G5FAV              │    │
│  │  - current: false                                   │    │
│  │  - revoked_at: 2024-04-15                           │    │
│  │  - revocation_reason: security_incident            │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Lineage Tracking

### Creation Event

```typescript
interface CredentialCreatedEvent {
  eventType: 'CREDENTIAL_CREATED';
  credentialId: string;
  tenantId: string;
  credentialType: 'API_KEY' | 'SESSION' | 'PROVIDER_SECRET';
  createdBy: string;           // user ID or system
  permissions: string[];
  expiresAt?: Date;
  parentCredentialId?: string; // for rotation
}

async function trackCreation(event: CredentialCreatedEvent): Promise<void> {
  const lineage: CredentialLineage = {
    id: ulid(),
    credentialId: event.credentialId,
    tenantId: event.tenantId,
    type: event.credentialType,
    version: 1,
    previousId: event.parentCredentialId,
    nextId: null,
    createdAt: new Date(),
    status: 'active',
    metadata: {
      createdBy: event.createdBy,
      permissions: event.permissions
    }
  };

  // Update previous credential's nextId
  if (event.parentCredentialId) {
    await lineageRepository.update(event.parentCredentialId, {
      nextId: event.credentialId,
      status: 'rotated'
    });
  }

  await lineageRepository.save(lineage);
}
```

### Rotation Event

```typescript
interface CredentialRotatedEvent {
  eventType: 'CREDENTIAL_ROTATED';
  oldCredentialId: string;
  newCredentialId: string;
  rotatedBy: string;
  reason: 'scheduled' | 'manual' | 'emergency';
}
```

### Revocation Event

```typescript
interface CredentialRevokedEvent {
  eventType: 'CREDENTIAL_REVOKED';
  credentialId: string;
  revokedBy: string;
  reason: string;
  incidentId?: string;
}
```

---

## Query Interface

### Get Credential History

```typescript
async function getCredentialLineage(credentialId: string): Promise<LineageHistory> {
  const history: CredentialVersion[] = [];

  // Get all related credentials
  let currentId: string | null = credentialId;

  while (currentId) {
    const version = await lineageRepository.findById(currentId);
    history.push(version);

    // For current credential, also get its history
    if (version.previousId) {
      // Traverse backward to oldest
      currentId = version.previousId;
    } else {
      break;
    }
  }

  return {
    currentId: credentialId,
    versions: history.reverse(), // oldest first
    createdAt: history[0].createdAt,
    status: history[history.length - 1].status
  };
}
```

### Impact Assessment

```typescript
async function assessCredentialImpact(
  tenantId: string,
  fromDate: Date,
  toDate: Date
): Promise<ImpactReport> {
  const credentials = await lineageRepository.findByTenantAndDateRange(
    tenantId,
    fromDate,
    toDate
  );

  return {
    totalCreated: credentials.filter(c => c.status === 'active').length,
    totalRotated: credentials.filter(c => c.status === 'rotated').length,
    totalRevoked: credentials.filter(c => c.status === 'revoked').length,
    compromiseRisk: calculateRiskScore(credentials),
    recommendations: generateRecommendations(credentials)
  };
}
```

---

## Forensic Analysis

### Incident Timeline Reconstruction

```typescript
async function reconstructIncident(incidentId: string): Promise<IncidentTimeline> {
  // 1. Get all credentials created/revoked during incident window
  const credentials = await lineageRepository.query({
    incidentId,
    tenantId: incident.tenantId
  });

  // 2. Get all requests using these credentials
  const requests = await requestLineage.query({
    credentialId: { $in: credentials.map(c => c.id) },
    timestamp: { $gte: incident.startTime, $lte: incident.endTime }
  });

  // 3. Build timeline
  const timeline = buildTimeline([
    ...credentials.map(c => ({
      type: 'credential' as const,
      ...c
    })),
    ...requests.map(r => ({
      type: 'request' as const,
      ...r
    }))
  ]);

  return timeline;
}
```

---

## Trust Boundaries

| Operation | Authorization |
|-----------|---------------|
| Read lineage | Tenant admin, audit viewer |
| Create credential | Key owner, system |
| Rotate credential | Key owner, scheduled job |
| Revoke credential | Security team, tenant admin |

---

## Related Documents

- `05-security/api-key-security.md`
- `05-security/audit-model.md`
- `15-runtime-lineage/request-lineage.md`