# Suppression System

## Metadata
```yaml
title: Suppression System
domain: communication
owner: Platform Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: LOW
queue-impact: LOW
provider-impact: HIGH
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - delivery-intelligence.md
  - webhook-reconciliation.md
related-docs:
  - communication-overview.md
  - communication-security.md
related-queues:
  - suppression-sync
related-services:
  - SuppressionManager
  - ProviderSyncService
related-providers:
  - SES
  - Resend
  - Maileroo
related-runtime-states:
  - suppression_syncing
  - suppression_synced
  - suppression_blocked
related-threat-models:
  - Suppression list leakage
  - Bounce rate manipulation
```

---

## Overview

The Suppression System prevents sending to invalid, bounced, or unsubscribed addresses. It maintains global and tenant-specific suppression lists, syncs with provider suppression lists, and enforces suppression rules at send time.

---

## Suppression Types

### Hard Bounces

Permanent delivery failures:

| Reason | Duration | Action |
|--------|----------|--------|
| Invalid domain | Permanent | Always suppress |
| Invalid mailbox | Permanent | Always suppress |
| Mailbox full | 30 days | Re-enable after |
| Account suspended | 90 days | Review before enable |

### Soft Bounces

Temporary delivery failures:

| Reason | Duration | Action |
|--------|----------|--------|
| Greylisted | 1 hour | Retry |
| Quota exceeded | 24 hours | Retry |
| Temporarily unavailable | 24 hours | Retry |

### Complaints

Spam complaints from recipients:

| Source | Duration | Action |
|--------|----------|--------|
| Feedback Loop | Permanent | Always suppress |
| ISP notification | Permanent | Always suppress |

---

## Architecture

### Components

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Send Request   │────▶│  Suppression     │────▶│  Message Queue  │
└─────────────────┘     │  Check           │     └─────────────────┘
                       └──────────────────┘
                              │
                       ┌──────▼──────┐
                       │ Redis Cache │
                       └──────┬──────┘
                              │
                       ┌──────▼──────┐
                       │  PostgreSQL │
                       └─────────────┘
```

### Suppression Store

```typescript
interface SuppressionEntry {
  recipient: string;           // Email or phone
  type: 'bounce' | 'complaint' | 'unsubscribe';
  reason: string;
  source: 'provider' | 'manual' | 'internal';
  tenantId: string;
  suppressedAt: Date;
  expiresAt?: Date;
  autoRemove: boolean;
}
```

---

## Sync Mechanism

### Provider Sync

```typescript
async function syncProviderSuppressions(provider: string): Promise<void> {
  const bounces = await provider.getBounceList();
  const complaints = await provider.getComplaintList();

  await store.upsertBatch([
    ...bounces.map(b => ({ ...b, source: 'provider' })),
    ...complaints.map(c => ({ ...c, source: 'provider' }))
  ]);

  await metrics.record('suppressions_synced', bounces.length + complaints.length);
}
```

### Sync Schedule

| Provider | Frequency | Method |
|----------|-----------|--------|
| SES | Hourly | ListExport |
| Resend | Every 2 hours | API pull |
| Maileroo | Daily | API pull |

---

## Suppression Check

### Send-Time Validation

```typescript
async function checkSuppression(recipient: string, tenantId: string): Promise<SuppressionCheck> {
  const entry = await store.find({ recipient, tenantId });

  if (!entry) {
    return { allowed: true, reason: null };
  }

  if (entry.expiresAt && entry.expiresAt < new Date()) {
    await store.remove(entry.id);
    return { allowed: true, reason: null };
  }

  return {
    allowed: false,
    reason: entry.reason,
    suppressedAt: entry.suppressedAt
  };
}
```

---

## Tenant Isolation

### Per-Tenant Suppressions

Each tenant maintains:
- Global suppression list (all tenants)
- Tenant-specific suppressions (own list)
- Sender-specific suppressions

```typescript
interface TenantSuppressionConfig {
  tenantId: string;
  globalSuppressions: boolean;   // Include global
  autoSuppressBounces: boolean;
  autoSuppressComplaints: boolean;
  manualSuppressionEnabled: boolean;
}
```

---

## Maintenance

### Automatic Cleanup

- Expired entries: Daily
- Duplicate entries: Weekly
- Analytics update: Hourly

### Reporting

| Metric | Description |
|--------|-------------|
| suppression_hit_rate | Percent of sends blocked |
| false_positive_rate | Incorrectly suppressed |
| sync_lag | Provider sync delay |

---

## Related Documents

- `04-communication/delivery-intelligence.md`
- `04-communication/webhook-reconciliation.md`
- `04-communication/communication-security.md`