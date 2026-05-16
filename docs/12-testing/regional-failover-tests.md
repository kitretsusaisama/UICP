# Regional Failover Tests

## Metadata
```yaml
title: Regional Failover Tests
domain: disaster-recovery
owner: SRE Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - src/infrastructure/geo/routing.service.ts
  - src/infrastructure/db/mysql/geo-replication.service.ts
  - src/infrastructure/failover/regional-failover-controller.ts
related-docs:
  - docs/10-operations/dr-procedures.md
  - docs/02-architecture/multi-region-design.md
related-queues:
  - region-health-check
  - cross-region-sync
related-services:
  - GeoRoutingService
  - GeoReplicationService
  - FailoverController
```

---

## Overview

Regional failover tests validate that the system maintains availability during region-wide failures. These tests ensure data replication, traffic rerouting, and state synchronization work correctly across regions.

---

## Test Coverage

### Traffic Failover

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Primary region down | Simulate region failure | Traffic routes to secondary within 60s |
| Health check failure | Mark region unhealthy | Traffic rerouted to healthy region |
| DNS failover | Update DNS after failover | Global traffic points to new region |
| Session continuity | Request fails over mid-session | Request resumes in new region |

### Data Replication

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Async replication | Write to primary | Data appears in secondary within 5s |
| Sync replication | Write with sync flag | Data confirmed in both regions |
| Conflict resolution | Write same key in both regions | Last-write-wins applied |
| Replication lag | Simulate network delay | Replication catches up after 30s |

### State Synchronization

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Config sync | Update config in primary | Synced to secondary within 10s |
| API key sync | Create API key | Available in all regions |
| User session | User created in primary | Visible in secondary region |
| Queue state | Messages in primary queue | Visible in failover region |

### Failback Procedures

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Primary recovery | Primary region comes back | Traffic gradually shifts back |
| Data reconciliation | Sync missed writes | All data consistent after 5 minutes |
| Manual trigger | Admin initiates failback | Smooth transition, no data loss |

---

## Test Implementation

```typescript
describe('Regional Failover', () => {
  describe('Traffic Failover', () => {
    it('should route traffic to secondary when primary fails', async () => {
      await geoRouting.setPrimaryRegion('us-east-1');

      await chaosInjector.killRegion('us-east-1');

      await waitFor(60000);

      const routing = await geoRouting.getCurrentRouting();
      expect(routing.primary).toBe('us-west-2');
    });

    it('should maintain session during failover', async () => {
      const session = await authService.createSession(userId);
      const originalRegion = session.region;

      await chaosInjector.killRegion(originalRegion);

      const resumedSession = await sessionService.getSession(session.id);

      expect(resumedSession).toBeDefined();
      expect(resumedSession.region).not.toBe(originalRegion);
    });
  });

  describe('Data Replication', () => {
    it('should replicate data within SLA', async () => {
      await primaryDb.write('providers', testProvider);

      await waitFor(5000);

      const replicated = await secondaryDb.read('providers', testProvider.id);
      expect(replicated).toEqual(testProvider);
    });

    it('should resolve conflicts with last-write-wins', async () => {
      await primaryDb.write('config', { key: 'test', value: 'primary' });
      await secondaryDb.write('config', { key: 'test', value: 'secondary' });

      await replicationService.sync();

      const final = await primaryDb.read('config', 'test');
      expect(final.value).toBe('secondary'); // Latest timestamp wins
    });
  });

  describe('Failback', () => {
    it('should smoothly return traffic to recovered region', async () => {
      await failoverController.failover('us-east-1', 'us-west-2');

      await chaosInjector.restoreRegion('us-east-1');

      await waitForStabilization(60000);

      const routing = await geoRouting.getCurrentRouting();
      expect(routing.primary).toBe('us-east-1');
    });
  });
});
```

---

## RTO/RPO Targets

- Recovery Time Objective (RTO): 60 seconds
- Recovery Point Objective (RPO): 5 seconds
- Maximum data loss: < 1% of transactions
- Failover success rate: > 99.9%

---

## Test Environment

- Multi-region deployment (at least 3 regions)
- Real database replication
- Network latency simulation
- Chaos injection capabilities

---

## Monitoring During Failover

- Latency spike monitoring
- Error rate monitoring
- Queue backlog monitoring
- Replication lag alerting