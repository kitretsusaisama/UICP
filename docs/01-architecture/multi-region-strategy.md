# Multi-Region Strategy

## Metadata
```yaml
title: Multi-Region Strategy
domain: infrastructure
owner: Infrastructure Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - smart-routing.md
  - scaling-strategy.md
related-docs:
  - distributed-runtime.md
  - provider-outages.md
```

---

## Overview

UICP operates across multiple geographic regions to ensure high availability and low latency. Each region operates independently with cross-region replication for data durability.

---

## Region Architecture

### Active-Active Deployment

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│    us-east-1    │    │    eu-west-1    │    │    ap-south-1   │
│                 │    │                 │    │                 │
│  API Nodes (5)  │    │  API Nodes (5)  │    │  API Nodes (5)  │
│  Workers (20)   │    │  Workers (20)   │    │  Workers (20)   │
│  MySQL Primary  │    │  MySQL Replica  │    │  MySQL Replica  │
│  Redis Cluster  │    │  Redis Replica  │    │  Redis Replica  │
└────────┬────────┘    └────────┬────────┘    └────────┬────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    Global Load Balancer
                    (Route53/CloudFlare)
```

### Region Responsibilities

| Region | Primary Traffic | Failover Target | Providers |
|--------|-----------------|-----------------|------------|
| us-east-1 | North America | eu-west-1 | AWS, Twilio |
| eu-west-1 | Europe | us-east-1 | AWS, Twilio |
| ap-south-1 | Asia Pacific | us-east-1 | AWS, Twilio |

---

## Data Replication

### MySQL Replication

```typescript
// Primary region writes, replicas read
class DatabaseConfig {
  readonly replication = {
    us-east-1: {
      primary: { host: 'mysql-us-east-1.internal', port: 3306 },
      replicas: [
        { host: 'mysql-us-east-1-replica-1.internal', port: 3306 },
        { host: 'mysql-us-east-1-replica-2.internal', port: 3306 },
      ],
    },
    eu-west-1: {
      primary: null, // Read-only replica
      replicas: [
        { host: 'mysql-eu-west-1-replica-1.internal', port: 3306 },
      ],
    },
  };
}
```

### Redis Replication

```typescript
// Redis active-passive for session storage
const redisConfig = {
  clusters: {
    'us-east-1': {
      nodes: ['10.0.1.1', '10.0.1.2', '10.0.1.3'],
      master: '10.0.1.1',
    },
  },
};
```

---

## Traffic Routing

### Latency-Based Routing

```typescript
class GlobalTrafficManager {
  async routeRequest(clientIp: string): Promise<string> {
    // 1. Determine client region from IP
    const clientRegion = await this.geoIp.lookup(clientIp);

    // 2. Find closest healthy region
    const healthyRegions = await this.healthChecker.getHealthyRegions();

    const closest = healthyRegions
      .map(r => ({
        region: r.name,
        latency: await this.latencyChecker.measure(clientIp, r.endpoint),
      }))
      .sort((a, b) => a.latency - b.latency)[0];

    return closest.region;
  }
}
```

### Health-Based Failover

```typescript
async function failover(sourceRegion: string, targetRegion: string): Promise<void> {
  // 1. Update DNS to point to target region
  await this.dns.update(sourceRegion, targetRegion);

  // 2. Enable target region as primary
  await this.database.setPrimary(targetRegion);

  // 3. Sync any pending data
  await this.replicator.sync(sourceRegion, targetRegion);

  // 4. Notify monitoring
  await this.alert.send('region_failover', {
    from: sourceRegion,
    to: targetRegion,
    timestamp: new Date(),
  });
}
```

---

## Tenant Region Assignment

### Region Selection

```typescript
async function assignTenantRegion(tenantId: TenantId): Promise<string> {
  // 1. Check tenant preference
  const tenant = await this.tenantRepository.findById(tenantId);
  if (tenant.settings.preferredRegion) {
    return tenant.settings.preferredRegion;
  }

  // 2. Determine from domain/TLD
  if (tenant.domain?.endsWith('.eu')) {
    return 'eu-west-1';
  }
  if (tenant.domain?.endsWith('.asia')) {
    return 'ap-south-1';
  }

  // 3. Default to US
  return 'us-east-1';
}
```

### Cross-Region Operations

```typescript
async function executeCrossRegion(
  operation: Operation,
  tenantId: TenantId
): Promise<void> {
  const tenantRegion = await this.tenantService.getRegion(tenantId);

  // Route to tenant's region
  await this.regionClient.execute(tenantRegion, operation);
}
```

---

## Compliance and Data Residency

### Data Residency Controls

```typescript
interface DataResidencyRule {
  region: string;
  dataTypes: string[]; // PII, financial, health
  tenants: string[];   // Specific tenants
}

const residencyRules: DataResidencyRule[] = [
  { region: 'eu-west-1', dataTypes: ['pii'], tenants: ['eu-companies'] },
  { region: 'ap-south-1', dataTypes: ['pii'], tenants: ['apac-companies'] },
];

async function ensureDataResidency(
  tenantId: TenantId,
  dataType: string
): Promise<string> {
  const tenant = await this.tenantRepository.findById(tenantId);

  // Enforce data residency
  for (const rule of residencyRules) {
    if (rule.tenants.includes(tenantId) && rule.dataTypes.includes(dataType)) {
      return rule.region;
    }
  }

  // Default region
  return tenant.region;
}
```

---

## Related Documents

- `smart-routing.md`
- `scaling-strategy.md`
- `distributed-runtime.md`
- `16-failure-models/provider-outages.md`