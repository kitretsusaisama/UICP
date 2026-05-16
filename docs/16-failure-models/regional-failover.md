# Regional Failover

## Metadata

```yaml
title: Regional Failover
domain: Disaster Recovery
owner: Platform Team
criticality: Critical
runtime-impact: Multi-region service impact
security-impact: Data integrity across regions
queue-impact: Cross-region queue synchronization
provider-impact: Multiple region dependencies
tenant-impact: Global tenant impact
ai-ingestable: true
review-cycle: Quarterly
last-reviewed: 2026-05-16
depends-on:
  - DNS Configuration
  - Database Replication
  - Health Checks
  - Traffic Routing
related-docs:
  - docs/03-disaster-recovery/architecture.md
  - docs/05-runbook/region-failover.md
  - docs/09-runbooks/multi-region.md
related-queues:
  - cross-region-sync
  - dns-updates
  - state-replication
related-services:
  - dns-controller
  - region-manager
  - health-monitor
  - db-replicator
related-providers:
  - AWS Route53
  - AWS RDS
  - AWS CloudFront
related-runtime-states:
  - REGION_DEGRADED
  - FAILOVER_IN_PROGRESS
  - CROSS_REGION_SYNC
related-threat-models:
  - Region-Wide Outage
  - Data Consistency Violation
  - Split-Brain Scenario
```

## Symptoms

- **Primary region health check failures**
- **DNS failover not triggering** automatically
- **Stale data served** from secondary region
- **Database replication lag** exceeding thresholds
- **Inconsistent state** between regions after failover

## Metrics

| Metric | Normal | Alert Threshold |
|--------|--------|-----------------|
| Region health check | > 99% | < 90% |
| DNS failover time | < 60s | > 300s |
| DB replication lag | < 1s | > 30s |
| Cross-region latency | < 50ms | > 200ms |
| Data consistency score | 100% | < 99% |

## Propagation Chain

```
Regional Outage (Power/Network/Fire)
        ↓
Health Check Failure
        ↓
DNS Failover Triggered
        ↓
Stale Cache Served
        ↓
Replication Lag Increases
        ↓
Split-Brain or Data Loss
        ↓
Extended Service Degradation
```

## Debugging Steps

1. **Check regional health status**
   ```bash
   kubectl get regions -o wide
   aws route53 get-health-check-status --id HEALTH_CHECK_ID
   ```

2. **Verify DNS failover status**
   ```bash
   aws route53 list-resource-record-sets --hosted-zone-id ZONE_ID
   ```

3. **Analyze database replication**
   ```bash
   aws rds describe-db-instances | grep -E "ReplicaLag|Status"
   ```

4. **Check for data consistency issues**
   ```bash
   kubectl exec -it db-primary -- check-consistency
   ```

5. **Review failover trigger logs**
   ```bash
   kubectl logs region-manager --tail=500 | grep -i failover
   ```

## Mitigation

### Immediate Actions

1. **Manual failover activation** if automatic fails
   ```bash
   kubectl exec region-manager -- trigger-failover --target=us-west-2
   ```

2. **Update DNS manually** if Route53 fails
   ```bash
   aws route53 change-resource-record-sets --hosted-zone-id ZONE_ID --change-batch file://failover.json
   ```

3. **Force cache invalidation** in secondary region

4. **Enable read-only mode** until consistency verified

### Preventive Measures

1. **Regular failover drills** (monthly)
2. **Implement automated health checks** with multiple dependencies
3. **Use multi-active architecture** where possible
4. **Add replication monitoring** with alerts
5. **Implement data checksum validation** across regions

## Rollback

```bash
# Restore primary region
kubectl exec region-manager -- restore-primary --region=us-east-1

# Revert DNS to primary
aws route53 change-resource-record-sets --hosted-zone-id ZONE_ID --change-batch file://rollback.json

# Verify data consistency post-rollback
kubectl exec -it db-check -- verify-consistency
```

## Recovery

1. **Verify primary region health** before restore
2. **Sync data from secondary** to primary (if needed)
3. **Gradually shift traffic** back (10% → 100%)
4. **Monitor for split-brain** symptoms post-recovery
5. **Run consistency checks** across all data stores

## Postmortem Checklist

- [ ] Document root cause of regional failure
- [ ] Review health check configuration and thresholds
- [ ] Analyze DNS failover timing
- [ ] Check database replication lag during event
- [ ] Verify data consistency after failover
- [ ] Review manual intervention requirements
- [ ] Update disaster recovery runbook
- [ ] Schedule failover drill to validate fixes