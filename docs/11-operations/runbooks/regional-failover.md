# Runbook: Regional Failover

## Metadata
```yaml
title: Regional Failover Runbook
domain: operations
owner: platform-team
criticality: CRITICAL
runtime-impact: CRITICAL
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - docs/11-operations/runbooks/database-failover.md
  - docs/11-operations/runbooks/dns-failover.md
  - docs/11-operations/disaster-recovery-plan.md
related-docs:
  - docs/06-architecture/multi-region-design.md
  - docs/06-architecture/infrastructure.md
  - docs/09-compliance/dr-requirements.md
related-queues:
  - All queues must replicate across regions
related-services:
  - all-services
```

---

## Scenario

Primary region becomes unavailable due to natural disaster, power failure, network partition, or cascading infrastructure failure.

---

## Symptoms

- All services in primary region unhealthy
- Health check failures from load balancer
- DNS failover not automatic
- Database primary unreachable
- High latency or timeouts from all requests

---

## Metrics

```promql
# Region health status
uicp_region_health{region="us-east-1"}
uicp_region_health{region="us-west-2"}

# Request routing
uicp_request_total by (region, status)

# Database replication lag
uicp_db_replication_lag{region="us-west-2"}

# DNS resolution
dns_query_success_rate{region="us-east-1"}

# Service availability
up{namespace="us-east-1"}
```

---

## Mitigation

### Pre-Failover (if early warning exists)

1. **Enable DNS Failover**
   ```bash
   # Route53 failover configuration
   aws route53 update-health-check --health-check-id {HC_ID} --failure-threshold 3
   
   # Verify failover record set
   aws route53 get-change --id {CHANGE_ID}
   ```

2. **Scale Up Secondary Region**
   ```bash
   # Pre-scale in secondary region
   kubectl scale deployment --replicas=5 -n uicp --region=us-west-2
   ```

3. **Verify Data Replication**
   ```bash
   # Check replication lag
   psql -h db.us-west-2.uicp.io -c "SELECT now() - pg_last_xact_replay_timestamp() AS lag;"
   
   # Ensure all queues synced
   redis-cli -h redis.us-west-2.cluster.io INFO replication
   ```

### Failover Execution (5-15 min)

1. **Activate Secondary Region**
   ```bash
   # Promote read replica to primary
   aws rds promote-db-instance --db-instance-identifier uicp-db-uswest2
   
   # Promote Redis replica
   redis-cli -h redis.us-west-2.cluster.io REPLICAOF no one
   ```

2. **Update DNS**
   ```bash
   # Switch traffic to secondary region
   aws route53 change-resource-record-sets \
     --hosted-zone-id {ZONE_ID} \
     --change-batch file://dns-failover.json
   ```

3. **Enable Traffic Routing**
   ```bash
   # Update load balancer config
   kubectl apply -f load-balancer-secondary.yaml
   
   # Update API gateway region routing
   redis-cli SET routing:primary-region "us-west-2"
   ```

4. **Notify Services**
   ```bash
   # Update service discovery
   consul catalog register -datacenter=us-west-2
   
   # Signal failover to monitoring
   curl -X POST https://monitoring.uicp.io/failover \
     -d '{"source_region":"us-east-1","target_region":"us-west-2"}'
   ```

### Post-Failover (15-60 min)

1. **Verify Service Health**
   ```bash
   # Health check all services
   for svc in api-gateway auth-service user-service; do
     curl -f https://$svc.us-west-2.uicp.io/health || echo "FAILED: $svc"
   done
   ```

2. **Monitor Queue Processing**
   ```bash
   # Verify message processing in new region
   redis-cli -h redis.us-west-2.cluster.io INFO stats | grep instantaneous_ops
   ```

3. **Update Client Configuration**
   ```bash
   # Push new region configuration to clients
   curl -X POST https://config.uicp.io/push -d '{"region":"us-west-2"}'
   ```

---

## Rollback

To restore primary region when recovered:

```bash
# 1. Verify primary region is healthy
kubectl get nodes --region=us-east-1
kubectl get pods -n uicp --region=us-east-1

# 2. Sync any data created during outage
# Run data sync job
kubectl apply -f data-sync-job.yaml -n uicp

# 3. Wait for replication to catch up
# Monitor replication lag until < 1 second
watch -n 5 'psql -h db.us-east-1.uicp.io -c "SELECT pg_current_wal_lsn() - replay_lsn AS lag FROM pg_stat_replication"'

# 4. Switch traffic back
aws route53 change-resource-record-sets --hosted-zone-id {ZONE_ID} --change-batch file://dns-primary.json

# 5. Verify traffic flowing to primary
watch -n 10 'curl -s https://api.uicp.io/region | jq .region'

# 6. Scale down secondary region
kubectl scale deployment --replicas=2 -n uicp --region=us-west-2
```

---

## Recovery

1. Verify all services operational in new region
2. Confirm database replication set up for bidirectional
3. Monitor error rates and latency
4. Process any queue backlog from outage
5. Complete incident documentation

---

## Observability Queries

```promql
# Request distribution by region
sum(rate(http_requests_total[5m])) by (region)

# Error rate by region
sum(rate(http_requests_failed_total[5m])) by (region) / sum(rate(http_requests_total[5m])) by (region)

# Database connections by region
uicp_db_active_connections by (region)

# Cache hit rate by region
uicp_cache_hit_rate by (region)

# Queue backlog by region
uicp_queue_depth by (region, queue_name)
```

---

## Contacts

- Infrastructure Lead: #infra-leads
- AWS Support: Enterprise Support
- DevOps On-Call: PagerDuty
- Customer Success: If extended outage

---

## SLA

- RTO: 30 minutes
- RPO: 5 minutes (database replication)
- Target failover time: 15 minutes

---

## Related Runbooks

- [Database Failover](./database-failover.md)
- [DNS Failover](./dns-failover.md)
- [Disaster Recovery Plan](./disaster-recovery-plan.md)