# Scaling Playbooks

## Metadata
```yaml
title: Scaling Playbooks
domain: operations
owner: platform-team
criticality: MEDIUM
runtime-impact: HIGH
security-impact: LOW
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingesting: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - docs/11-operations/runbooks/queue-storm.md
  - docs/06-architecture/horizontal-scaling.md
related-docs:
  - docs/06-architecture/infrastructure.md
  - docs/06-architecture/auto-scaling-config.md
related-queues:
  - All application queues
related-services:
  - api-gateway
  - worker-service
  - all-scalable-services
```

---

## Overview

This document provides playbooks for scaling UICP services in response to increased load, traffic spikes, or capacity constraints.

---

## Scaling Principles

1. **Scale up before hitting limits** - Proactive scaling based on trends
2. **Scale down gradually** - Avoid thrashing between scaling events
3. **Understand limits** - Know maximum capacity per service
4. **Test at scale** - Regular load testing to validate scaling
5. **Monitor cost** - Balance performance with operational cost

---

## Playbook: API Gateway Scaling

### Triggers

- CPU > 70% for 5 minutes
- Request latency p99 > 500ms
- Error rate > 1%
- Connection count > 80% of limit

### Horizontal Scaling

```bash
# Check current replicas
kubectl get deployment api-gateway -n uicp

# Manual scale
kubectl scale deployment api-gateway --replicas=10 -n uicp

# Auto-scale configuration
kubectl autoscale deployment api-gateway \
  --min=3 \
  --max=20 \
  --cpu-percent=70 \
  --memory-percent=80 \
  -n uicp

# Verify scaling
kubectl get hpa api-gateway -n uicp
watch -n 5 'kubectl get pods -l app=api-gateway -n uicp'
```

### Vertical Scaling (if needed)

```bash
# Update resource requests
kubectl patch deployment api-gateway -n uicp -p '{
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "api-gateway",
          "resources": {
            "requests": {"cpu": "2000m", "memory": "4Gi"},
            "limits": {"cpu": "4000m", "memory": "8Gi"}
          }
        }]
      }
    }
  }
}'
```

### Rate Limiting Adjustments

```bash
# Increase rate limits temporarily
redis-cli SET rate-limit:global:max 50000

# Adjust per-tenant limits
redis-cli SET rate-limit:tenant:{TENANT_ID}:max 10000
```

---

## Playbook: Worker Service Scaling

### Triggers

- Queue backlog > 1000 messages
- Message processing latency > 5 seconds
- Worker CPU > 80%
- Consumer lag increasing

### Worker Scaling

```bash
# Check current queue depth
redis-cli LLEN queue:email:outbound

# Manual scale workers
kubectl scale deployment worker-service --replicas=15 -n uicp

# Auto-scale based on queue depth
kubectl apply -f - <<EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: worker-service-hpa
  namespace: uicp
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: worker-service
  minReplicas: 3
  maxReplicas: 50
  metrics:
  - type: External
    external:
      metric:
        name: queue_depth
        selector:
          matchLabels:
            queue: email-outbound
      target:
        type: AverageValue
        averageValue: "100"
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
EOF
```

### Queue Optimization

```bash
# Increase batch size for processing
kubectl set env deployment/worker-service BATCH_SIZE=50 -n uicp

# Enable parallel processing
kubectl set env deployment/worker-service PARALLEL_PROCESSING=true -n uicp

# Adjust message concurrency
kubectl set env deployment/worker-service MAX_CONCURRENT=20 -n uicp
```

---

## Playbook: Database Scaling

### Read Replica Scaling

```bash
# Check current read replica status
aws rds describe-db-instances --db-instance-identifier uicp-prod | grep -E "DBInstanceStatus|ReadReplicaDBInstanceIdentifiers"

# Create additional read replica
aws rds create-db-instance \
  --db-instance-identifier uicp-prod-replica-2 \
  --db-instance-class db.r6g.xlarge \
  --engine postgres \
  --source-db-instance-identifier uicp-prod \
  --availability-zone us-east-1a

# Verify replica sync
psql -h uicp-prod-replica-2.cluster.uicp.io -U uicp -c "SELECT now() - pg_last_xact_replay_timestamp() AS replica_lag;"
```

### Vertical Scaling (if needed)

```bash
# Scale up instance class
aws rds modify-db-instance \
  --db-instance-identifier uicp-prod \
  --db-instance-class db.r6g.2xlarge \
  --apply-immediately

# Monitor during scaling
watch -n 10 'aws rds describe-db-instances --db-instance-identifier uicp-prod | jq ".DBInstances[0].DBInstanceStatus"'
```

### Connection Pool Adjustment

```bash
# Increase connection pool size
kubectl set env deployment/api-gateway DB_POOL_SIZE=50 -n uicp

# Check active connections
psql -h db.uicp.io -U uicp -c "SELECT count(*) FROM pg_stat_activity WHERE datname='uicp';"
```

---

## Playbook: Redis Scaling

### Cluster Scaling

```bash
# Check cluster status
redis-cli -h redis-cluster.uicp.io CLUSTER INFO

# Add new node
redis-cli --cluster add-node \
  10.0.1.5:6379 \
  $(redis-cli -h redis-cluster.uicp.io CLUSTER NODES | grep master | head -1 | awk '{print $1}')

# Rebalance slots
redis-cli --cluster rebalance redis-cluster.uicp.io:6379

# Verify memory usage
redis-cli INFO memory | grep used
```

### Memory Optimization

```bash
# Enable eviction policy
redis-cli CONFIG SET maxmemory-policy allkeys-lru
redis-cli CONFIG SET maxmemory 8gb

# Clear unused keys
redis-cli FLUSHDB async

# Verify after cleanup
redis-cli INFO memory | grep used_memory
```

---

## Playbook: CDN Scaling

### Cache Configuration

```bash
# Increase cache TTL for static assets
aws cloudfront update-distribution \
  --id {DISTRIBUTION_ID} \
  --default-cache-behavior "DefaultCacheBehavior"='{"MinTTL":3600}'

# Purge cache if needed
aws cloudfront create-invalidation \
  --distribution-id {DISTRIBUTION_ID} \
  --paths "/*"
```

### Origin Protection

```bash
# Increase origin timeout
kubectl patch deployment api-gateway -n uicp -p '{
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "api-gateway",
          "env": [{"name": "ORIGIN_TIMEOUT", "value": "30"}]
        }]
      }
    }
  }
}'
```

---

## Scaling Monitoring

### Key Metrics to Watch

```promql
# Scaling effectiveness
rate(uicp_requests_total[5m]) / uicp_worker_replicas

# Queue drain rate
delta(uicp_queue_depth[5m]) > 0

# Resource utilization
uicp_service_cpu_utilization < 80
uicp_service_memory_utilization < 85

# Latency under load
histogram_quantile(0.95, rate(uicp_request_duration_seconds_bucket[5m])) < 1

# Error rates during scaling
rate(uicp_requests_failed_total[5m]) < 0.01
```

### Scaling Alerts

| Alert | Threshold | Action |
|-------|-----------|--------|
| HPA at max | replicas = max | Investigate load source |
| Queue backup | depth > 10000 | Scale workers immediately |
| DB connections | > 80% limit | Scale read replicas |
| Memory pressure | > 90% | Optimize or scale |

---

## Cost Management

### Scaling Cost Calculator

| Service | Base Replicas | Max Replicas | Cost/hour/replica |
|---------|---------------|--------------|-------------------|
| api-gateway | 3 | 20 | $0.50 |
| worker-service | 5 | 50 | $0.40 |
| auth-service | 3 | 10 | $0.30 |

### Scaling Policies

- **Daytime (peak)**: Higher min replicas
- **Nighttime (off-peak)**: Lower min replicas
- **Weekends**: Reduced baseline

```yaml
# Scheduled scaling for worker-service
cron: "0 6 * * 1-5"  # Weekdays 6am
action: scale to 10 replicas

cron: "0 20 * * 1-5"  # Weekdays 8pm  
action: scale to 5 replicas
```

---

## Related Documents

- [Queue Storm Runbook](./runbooks/queue-storm.md)
- [Operational Health Checks](./operational-health-checks.md)
- [Auto Scaling Configuration](./auto-scaling-config.md)