# Operational Health Checks

## Metadata
```yaml
title: Operational Health Checks
domain: operations
owner: platform-team
criticality: MEDIUM
runtime-impact: LOW
security-impact: LOW
queue-impact: LOW
provider-impact: LOW
tenant-impact: LOW
ai-ingestable: true
review-cycle: weekly
last-reviewed: 2026-05-16
depends-on:
  - docs/11-operations/maintenance.md
  - docs/06-architecture/monitoring-strategy.md
related-docs:
  - docs/06-architecture/infrastructure.md
  - docs/06-architecture/observability-stack.md
related-queues:
  - health-check-results
related-services:
  - all-services
```

---

## Overview

This document outlines regular health check procedures for the UICP platform to ensure optimal performance and early detection of issues.

---

## Daily Health Checks (5 min)

### System Status Overview

```bash
# Check all service health
curl -s https://api.uicp.io/v1/health | jq '.'

# Check Kubernetes cluster
kubectl get nodes -o wide
kubectl get pods -n uicp --no-headers | grep -c Running

# Check recent deployments
kubectl rollout status -n uicp --timeout=300s
```

### Key Metrics Review

```promql
# Error rate should be < 1%
rate(http_requests_failed_total[5m]) / rate(http_requests_total[5m])

# Latency p99 should be < 1s
histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))

# Services should be healthy
up == 1

# No critical alerts firing
alertmanager_alerts{alertname=~"critical|p1",state="firing"} == 0
```

### Queue Health

```bash
# Check queue depths
redis-cli KEYS "queue:*" | while read q; do
  echo "$q: $(redis-cli LLEN $q)"
done

# Check for stuck messages
redis-cli LRANGE queue:email:outbound 0 10 | jq -r '.[] | .timestamp' | head -10
```

---

## Weekly Health Checks (30 min)

### Database Health

```sql
-- Check for long-running queries
SELECT pid, now() - query_start as duration, query
FROM pg_stat_activity
WHERE state = 'active' AND query_start < now() - interval '5 minutes';

-- Check for dead tuples
SELECT schemaname, tablename, n_dead_tup, n_live_tup,
  round(n_dead_tup::numeric / NULLIF(n_live_tup, 0) * 100, 2) as dead_ratio
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY dead_ratio DESC;

-- Check index usage
SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC LIMIT 20;
```

### Cache Health

```bash
# Check Redis memory
redis-cli INFO memory | grep -E "used_memory|maxmemory|evicted"

# Check hit rate
redis-cli INFO stats | grep -E "keyspace_hits|keyspace_misses"

# Check connected clients
redis-cli INFO clients

# Check for blocking commands
redis-cli INFO commandstats | grep -E "blpop|brpop|brpoplpush"
```

### Storage Health

```bash
# Check disk usage
df -h /var/lib/docker /var/lib/kubelet

# Check for disk pressure
kubectl get nodes -o jsonpath='{range .items[*]} {.status.conditions[?(@.type=="DiskPressure")].message}{"\n"}{end}'

# Check PVC usage
kubectl get pvc -n uicp -o jsonpath='{range .items[*]} {.metadata.name}: {.status.phase}{"\n"}{end}'
```

### Security Health

```bash
# Check for unused credentials
kubectl get secrets -n uicp | grep -E "token|password|key" | awk '{print $1}' | xargs -I {} kubectl get secret {} -n uicp -o json | jq -r '.data' | base64 -d | grep -E "expired|old"

# Check network policies
kubectl get networkpolicies -n uicp

# Check RBAC
kubectl auth can-i --list --namespace=uicp
```

---

## Monthly Health Checks (1 hour)

### Capacity Planning

```bash
# Analyze resource usage trends
kubectl top pods -n uicp --sort-by=memory | head -20
kubectl top nodes

# Check scaling events
kubectl get hpa -n uicp -o yaml | grep -A 5 lastActiveTime

# Analyze cost trends
aws ce get-cost-and-usage \
  --time-period StartDate=2024-01-01,EndDate=2024-01-31 \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --groupBy Type=DIMENSION,Key=SERVICE
```

### Dependency Updates

```bash
# Check for outdated dependencies
npm outdated --json | jq '.'

# Check for security vulnerabilities
npm audit --json | jq '.metadata.vulnerabilities'

# Check container base images
docker images | grep -E "alpine|ubuntu" | head -10
```

### Backup Verification

```bash
# Verify database backups
aws s3 ls s3://uicp-backups/database/ | tail -5

# Test backup restoration
./scripts/test-backup-restore.sh --latest

# Check backup retention policy
aws s3api get-bucket-lifecycle-configuration --bucket uicp-backups
```

### Disaster Recovery Testing

```bash
# Test failover to backup region
./scripts/dr-test.sh --target-region=us-west-2

# Verify data replication
psql -h db.us-west-2.uicp.io -U uicp -c "SELECT pg_is_in_recovery();"

# Test DNS failover
dig +short uicp.io
```

---

## Service-Specific Health Checks

### API Gateway

```bash
# Check request rate
rate(http_requests_total{service="api-gateway"}[5m])

# Check rate limiting
redis-cli GET rate-limit:global:remaining

# Check SSL certificate expiry
kubectl get certificate -n uicp -o jsonpath='{range .items[*]} {.spec.secretName}: {.status.notAfter}{"\n"}{end}'
```

### Auth Service

```bash
# Check token issuance
rate(uicp_jwt_issued_total[5m])

# Check session count
redis-cli KEYS "session:*" | wc -l

# Check failed authentications
rate(uicp_auth_failed_total[5m])
```

### Email Service

```bash
# Check delivery rate
rate(uicp_email_delivered_total[5m]) / rate(uicp_email_sent_total[5m])

# Check bounce rate
rate(uicp_email_bounced_total[5m])

# Check SES quota
aws ses get-quota-summary
```

### User Service

```bash
# Check user creation rate
rate(uicp_user_created_total[5m])

# Check for inactive users
psql -h db.uicp.io -U uicp -c "SELECT count(*) FROM users WHERE last_login < now() - interval '90 days';"

# Check profile completeness
psql -h db.uicp.io -U uicp -c "SELECT (count(*) FILTER (WHERE email IS NOT NULL)::float / count(*) * 100) as email_rate FROM users;"
```

---

## Health Check Automation

### Automated Health Dashboard

Create a Grafana dashboard with these panels:

1. **Overall Health**: Green/Yellow/Red status
2. **Service Status**: All services up/down
3. **Error Rate**: Last 24 hours trend
4. **Latency**: p50, p95, p99
5. **Queue Backlog**: By queue
6. **Resource Usage**: CPU, Memory, Disk
7. **Scaling Events**: HPA activity

### Scheduled Health Report

```bash
# Generate weekly health report
0 8 * * 1 /scripts/health-report.sh --weekly
```

Report includes:
- Summary of metrics
- Any incidents during period
- Upcoming maintenance windows
- Recommended actions

---

## Alert Response

| Alert | Severity | Response Time | Action |
|-------|----------|---------------|--------|
| Service Down | P0 | Immediate | Run emergency procedures |
| Error Rate > 5% | P1 | 15 min | Investigate, scale if needed |
| Latency > 2s | P1 | 30 min | Check dependencies, scale |
| Queue Backup | P2 | 1 hour | Scale workers |
| Disk > 90% | P1 | 1 hour | Clean up or expand |

---

## Related Documents

- [Maintenance Procedures](./maintenance.md)
- [Emergency Procedures](./emergency-procedures.md)
- [Monitoring Alerts](./monitoring-alerts.md)