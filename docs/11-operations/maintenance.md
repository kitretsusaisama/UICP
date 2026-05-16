# Maintenance Procedures

## Metadata
```yaml
title: Maintenance Procedures
domain: operations
owner: platform-team
criticality: MEDIUM
runtime-impact: MEDIUM
security-impact: MEDIUM
queue-impact: LOW
provider-impact: LOW
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - docs/11-operations/deployment-checklists.md
  - docs/11-operations/operational-health-checks.md
related-docs:
  - docs/08-devops/change-management.md
  - docs/06-architecture/infrastructure.md
  - docs/09-compliance/maintenance-window-policy.md
related-queues:
  - maintenance-tasks
  - scheduled-jobs
related-services:
  - all-services
```

---

## Overview

This document covers planned maintenance procedures for the UICP platform, including schedules, processes, and best practices.

---

## Maintenance Windows

### Standard Windows

| Day | Time (UTC) | Duration | Scope |
|-----|-------------|----------|-------|
| Tuesday | 02:00-04:00 | 2 hours | Non-critical updates |
| Thursday | 02:00-06:00 | 4 hours | Database maintenance |
| Saturday | 22:00-02:00 | 4 hours | Major deployments |

### Emergency Windows

Available 24/7 for critical security patches or urgent infrastructure issues.

---

## Maintenance Types

### 1. Database Maintenance

#### Index Rebuild
```bash
# Schedule during low-traffic window
# Run during Thursday maintenance window

# Check index fragmentation
psql -h db.uicp.io -U uicp -c "SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch FROM pg_stat_user_indexes ORDER BY idx_scan DESC;"

# Rebuild fragmented indexes
REINDEX INDEX CONCURRENTLY idx_user_email;
```

#### Vacuum Operations
```bash
# Analyze tables for query optimization
psql -h db.uicp.io -U uicp -c "ANALYZE;" 

# Vacuum to reclaim space (non-blocking)
psql -h db.uicp.io -U uicp -c "VACUUM ANALYZE;"

# For critical tables, use concurrent vacuum
psql -h db.uicp.io -U uicp -c "VACUUM (VERBOSE, ANALYZE) users;"
```

#### Connection Pool Cleanup
```bash
# Check for stale connections
psql -h db.uicp.io -U uicp -c "SELECT * FROM pg_stat_activity WHERE state = 'idle' AND state_change < now() - interval '1 hour';"

# Terminate stale connections
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle' AND state_change < now() - interval '1 hour';
```

---

### 2. Cache Maintenance

#### Redis Memory Optimization
```bash
# Check memory usage
redis-cli INFO memory | grep used

# Identify large keys
redis-cli --bigkeys

# Clear expired keys
redis-cli FLUSHDB async

# Verify memory after cleanup
redis-cli INFO memory | grep used
```

#### Cache Warming
```bash
# Pre-populate cache for critical data
python scripts/cache_warm.py --mode=critical

# Verify cache hit rates
redis-cli INFO stats | grep hit_rate
```

---

### 3. Log Maintenance

#### Archive Old Logs
```bash
# Archive logs older than 30 days
./scripts/archive-logs.sh --days=30 --destination=s3://uicp-logs-archive/

# Compress remaining logs
find /var/log/uicp -name "*.log" -mtime +7 -exec gzip {} \;

# Verify archive completion
aws s3 ls s3://uicp-logs-archive/ --recursive | wc -l
```

#### Log Rotation Configuration
```bash
# Check current rotation config
cat /etc/logrotate.d/uicp

# Test rotation
logrotate -d /etc/logrotate.d/uicp
```

---

### 4. Security Maintenance

#### Certificate Rotation
```bash
# Check certificate expiry
kubectl get certificates -n uicp

# Renew certificates
kubectl apply -f certificates/renew.yaml

# Verify new certificates
kubectl get certificates -n uicp | grep -E "READY|True"
```

#### Dependency Updates
```bash
# Check for outdated dependencies
npm audit --json > audit-report.json

# Update in staging first
npm update --save

# Test thoroughly before production
./tests/integration.sh --env=staging

# Deploy to production
./scripts/deploy.sh --env=production
```

---

### 5. Infrastructure Maintenance

#### Kubernetes Updates
```bash
# Check for node updates
kubectl get nodes

# Drain node for maintenance
kubectl drain node-{name} --ignore-daemonsets --delete-emptydir-data

# After maintenance, uncordon
kubectl uncordon node-{name}
```

#### Horizontal Pod Autoscaler Tuning
```bash
# Review HPA settings
kubectl get hpa -n uicp

# Adjust based on recent metrics
kubectl patch hpa api-gateway -n uicp -p '{"spec":{"maxReplicas":20}}'
```

---

## Pre-Maintenance Checklist

- [ ] Notify tenants 72 hours in advance (for > 30 min downtime)
- [ ] Update status page with maintenance window
- [ ] Verify backups completed successfully
- [ ] Ensure monitoring alerts are acknowledged
- [ ] Prepare rollback plan
- [ ] Confirm on-call coverage
- [ ] Test in staging environment
- [ ] Document expected impact

---

## During Maintenance

1. **Log all actions**
   ```bash
   ./scripts/maintenance-log.sh --start --type=database --ticket=JIRA-123
   ```

2. **Monitor key metrics**
   ```promql
   # Watch for anomalies
   rate(http_requests_failed_total[5m]) < 0.05
   uicp_service_health == 1
   ```

3. **Document progress**
   - Time each step completes
   - Note any unexpected findings
   - Update stakeholders every 30 minutes

---

## Post-Maintenance

1. **Verify services operational**
   ```bash
   ./scripts/health-check.sh --all-services
   ```

2. **Run smoke tests**
   ```bash
   ./tests/smoke-test.sh --env=production
   ```

3. **Update maintenance log**
   ```bash
   ./scripts/maintenance-log.sh --end --status=success
   ```

4. **Remove temporary blocks**
   ```bash
   redis-cli DEL maintenance:block:*
   ```

5. **Send completion notification**
   ```bash
   ./scripts/notify-maintenance-complete.sh --channels=slack,status-page
   ```

6. **Update documentation**
   - Note any issues encountered
   - Update runbooks if needed
   - Record time taken for planning

---

## Related Documents

- [Emergency Procedures](./emergency-procedures.md)
- [Operational Health Checks](./operational-health-checks.md)
- [Deployment Checklists](./deployment-checklists.md)