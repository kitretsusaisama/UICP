# Rollback Strategy

## Metadata
```yaml
title: Rollback Strategy
domain: operations
owner: platform-team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: MEDIUM
provider-impact: NONE
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - docs/11-operations/deployment-checklists.md
  - docs/11-operations/runbooks/rollback-execution.md
related-docs:
  - docs/08-devops/ci-cd-pipeline.md
  - docs/06-architecture/deployment-architecture.md
related-queues:
  - deploy-notification
  - rollback-events
related-services:
  - deployment-service
  - api-gateway
  - all-services
```

---

## Overview

This document outlines the rollback strategy for UICP platform deployments, ensuring rapid recovery from failed or problematic releases while minimizing tenant impact.

---

## Rollback Triggers

### Automatic Triggers

| Condition | Threshold | Action |
|-----------|-----------|--------|
| Error rate spike | > 5% in 5 min | Auto-rollback |
| Latency p99 | > 2s for 5 min | Auto-rollback |
| Health check failures | > 50% for 2 min | Auto-rollback |
| Critical service down | Any for 1 min | Auto-rollback |

### Manual Triggers

- Security vulnerability detected in new version
- Data corruption or integrity issues
- Customer reports critical bugs
- Compliance violations discovered
- Performance degradation confirmed

---

## Rollback Types

### 1. Application Rollback

**Scope**: Single service or microservice

**Procedure**:
```bash
# Using kubectl
kubectl rollout undo deployment/{service-name} -n uicp

# Using our deployment system
curl -X POST https://deploy.uicp.io/rollback \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"service":"api-gateway","environment":"production"}'

# Verify rollback
kubectl rollout status deployment/{service-name} -n uicp
```

**Recovery Time**: 2-5 minutes

---

### 2. Database Migration Rollback

**Scope**: Schema changes, migrations

**Procedure**:
```bash
# Check migration status
kubectl exec -it postgres-primary-0 -- psql -U uicp -c "SELECT * FROM schema_migrations ORDER BY applied_at DESC LIMIT 5;"

# Downgrade using migration tool
kubectl exec -it migrate-job -- down --steps 1

# Or manually revert if needed
kubectl exec -it postgres-primary-0 -- psql -U uicp -f /rollback/schema_revert.sql
```

**Recovery Time**: 5-15 minutes

**Caution**: Some migrations cannot be rolled back safely. See [Migration Safety](./migration-safety.md).

---

### 3. Infrastructure Rollback

**Scope**: Kubernetes cluster, node pools, networking

**Procedure**:
```bash
# Rollback node pool
gcloud container node-pools rollback {node-pool-name} --cluster={cluster}

# Rollback VPC changes
terraform apply -destroy -target=module.vpc -var-file=rollback.tfvars

# Rollback Load Balancer config
kubectl apply -f load-balancer-backup.yaml
```

**Recovery Time**: 15-30 minutes

---

### 4. Full Environment Rollback

**Scope**: Entire production environment

**Procedure**:
```bash
# 1. Stop incoming traffic
kubectl scale ingress production --replicas=0 -n uicp

# 2. Restore database from snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier uicp-prod-rollback \
  --db-snapshot-identifier pre-deploy-snapshot

# 3. Restore Redis from backup
redis-cli SLAVEOF NO ONE
redis-cli BGSAVE
# Wait for backup, then restore

# 4. Deploy previous version to all services
./scripts/deploy-versions.sh --version=previous --env=production

# 5. Restore traffic
kubectl scale ingress production --replicas=1 -n uicp
```

**Recovery Time**: 30-60 minutes

---

## Rollback Decision Framework

```
                    ┌─────────────────────────┐
                    │  Deployment Failed?    │
                    └───────────┬─────────────┘
                                │
                    ┌──────────┴──────────┐
                    │                     │
                   YES                     NO
                    │                     │
     ┌─────────────┴──────────┐  ┌──────┴──────────┐
     │                         │  │                 │
┌────┴────┐              ┌─────┴───┴────┐    ┌──────┴──────┐
│Critical?│              │  Monitor     │    │  Continue   │
└────┬────┘              │  30 min      │    │  Monitoring │
     │                   └──────┬───────┘    └─────────────┘
   YES│NO                       │
     │  │                  ┌────┴────┐
     │  │                 │ Issue?   │
     │  │                 └─────┬────┘
     │  │                   YES │ NO
     │  │                    │   │
     ▼  ▼                    ▼   ▼
┌─────────┐            Rollback   Continue
│Rollback │
└─────────┘
```

---

## Rollback Verification

### Health Checks
```bash
# Verify all services running
kubectl get pods -n uicp -l app.kubernetes.io/version={previous-version}

# Check service health
for svc in api-gateway auth-service user-service; do
  curl -f https://$svc.uicp.io/health || exit 1
done
```

### Functional Tests
```bash
# Run smoke tests
./tests/smoke-test.sh --env=production

# Run critical path tests
./tests/critical-path.sh --env=production

# Verify tenant operations
./scripts/tenant-check.sh --sample=10
```

### Observability
```promql
# Verify error rates normalized
rate(http_requests_failed_total[5m]) < 0.01

# Verify latency normalized
histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m])) < 1

# Verify queue processing normal
delta(uicp_queue_depth[5m]) > -100
```

---

## Rollback Communication

### Internal
- Post to #ops-incidents: "Rolling back to v{previous-version} due to {reason}"
- Update PagerDuty incident status
- Notify on-call team via Slack

### External
- Status page update if customer-facing impact > 5 minutes
- Tenant notification if data/functionality impact
- Support team briefed for customer inquiries

---

## Rollback Documentation

After any rollback, document:

1. **What failed**: Error messages, metrics
2. **When detected**: Time from deploy to detection
3. **Rollback time**: Total time to restore
4. **Tenant impact**: Any affected customers
5. **Root cause**: Initial analysis
6. **Prevention**: Steps to prevent recurrence

```markdown
## Rollback Report - {DATE}

**Version**: v1.2.3 → v1.2.2
**Trigger**: 15% error rate spike
**Detection time**: 8 minutes post-deploy
**Rollback time**: 4 minutes
**Impact**: None (automated detection)

**Root cause**: New dependency introduced blocking API calls
**Fix applied**: Reverted dependency version
```

---

## Related Documents

- [Deployment Checklists](./deployment-checklists.md)
- [Emergency Procedures](./emergency-procedures.md)
- [Monitoring Alerts](./monitoring-alerts.md)