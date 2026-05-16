# Deployment Checklists

## Metadata
```yaml
title: Deployment Checklists
domain: devops
owner: platform-team
criticality: HIGH
runtime-impact: HIGH
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - docs/11-operations/runbooks/deployment-failure.md
  - docs/11-operations/rollback-strategy.md
related-docs:
  - docs/08-devops/ci-cd-pipeline.md
  - docs/08-devops/release-management.md
  - docs/07-security/code-security-requirements.md
related-queues:
  - deploy-events
  - release-notifications
related-services:
  - deployment-service
  - ci-pipeline
```

---

## Pre-Deployment Checklist

### Code Review

- [ ] All PRs approved by at least 2 reviewers
- [ ] No critical or high security findings
- [ ] Unit test coverage > 80%
- [ ] Integration tests passing
- [ ] No TODO comments in production code
- [ ] Changelog updated with user-facing changes
- [ ] Breaking changes documented

### Security

- [ ] Dependencies scanned (no known vulnerabilities)
- [ ] No hardcoded secrets or credentials
- [ ] Environment variables properly configured
- [ ] Secrets stored in secure vault
- [ ] Security review completed for new features
- [ ] Compliance requirements met

### Database

- [ ] Migration files reviewed
- [ ] Migration tested in staging
- [ ] Rollback migration available
- [ ] No long-running queries introduced
- [ ] Index impact analyzed
- [ ] Data migration script tested

### Configuration

- [ ] Feature flags configured for gradual rollout
- [ ] Environment-specific configs verified
- [ ] API rate limits adjusted if needed
- [ ] Monitoring/alerting thresholds reviewed
- [ ] Logging level appropriate

---

## Staging Deployment Checklist

### Pre-Deployment

- [ ] Staging environment healthy
- [ ] Latest main branch deployed to staging
- [ ] Database migrations applied
- [ ] External services (SES, Redis) connected
- [ ] Health checks passing

### Deployment

- [ ] Deployment pipeline triggered
- [ ] Blue/green or canary strategy selected
- [ ] Initial traffic percentage: 5%
- [ ] Deployment progress monitored
- [ ] No errors in deployment logs

### Post-Deployment

- [ ] Smoke tests passing
- [ ] API health check passing
- [ ] Database connections healthy
- [ ] Cache warming complete
- [ ] Metrics flowing to dashboards
- [ ] Logs appearing in log aggregation
- [ ] Error rate < 1%
- [ ] Latency p99 < 2s

### Verification

- [ ] End-to-end tests passing
- [ ] Critical user journeys working
- [ ] Admin console accessible
- [ ] Tenant operations functional
- [ ] Background jobs processing

---

## Production Deployment Checklist

### Pre-Deployment (T-24h)

- [ ] Change request submitted
- [ ] Stakeholders notified
- [ ] Rollback plan documented
- [ ] On-call engineer briefed
- [ ] Maintenance window scheduled
- [ ] Status page updated

### Pre-Deployment (T-1h)

- [ ] Final smoke tests in staging
- [ ] Pre-deployment backup completed
- [ ] Monitoring dashboards ready
- [ ] Incident channel created
- [ ] All on-call engineers acknowledged

### Deployment

#### Step 1: Preparation
```bash
# Verify current state
kubectl get deployments -n uicp
kubectl get pods -n uicp -l app=uicp

# Check resource availability
kubectl describe nodes | grep -E "Allocated resources|Total CPU"
```

#### Step 2: Deployment
```bash
# Deploy to canary group (10% traffic)
kubectl set image deployment/api-gateway api-gateway=registry.uicp.io/api-gateway:v{new-version} -n uicp

# Or use deployment controller
curl -X POST https://deploy.uicp.io/deploy \
  -d '{"version":"v{new-version}","strategy":"canary","traffic":10}'
```

#### Step 3: Verification
```bash
# Check pod status
kubectl rollout status deployment/api-gateway -n uicp

# Check health
curl -s https://api-gateway.uicp.io/health

# Check metrics
promql_query "rate(http_requests_total{service='api-gateway'}[5m])"
```

#### Step 4: Traffic Increase
```bash
# Increase to 50%
curl -X POST https://deploy.uicp.io/deploy \
  -d '{"version":"v{new-version}","traffic":50}'

# Wait 10 minutes, monitor errors
sleep 600

# Increase to 100%
curl -X POST https://deploy.uicp.io/deploy \
  -d '{"version":"v{new-version}","traffic":100}'
```

### Post-Deployment (T+1h)

- [ ] Error rate < 0.5%
- [ ] Latency normalized
- [ ] No new alerts triggered
- [ ] Queue processing normal
- [ ] Database performance normal

### Post-Deployment (T+24h)

- [ ] Complete error rate analysis
- [ ] No memory leaks detected
- [ ] No connection leaks
- [ ] Monitoring baseline updated
- [ ] Documentation updated if needed

---

## Rollback Checklist

If issues detected during or after deployment:

### Immediate (0-5 min)

- [ ] Identify issue severity
- [ ] Execute rollback command
```bash
# Rollback to previous version
kubectl rollout undo deployment/api-gateway -n uicp

# Or specific version
kubectl rollout undo deployment/api-gateway -n uicp --to-revision=3
```

- [ ] Verify rollback succeeded
- [ ] Check system health

### Post-Rollback (5-30 min)

- [ ] Confirm error rate returning to normal
- [ ] Monitor for 30 minutes minimum
- [ ] Document incident details
- [ ] Schedule post-mortem

---

## Emergency Deployment (Hotfix)

For critical production issues requiring immediate deployment:

### Prerequisites

- [ ] Severity: P0 or P1 confirmed
- [ ] Change request fast-tracked
- [ ] Security review if applicable
- [ ] Sign-off from VP Engineering or CTO

### Process

```bash
# 1. Create hotfix branch
git checkout -b hotfix/critical-fix

# 2. Make minimal fix
# ... make changes ...

# 3. Fast-forward through pipeline
# Approval: Skip standard review, get verbal approval
# Deploy: Use canary with 20% traffic initially

# 4. Monitor closely
# 5. If issues: Immediate rollback
```

---

## Deployment Sign-Off

### Pre-Production Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Engineering Lead | | | |
| Security Review | | | |
| QA Lead | | | |
| Product Owner | | | |

### Production Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| On-Call Engineer | | | |
| Engineering Lead | | | |
| VP Engineering | | | (if P0/P1) |

---

## Related Documents

- [Rollback Strategy](./rollback-strategy.md)
- [Emergency Procedures](./emergency-procedures.md)
- [CI/CD Pipeline](./ci-cd-pipeline.md)