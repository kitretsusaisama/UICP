# Tenant Abuse

## Metadata

```yaml
title: Tenant Abuse
domain: Multi-Tenancy
owner: Platform Team
criticality: Critical
runtime-impact: Service degradation for all tenants
security-impact: Unauthorized access and data breaches
queue-impact: Queue exhaustion by abusive tenant
provider-impact: Provider quota exhaustion
tenant-impact: Resource starvation for legitimate tenants
ai-ingestable: true
review-cycle: Monthly
last-reviewed: 2026-05-16
depends-on:
  - Rate Limiting
  - Quota Management
  - Tenant Isolation
related-docs:
  - docs/04-security/tenant-isolation.md
  - docs/05-runbook/tenant-management.md
  - docs/08-threat-models/tenant-attacks.md
related-queues:
  - api-requests
  - background-jobs
  - webhook-events
related-services:
  - api-gateway
  - tenant-service
  - rate-limiter
related-providers:
  - All External Providers
related-runtime-states:
  - TENANT_OVERLOAD
  - RESOURCE_EXHAUSTION
related-threat-models:
  - Tenant Isolation Bypass
  - Resource Exhaustion Attack
  - Quota Circumvention
```

## Symptoms

- **Unusual API spike** from single tenant
- **Resource consumption** exceeding allocated quota
- **Queue depth explosion** from one tenant's jobs
- **Service degradation** for other tenants
- **API latency increase** across platform

## Metrics

| Metric | Normal | Alert Threshold |
|--------|--------|-----------------|
| Per-tenant API rate | < 1000/min | > 10000/min |
| Per-tenant queue depth | < 100 | > 5000 |
| Per-tenant CPU usage | < 50% | > 200% |
| Per-tenant storage | Stable | > 2x baseline |
| Concurrent requests | < 100 | > 1000 |

## Propagation Chain

```
Compromised Tenant Account
        ↓
Excessive API Calls
        ↓
Quota Exceeded (if present)
        ↓
Circuit Breaker Triggers
        ↓
All Tenant Requests Affected
        ↓
Service-Wide Outage
```

## Debugging Steps

1. **Identify abusive tenant**
   ```bash
   kubectl top pods --by-tenant
   kubectl logs api-gateway --tail=1000 | jq 'select(.tenant_id == "ABUSE")
   ```

2. **Analyze per-tenant metrics**
   ```bash
   prometheus_query('rate(api_requests{tenant!="trusted"}[5m])')
   ```

3. **Check quota enforcement**
   ```bash
   kubectl get quota -o wide
   kubectl describe resourcequota
   ```

4. **Review tenant activity logs**
   ```bash
   grep "tenant_id=ABUSE" /var/log/api-gateway.log | tail -1000
   ```

5. **Identify attack vector**
   ```bash
   curl -s service-endpoint/audit/tenant/ABUSE
   ```

## Mitigation

### Immediate Actions

1. **Suspend abusive tenant** immediately
   ```bash
   kubectl exec tenant-service -- suspend-tenant ABUSE
   ```

2. **Apply emergency rate limit** to tenant
   ```bash
   kubectl apply -f config/emergency-rate-limit.yaml
   ```

3. **Clear tenant's queue** to restore service
   ```bash
   kubectl delete jobs -l tenant=ABUSE
   ```

4. **Enable strict tenant isolation** in gateway

### Preventive Measures

1. **Implement per-tenant quotas** with enforcement
2. **Add tenant-level circuit breakers**
3. **Monitor tenant resource consumption** in real-time
4. **Implement tenant reputation scoring**
5. **Add anomaly detection** for tenant behavior

## Rollback

```bash
# Lift emergency rate limit
kubectl delete -f config/emergency-rate-limit.yaml

# Restore tenant access (after review)
kubectl exec tenant-service -- restore-tenant ABUSE

# Reset tenant resource counters
kubectl exec tenant-service -- reset-quota ABUSE
```

## Recovery

1. **Verify tenant isolation** is functioning
2. **Monitor other tenants** for lingering effects
3. **Review and adjust quotas** if needed
4. **Audit tenant data** for compromise indicators
5. **Document incident** for security review

## Postmortem Checklist

- [ ] Identify root cause of abuse (compromised credentials, malicious, bug)
- [ ] Review quota enforcement implementation
- [ ] Check circuit breaker activation timing
- [ ] Verify tenant isolation integrity
- [ ] Review anomaly detection alerts
- [ ] Assess damage to other tenants
- [ ] Implement additional tenant safeguards
- [ ] Update threat model with new attack vectors