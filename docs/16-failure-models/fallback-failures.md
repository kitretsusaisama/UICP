# Fallback Failures

## Metadata

```yaml
title: Fallback Failures
domain: Resilience
owner: Platform Team
criticality: High
runtime-impact: Service degradation or full outage
security-impact: Potential unauthorized access via fallback paths
queue-impact: Queues may overflow if fallbacks fail
provider-impact: Multiple provider dependencies
tenant-impact: Cross-tenant failure propagation
ai-ingestable: true
review-cycle: Quarterly
last-reviewed: 2026-05-16
depends-on:
  - Circuit Breakers
  - Retry Mechanisms
  - Health Checks
related-docs:
  - docs/01-architecture/overview.md
  - docs/05-runbook/circuit-breaker.md
related-queues:
  - outbound-email
  - notification-delivery
related-services:
  - email-provider
  - notification-service
related-providers:
  - AWS SES
  - SendGrid
related-runtime-states:
  - DEGRADED
  - FAILOVER
related-threat-models:
  - Fallback Bypass Attack
```

## Symptoms

- **Primary path failures** that do not trigger fallback activation
- **Fallback loops** where primary and fallback both fail repeatedly
- **Silent degradation** where users receive degraded service without notification
- **Inconsistent behavior** across tenants due to different fallback configurations
- **Timeout cascades** when fallback connections also timeout

## Metrics

| Metric | Normal | Alert Threshold |
|--------|--------|-----------------|
| Fallback activation rate | < 1% | > 5% |
| Fallback failure rate | < 0.1% | > 1% |
| Fallback latency p99 | < 500ms | > 2000ms |
| Fallback circuit open | 0 | > 0 |
| Primary path availability | > 99.9% | < 99% |

## Propagation Chain

```
Primary Service Failure
        ↓
Circuit Breaker Opens
        ↓
Fallback Activation
        ↓
Fallback Overwhelmed OR
        ↓
Fallback Logic Bug → Unhandled Exception
        ↓
Complete Service Outage
```

## Debugging Steps

1. **Check circuit breaker state**
   ```bash
   kubectl get circuitbreakers -o wide
   ```

2. **Verify fallback configuration**
   ```bash
   curl -s service-endpoint/health | jq '.fallback'
   ```

3. **Review fallback activation logs**
   ```bash
   grep -i "fallback activated" /var/log/service.log
   ```

4. **Test fallback path manually**
   ```bash
   curl -X POST service-endpoint/fallback-test
   ```

5. **Check for fallback configuration drift**
   ```bash
   diff config/fallback-prod.yaml config/fallback-staging.yaml
   ```

## Mitigation

### Immediate Actions

1. **Disable failing fallbacks** to prevent cascade
2. **Route traffic to healthy secondary** path
3. **Activate static fallback responses** for critical endpoints
4. **Implement fallback throttling** to prevent fallback overload

### Preventive Measures

1. **Test fallbacks regularly** in production-like environments
2. **Implement fallback health checks** with dedicated probes
3. **Add timeout protection** for fallback paths (max 30s)
4. **Log all fallback activations** for pattern analysis
5. **Use dead letter queues** for fallback message persistence

## Rollback

```bash
# Revert fallback configuration
kubectl apply -f config/fallback-config-v1.yaml

# Reset circuit breaker
kubectl exec -it service-pod -- reset-circuit-breaker

# Restore primary path
kubectl scale deployment primary-service --replicas=3
```

## Recovery

1. **Verify primary path health** before disabling fallbacks
2. **Gradually restore traffic** to primary (10% → 50% → 100%)
3. **Monitor fallback activation rate** post-recovery
4. **Clear fallback circuit breaker** if stuck in open state
5. **Validate data consistency** across primary and fallback

## Postmortem Checklist

- [ ] Document root cause of primary failure
- [ ] Review fallback activation timing and thresholds
- [ ] Check if fallback had adequate capacity
- [ ] Validate fallback timeout configuration
- [ ] Review circuit breaker settings
- [ ] Add test case for this failure scenario
- [ ] Update runbook with lessons learned
- [ ] Verify all fallbacks have monitoring