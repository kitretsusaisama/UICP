# Retry Amplification

## Metadata

```yaml
title: Retry Amplification
domain: Reliability
owner: Platform Team
criticality: Critical
runtime-impact: System overload and cascading failures
security-impact: Resource exhaustion enables DoS
queue-impact: Queue explosion with exponential backlog
provider-impact: Provider rate limits triggered
tenant-impact: Resource starvation across tenants
ai-ingestable: true
review-cycle: Monthly
last-reviewed: 2026-05-16
depends-on:
  - Retry Mechanisms
  - Rate Limiting
  - Circuit Breakers
related-docs:
  - docs/01-architecture/overview.md
  - docs/07-design/resilience-patterns.md
  - docs/05-runbook/retry-configuration.md
related-queues:
  - email-outbound
  - webhooks-delivery
  - api-calls
related-services:
  - api-gateway
  - retry-handler
  - worker-service
related-providers:
  - AWS SES
  - External APIs
related-runtime-states:
  - OVERLOADED
  - RETRY_STORM
related-threat-models:
  - Retry-Based DoS
  - Cascading Failure
```

## Symptoms

- **Exponential queue growth** with messages increasing rapidly
- **Increased response latency** as workers struggle with backlog
- **Provider rate limit errors** from repeated retry attempts
- **Memory pressure** on retry handlers storing message state
- **Worker saturation** with all pods at 100% CPU utilization

## Metrics

| Metric | Normal | Alert Threshold |
|--------|--------|-----------------|
| Retry queue depth | < 100 | > 1000 |
| Retry rate | < 10/s | > 100/s |
| Duplicate message % | < 1% | > 10% |
| Retry backoff avg | < 5s | > 60s |
| Failed message age | < 1h | > 4h |

## Propagation Chain

```
Transient Failure
        ↓
Retry Without Backoff
        ↓
Multiple Retries Sent
        ↓
Provider Rate Limited
        ↓
More Retries Triggered
        ↓
Queue Explosion
        ↓
Worker Saturation
        ↓
Complete System Outage
```

## Debugging Steps

1. **Identify retry storm source**
   ```bash
   kubectl top pods | grep -E "retry|worker"
   kubectl get events --sort-by='.lastTimestamp' | grep retry
   ```

2. **Check queue depth explosion**
   ```bash
   kubectl get queues | awk '$3 > 1000 {print}'
   ```

3. **Analyze retry pattern**
   ```bash
   kubectl logs retry-handler --tail=1000 | grep "retry attempt"
   ```

4. **Identify rate-limited requests**
   ```bash
   grep "429" /var/log/api-gateway.log | wc -l
   ```

5. **Check backoff configuration**
   ```bash
   kubectl get configmap retry-config -o yaml | grep backoff
   ```

## Mitigation

### Immediate Actions

1. **Pause retry processing** temporarily
   ```bash
   kubectl scale deployment retry-handler --replicas=0
   ```

2. **Implement exponential backoff** if not present
3. **Add jitter** to retry intervals to prevent thundering herd
4. **Set max retry limit** (typically 3-5 attempts)
5. **Drain oldest messages** from queue to reduce memory

### Preventive Measures

1. **Implement circuit breaker** for external calls
2. **Use dead letter queues** after max retries
3. **Add retry budget** (max retries per minute)
4. **Implement idempotency** keys for deduplication
5. **Configure per-provider** retry limits

## Rollback

```bash
# Restore previous retry config
kubectl apply -f config/retry-config-v1.yaml

# Reset retry counters
kubectl exec -it worker-pod -- reset-retry-counters

# Scale up workers if throttled
kubectl scale deployment worker --replicas=10
```

## Recovery

1. **Gradually resume retry processing** (start with 1 pod)
2. **Monitor queue depth** closely during recovery
3. **Clear dead letter queue** after manual review
4. **Verify message ordering** for dependent messages
5. **Re-process failed messages** after fixing root cause

## Postmortem Checklist

- [ ] Document original failure that triggered retries
- [ ] Review retry backoff algorithm configuration
- [ ] Check if jitter was implemented
- [ ] Verify retry limits were respected
- [ ] Analyze why circuit breaker didn't activate
- [ ] Review rate limit handling strategy
- [ ] Add load test for retry storm scenario
- [ ] Update retry configuration documentation