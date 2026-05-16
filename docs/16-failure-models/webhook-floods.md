# Webhook Floods

## Metadata

```yaml
title: Webhook Floods
domain: Event Processing
owner: Platform Team
criticality: High
runtime-impact: Service overload and message loss
security-impact: DoS via webhook endpoint
queue-impact: Massive queue buildup
provider-impact: External provider timeout
tenant-impact: Selective tenant impact possible
ai-ingestable: true
review-cycle: Monthly
last-reviewed: 2026-05-16
depends-on:
  - Rate Limiting
  - Queue Management
  - Circuit Breakers
related-docs:
  - docs/02-event-architecture/webhooks.md
  - docs/05-runbook/webhook-handling.md
related-queues:
  - webhook-inbound
  - webhook-processing
  - webhook-dlq
related-services:
  - webhook-ingestor
  - webhook-processor
  - event-router
related-providers:
  - External API Providers
  - Payment Gateways
  - CRM Systems
related-runtime-states:
  - WEBHOOK_OVERLOAD
  - MESSAGE_LOSS
related-threat-models:
  - Webhook-Based DoS
  - Replay Attacks
  - Event Injection
```

## Symptoms

- **Sudden spike** in webhook requests
- **HTTP 429 errors** from our webhook endpoint
- **Webhooks dropped** without processing
- **Webhook timeout** from providers
- **Processing lag** exceeding 5 minutes

## Metrics

| Metric | Normal | Alert Threshold |
|--------|--------|-----------------|
| Webhook requests/sec | < 100 | > 1000 |
| Webhook queue depth | < 500 | > 5000 |
| Webhook processing time | < 1s | > 10s |
| Webhook drop rate | < 0.1% | > 5% |
| Provider timeout rate | < 1% | > 10% |

## Propagation Chain

```
External System Event Spike
        ↓
Webhook Burst Arrives
        ↓
Rate Limiter Bypassed or Inadequate
        ↓
Webhook Queue Overflow
        ↓
Messages Dropped or Delayed
        ↓
Processing Lag → Provider Timeout
        ↓
Event Data Loss
```

## Debugging Steps

1. **Identify webhook spike source**
   ```bash
   kubectl logs webhook-ingestor --tail=1000 | grep -E "source=|provider="
   ```

2. **Check webhook queue depth**
   ```bash
   kubectl get queues webhook-inbound -o wide
   ```

3. **Analyze webhook processing rate**
   ```bash
   prometheus_query('rate(webhooks_processed_total[5m])')
   ```

4. **Review rate limit configuration**
   ```bash
   kubectl get configmap webhook-config -o yaml
   ```

5. **Check for message loss**
   ```bash
   kubectl get events | grep webhook | grep -i "drop\|fail\|error"
   ```

## Mitigation

### Immediate Actions

1. **Enable aggressive rate limiting**
   ```bash
   kubectl apply -f config/webhook-rate-limit-emergency.yaml
   ```

2. **Scale webhook processors**
   ```bash
   kubectl scale deployment webhook-processor --replicas=20
   ```

3. **Implement webhook backpressure**
   ```bash
   curl -X POST service-endpoint/admin/enable-backpressure
   ```

4. **Activate webhook circuit breaker**

### Preventive Measures

1. **Implement per-provider rate limits**
2. **Add webhook deduplication** for identical events
3. **Use pull-based webhook fetching** where possible
4. **Configure adaptive rate limiting**
5. **Implement webhook replay capability**

## Rollback

```bash
# Remove emergency rate limits
kubectl delete -f config/webhook-rate-limit-emergency.yaml

# Reset webhook processor state
kubectl exec -it webhook-processor-pod -- reset-state

# Resume normal scaling
kubectl scale deployment webhook-processor --replicas=5
```

## Recovery

1. **Process backlogged webhooks** in priority order
2. **Verify no data loss** by comparing event counts
3. **Re-request critical webhooks** from providers if supported
4. **Monitor for delayed processing** effects
5. **Clear dead letter queue** after review

## Postmortem Checklist

- [ ] Identify source of webhook spike
- [ ] Review rate limiting configuration adequacy
- [ ] Check webhook processing capacity planning
- [ ] Analyze why backpressure didn't activate
- [ ] Review provider timeout handling
- [ ] Verify message delivery guarantees
- [ ] Assess webhook retry strategy effectiveness
- [ ] Update capacity planning for peak scenarios