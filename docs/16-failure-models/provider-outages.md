# Failure Model: Provider Outages

## Metadata
```yaml
title: Provider Outage Failure Model
domain: communication
criticality: HIGH
ai-ingestable: true
```

---

## Description

External email/SMS providers (SES, Resend, Msg91) may experience outages affecting message delivery.

---

## Symptoms

- Delivery failure rate spike
- Provider health check returns unhealthy
- Queue backlog increases
- Webhook events for failed deliveries

---

## Propagation Chain

```
1. Provider experiences outage (region, capacity, or technical)
2. API calls to provider fail or timeout
3. Message added to retry queue
4. If all providers fail, messages queue in DLQ
5. Users don't receive OTPs / notifications
6. Support tickets increase
```

---

## Provider Failure Impact Matrix

| Provider | Failure Impact | Critical Services |
|----------|----------------|-------------------|
| SES (Primary) | High | All email, password reset |
| Resend (Secondary) | Medium | Non-critical email |
| Maileroo (Tertiary) | Low | Fallback email |
| Msg91 (Primary SMS) | High | OTP, MFA |

---

## Mitigation Mechanisms

### 1. Automatic Failover
```
Provider Selection Logic:
1. Check provider health (cached)
2. Select highest-scoring available provider
3. If primary fails, auto-select secondary
4. Update provider scores based on success rate
```

### 2. Queue-Based Retry
- 3x exponential backoff (1s, 4s, 16s)
- Dead letter queue after max retries
- Manual intervention to replay DLQ messages

### 3. Provider Health Monitoring
- `/v1/providers/health` endpoint
- 30-second cache TTL
- Automatic score degradation on failures

---

## Recovery Strategy

### Immediate (0-5 min)
1. Monitor provider health endpoint
2. Verify failover to backup provider
3. Check queue depth for backlog

### Short-term (5-30 min)
1. If failover failed, manual provider switch
2. Process DLQ messages
3. Communicate status to stakeholders

### Long-term (30+ min)
1. Engage provider support (SES: AWS Support)
2. Evaluate alternative providers
3. Implement temporary workarounds

---

## Observability

| Metric | Alert Threshold |
|--------|-----------------|
| `uicp.provider.delivery_failure` | >5% |
| `uicp.provider.latency_p99` | >5000ms |
| `uicp.queue.email.backlog` | >10000 |
| `uicp.provider.health` | unhealthy |

---

## Runbook

```bash
# Check provider health
curl https://api.uicp.example/v1/providers/health

# Manual provider override (if needed)
# Edit REDIS_KEY: provider:scores
# Set specific provider as primary

# Process DLQ messages
# Use admin endpoint to replay failed messages
```

---

## Related Documents

- `04-communication/provider-selection.md`
- `04-communication/provider-health.md`
- `11-operations/runbooks/provider-failure.md`

