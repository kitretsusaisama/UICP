# SES Throttling

## Metadata

```yaml
title: SES Throttling
domain: Email Delivery
owner: Platform Team
criticality: High
runtime-impact: Email delivery failures
security-impact: Phishing detection may be bypassed during throttling
queue-impact: Email queue backup
provider-impact: AWS SES rate limits
tenant-impact: Tenant-specific throttling possible
ai-ingestable: true
review-cycle: Monthly
last-reviewed: 2026-05-16
depends-on:
  - Email Provider Configuration
  - Retry Mechanisms
  - Rate Limiting
related-docs:
  - docs/01-architecture/overview.md
  - docs/06-design/email-delivery.md
  - docs/05-runbook/email-troubleshooting.md
related-queues:
  - email-outbound
  - email-dlq
related-services:
  - email-service
  - notification-service
related-providers:
  - AWS SES
  - AWS EC2
related-runtime-states:
  - PROVIDER_THROTTLED
  - EMAIL_BLOCKED
related-threat-models:
  - Reputation Damage
  - Email Deliverability Loss
```

## Symptoms

- **SMTP 554 rejection** from SES with "Throttling error"
- **Increased bounce rate** after sustained throttling
- **Email delivery delays** (queue latency > 10 minutes)
- **Account-level throttling** triggered by volume spike
- **Reputation score degradation** affecting deliverability

## Metrics

| Metric | Normal | Alert Threshold |
|--------|--------|-----------------|
| SES send success rate | > 98% | < 95% |
| SES throttle errors | < 0.5% | > 2% |
| Email queue latency | < 5min | > 30min |
| Daily email volume | Stable | > 50% increase |
| SES account health | Green | Yellow/Red |

## Propagation Chain

```
Volume Spike
        ↓
Exceeds SES Quota
        ↓
451 Throttle Response
        ↓
Messages Queue Locally
        ↓
Retry Without Backoff
        ↓
Further Throttling
        ↓
Queue Overflow → Email Loss
```

## Debugging Steps

1. **Check SES quota status**
   ```bash
   aws ses get-send-quota --region us-east-1
   ```

2. **Review throttle errors in logs**
   ```bash
   grep -i "throttle\|451\|rate limit" /var/log/email-service.log | tail -100
   ```

3. **Analyze email volume trends**
   ```bash
   prometheus_query('rate(emails_sent_total[5m])')
   ```

4. **Check SES reputation**
   ```bash
   aws ses get-sending-authorization-policy --identity email@example.com
   ```

5. **Review bounce/complaint rates**
   ```bash
   aws ses get-send-statistics
   ```

## Mitigation

### Immediate Actions

1. **Reduce send rate** to stay within quota
2. **Implement exponential backoff** on throttle errors
3. **Route through backup provider** (SendGrid)
4. **Pause non-critical email** sends
5. **Request SES quota increase** if legitimate need

### Preventive Measures

1. **Implement sending rate limiting** per tenant
2. **Use dedicated IP** with proper warm-up
3. **Monitor bounce/complaint rates** closely
4. **Implement email prioritization** (critical vs marketing)
5. **Add circuit breaker** for SES calls

## Rollback

```bash
# Restore normal SES configuration
kubectl apply -f config/ses-config-v1.yaml

# Clear throttle state
kubectl exec -it email-service-pod -- clear-throttle-state

# Re-enable full email volume
kubectl scale deployment email-service --replicas=3
```

## Recovery

1. **Monitor SES quota** recovery over time
2. **Gradually increase volume** once throttling clears
3. **Review queued messages** for stale emails
4. **Verify deliverability** returns to normal
5. **Clear dead letter queue** after recovery

## Postmortem Checklist

- [ ] Document root cause of volume spike
- [ ] Review sending rate limiting implementation
- [ ] Check if backoff was properly implemented
- [ ] Analyze SES quota sizing
- [ ] Review tenant-specific limits
- [ ] Verify circuit breaker activation
- [ ] Check alerting was triggered appropriately
- [ ] Update email capacity planning