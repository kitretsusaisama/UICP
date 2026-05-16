# Runbook: SES Outage

## Metadata
```yaml
title: SES Outage Runbook
domain: operations
owner: platform-team
criticality: HIGH
runtime-impact: HIGH
security-impact: LOW
queue-impact: HIGH
provider-impact: CRITICAL
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - docs/11-operations/runbooks/provider-failure.md
  - docs/11-operations/runbooks/email-queue-management.md
related-docs:
  - docs/06-architecture/infrastructure.md
  - docs/04-admissibility/email-design.md
related-queues:
  - email-outbound
  - email-dlq
related-services:
  - ses-adapter
  - email-processor
  - notification-service
```

---

## Scenario

AWS SES experiences regional outage or throttling, impacting email delivery for all tenants.

---

## Symptoms

- `uicp.ses.delivery_failure` > 10%
- `uicp.ses.bounce_rate` > 5%
- `uicp.email.queue.backlog` increasing rapidly
- SES Console shows service unavailable or degraded
- Customer reports of missing transactional emails

---

## Metrics

```promql
# Delivery failure rate
rate(uicp_email_delivery_failed_total[5m]) / rate(uicp_email_sent_total[5m])

# Queue backlog
uicp_email_queue_depth

# SES throttling
aws_ses_throttle_count

# Bounce rate
rate(uicp_email_bounced_total[5m]) / rate(uicp_email_sent_total[5m])
```

---

## Mitigation

### Immediate Actions (0-5 min)

1. **Verify SES Status**
   ```bash
   curl -s https://status.aws.amazon.com/data.json | jq '.services[] | select(.name=="ses")'
   ```

2. **Enable Fallback Provider**
   ```bash
   # Set Resend as primary in Redis
   redis-cli SET provider:email:primary "resend"
   redis-cli SET provider:email:fallback "ses"
   ```

3. **Pause New Email Processing**
   ```bash
   # Scale down email processor to prevent queue explosion
   kubectl scale deployment email-processor --replicas=0 -n uicp
   ```

4. **Clear SES Cache**
   ```bash
   redis-cli DEL provider:ses:health
   ```

### Short-term Actions (5-30 min)

1. **Route Through Backup Provider**
   - Verify Resend is processing emails
   - Monitor delivery rates on backup

2. **Notify Stakeholders**
   ```bash
   # Trigger PagerDuty incident
   curl -X POST https://events.pagerduty.com/v2/enqueue \
     -H 'Content-Type: application/json' \
     -d '{"routing_key":"KEY","payload":{"summary":"SES Outage - Fallover Active"}}'
   ```

3. **Monitor DLQ**
   ```bash
   # Watch DLQ growth
   redis-cli LLEN queue:email:dlq
   ```

---

## Rollback

To restore SES as primary provider:

```bash
# Restore SES configuration
redis-cli SET provider:email:primary "ses"
redis-cli SET provider:email:fallback "resend"

# Clear cache to force re-evaluation
redis-cli DEL provider:email:health

# Scale up email processor
kubectl scale deployment email-processor --replicas=3 -n uicp
```

---

## Recovery

1. Monitor SES status page for resolution
2. Once SES recovers, gradually shift traffic back:
   ```bash
   # Add 10% traffic every 5 minutes
   for i in {1..10}; do
     redis-cli SET provider:ses:weight $((i * 10))
     sleep 300
   done
   ```
3. Process DLQ messages:
   ```bash
   # Replay DLQ to new primary
   redis-cli LRANGE queue:email:dlq 0 -1 | while read msg; do
     redis-cli LPUSH queue:email:outbound "$msg"
   done
   ```
4. Verify email delivery恢复正常 for all tenants

---

## Observability Queries

```promql
# Check email delivery by provider
sum(rate(uicp_email_delivered_total{provider="ses"}[5m])) by (tenant_id)
sum(rate(uicp_email_delivered_total{provider="resend"}[5m])) by (tenant_id)

# Email latency by provider
histogram_quantile(0.95, rate(uicp_email_latency_seconds_bucket{provider="ses"}[5m]))
histogram_quantile(0.95, rate(uicp_email_latency_seconds_bucket{provider="resend"}[5m]))

# DLQ depth
uicp_email_dlq_depth

# Tenant impact
sum(rate(uicp_email_failed_total[5m])) by (tenant_id, provider) > 100
```

---

## Contacts

- AWS Support: https://console.aws.amazon.com/support
- Resend Support: support@resend.com
- Internal On-Call: PagerDuty escalation

---

## Related Runbooks

- [Provider Failure](./provider-failure.md)
- [Queue Storm](./queue-storm.md)