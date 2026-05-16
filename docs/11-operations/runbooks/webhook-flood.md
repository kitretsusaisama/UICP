# Runbook: Webhook Flood

## Metadata
```yaml
title: Webhook Flood Runbook
domain: operations
owner: platform-team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: NONE
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - docs/11-operations/runbooks/queue-storm.md
  - docs/11-operations/runbooks/ddos-response.md
related-docs:
  - docs/04-admissibility/webhook-design.md
  - docs/06-architecture/api-gateway.md
related-queues:
  - webhook-outbound
  - webhook-retry
  - webhook-dlq
related-services:
  - webhook-dispatcher
  - webhook-worker
  - api-gateway
```

---

## Scenario

External system sends excessive webhook events, overwhelming the webhook processing system and potentially causing downstream service degradation.

---

## Symptoms

- `uicp.webhook.received` spike > 10x normal rate
- `uicp.webhook.queue.backlog` increasing
- `uicp.webhook.delivery_failure` > 20%
- Worker pods hitting resource limits
- Tenant API rate limit errors
- Duplicate webhook deliveries

---

## Metrics

```promql
# Webhook receipt rate
rate(uicp_webhook_received_total[1m])

# Queue depth
uicp_webhook_queue_depth

# Delivery success rate
rate(uicp_webhook_delivered_total[5m]) / rate(uicp_webhook_sent_total[5m])

# Retry count
uicp_webhook_retry_count

# Processing latency
histogram_quantile(0.95, rate(uicp_webhook_processing_seconds_bucket[5m]))

# By source system
uicp_webhook_received_total by (source_system)
```

---

## Mitigation

### Immediate Actions (0-1 min)

1. **Identify Attack Source**
   ```bash
   # Check top sources of webhooks
   redis-cli KEYS "webhook:source:*" | head -20
   
   # Or from logs
   grep "webhook received" /var/log/uicp/api-gateway.log | jq '.source'
   ```

2. **Enable Source Filtering**
   ```bash
   # Block specific source temporarily
   redis-cli SET webhook:block:source:{SOURCE_ID} "true"
   
   # Or via API
   curl -X POST http://api-gateway/internal/webhook/filter \
     -d '{"source":"github","action":"block","duration":"30m"}'
   ```

3. **Implement Circuit Breaker**
   ```bash
   # Pause webhook processing for specific source
   kubectl set env deployment/webhook-dispatcher PAUSE_SOURCE={SOURCE_ID} -n uicp
   ```

### Short-term Actions (1-10 min)

1. **Scale Webhook Workers**
   ```bash
   kubectl scale deployment webhook-worker --replicas=10 -n uicp
   ```

2. **Increase Timeout**
   ```bash
   # Increase timeout to handle slow deliveries
   kubectl set env deployment/webhook-dispatcher WEBHOOK_TIMEOUT=30 -n uicp
   ```

3. **Reduce Retry Attempts**
   ```bash
   # Temporarily reduce retry count to free resources
   kubectl set env deployment/webhook-dispatcher MAX_RETRIES=2 -n uicp
   ```

4. **Enable Delivery Throttling**
   ```bash
   # Limit deliveries per second per tenant
   redis-cli SET webhook:rate-limit:global "1000"
   ```

5. **Queue Webhook Messages**
   ```bash
   # Enable message buffering instead of immediate delivery
   redis-cli SET webhook:mode "buffered"
   ```

---

## Rollback

To restore normal webhook processing:

```bash
# Unblock source
redis-cli DEL webhook:block:source:{SOURCE_ID}

# Restore worker count
kubectl scale deployment webhook-worker --replicas=3 -n uicp

# Restore retry count
kubectl set env deployment/webhook-dispatcher MAX_RETRIES=5 -n uicp

# Restore timeout
kubectl set env deployment/webhook-dispatcher WEBHOOK_TIMEOUT=10 -n uicp

# Restore normal mode
redis-cli SET webhook:mode "immediate"

# Remove global rate limit
redis-cli DEL webhook:rate-limit:global
```

---

## Recovery

1. Monitor webhook queue draining
2. Verify delivery success rate returns to > 95%
3. Process any stuck webhooks:
   ```bash
   # Replay from DLQ
   redis-cli LRANGE queue:webhook:dlq 0 -1 | while read msg; do
     redis-cli LPUSH queue:webhook:outbound "$msg"
   done
   ```
4. Notify affected tenants of potential delays
5. Review source system for configuration issues

---

## Observability Queries

```promql
# Webhook rate by tenant
rate(uicp_webhook_received_total[5m]) by (tenant_id, source_system)

# Delivery latency by endpoint
histogram_quantile(0.95, rate(uicp_webhook_delivery_seconds_bucket[5m])) by (endpoint)

# Failed deliveries by reason
rate(uicp_webhook_failed_total[5m]) by (error_type)

# Queue depth trend
delta(uicp_webhook_queue_depth[5m])

# Resource utilization
uicp_webhook_worker_cpu
uicp_webhook_worker_memory
```

---

## Contacts

- API Gateway Team: #api-gateway
- Security Team: #security-ops
- Affected Tenants: Direct outreach

---

## Related Runbooks

- [Queue Storm](./queue-storm.md)
- [DDoS Response](./ddos-response.md)
- [Webhook Retry Failure](./webhook-retry-failure.md)