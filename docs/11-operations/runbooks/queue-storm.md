# Runbook: Queue Storm

## Metadata
```yaml
title: Queue Storm Runbook
domain: operations
owner: platform-team
criticality: HIGH
runtime-impact: HIGH
security-impact: LOW
queue-impact: CRITICAL
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - docs/11-operations/runbooks/redis-degradation.md
  - docs/11-operations/runbooks/worker-failure.md
related-docs:
  - docs/06-architecture/message-queues.md
  - docs/05-incident/queue-backlog-analysis.md
related-queues:
  - email-outbound
  - notification
  - webhooks
  - audit-log
related-services:
  - queue-processor
  - worker-service
  - message-broker
```

---

## Scenario

Sudden spike in message volume causes queue backlog, processing delays, and potential message TTL expiration/loss.

---

## Symptoms

- `uicp.queue.backlog` increasing > 1000 messages/minute
- `uicp.queue.message_age` > 5 minutes
- `uicp.worker.cpu` > 90%
- `uicp.worker.message_processing_rate` declining
- Consumer lag increasing
- DLQ messages accumulating

---

## Metrics

```promql
# Queue depth by queue name
uicp_queue_depth{queue_name=~"email|notification|webhook"}

# Message processing rate
rate(uicp_messages_processed_total[1m])

# Consumer lag
uicp_consumer_lag

# Message age
uicp_queue_message_age_max

# Worker utilization
uicp_worker_cpu_utilization
uicp_worker_memory_utilization

# Error rate
rate(uicp_queue_message_failed_total[5m])
```

---

## Mitigation

### Immediate Actions (0-2 min)

1. **Pause Incoming Traffic (if severe)**
   ```bash
   # Enable circuit breaker
   kubectl exec -it redis-cli -- redis-cli SET circuit:queue:enabled "false"
   ```

2. **Scale Workers**
   ```bash
   # Auto-scale based on backlog
   kubectl autoscale deployment worker-service --min=5 --max=20 --cpu-percent=70 -n uicp
   
   # Or manual scale for immediate relief
   kubectl scale deployment worker-service --replicas=15 -n uicp
   ```

3. **Identify Source of Spike**
   ```bash
   # Check which tenant is causing the spike
   redis-cli LRANGE queue:email:outbound 0 100 | jq -r '.tenant_id' | sort | uniq -c | sort -rn
   ```

4. **Apply Rate Limiting**
   ```bash
   # Enable per-tenant rate limiting
   kubectl set env deployment/api-gateway ENABLE_TENANT_RATE_LIMIT=true -n uicp
   ```

### Short-term Actions (2-15 min)

1. **Implement Message Prioritization**
   ```bash
   # Move critical messages to front of queue
   redis-cli LTRIM queue:email:outbound 0 10000
   
   # Use sorted set for priority
   redis-cli ZADD queue:priority 999 "critical:msg:123"
   ```

2. **Enable Message Batching**
   ```bash
   # Increase batch size for faster processing
   kubectl set env deployment/worker-service BATCH_SIZE=100 -n uicp
   ```

3. **Clear Non-Critical Queues**
   ```bash
   # Temporarily pause low-priority queues
   redis-cli SET queue:audit:paused "true"
   ```

4. **Add Backpressure**
   ```bash
   # Reject new messages from source
   curl -X POST http://api-gateway/internal/circuit-breaker/enable -d '{"queue":"webhook","duration":"30m"}'
   ```

---

## Rollback

To restore normal queue processing:

```bash
# Scale workers back to normal
kubectl scale deployment worker-service --replicas=5 -n uicp

# Disable rate limiting
kubectl set env deployment/api-gateway ENABLE_TENANT_RATE_LIMIT=false -n uicp

# Resume paused queues
redis-cli SET queue:audit:paused "false"

# Reset batch size
kubectl set env deployment/worker-service BATCH_SIZE=10 -n uicp

# Disable circuit breaker
redis-cli SET circuit:queue:enabled "true"
```

---

## Recovery

1. Monitor backlog decreasing to normal levels (< 1000 messages)
2. Verify message age below 60 seconds
3. Check processing rate stable
4. Process any expired/DLQ messages:
   ```bash
   # Process DLQ with retries
   python scripts/process_dlq.py --queue email --retries 3
   ```
5. Analyze root cause and implement prevention

---

## Observability Queries

```promql
# Queue depth by tenant
uicp_queue_depth by (queue_name, tenant_id)

# Processing rate trend
rate(uicp_messages_processed_total[5m])

# Worker scale events
kube_pod_container_status_restarts{namespace="uicp", pod=~"worker.*"}

# Message failure by type
rate(uicp_queue_message_failed_total[5m]) by (queue_name, error_type)

# Backlog growth rate
delta(uicp_queue_depth[5m])
```

---

## Contacts

- Queue Infrastructure: #queue-ops
- DevOps On-Call: PagerDuty
- Tenant Relations: If tenant-induced

---

## Related Runbooks

- [Redis Degradation](./redis-degradation.md)
- [Webhook Flood](./webhook-flood.md)
- [Provider Failure](./provider-failure.md)