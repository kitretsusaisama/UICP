# Runbook: Redis Degradation

## Metadata
```yaml
title: Redis Degradation Runbook
domain: operations
owner: platform-team
criticality: HIGH
runtime-impact: CRITICAL
security-impact: LOW
queue-impact: CRITICAL
provider-impact: NONE
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - docs/11-operations/runbooks/redis-backup-failure.md
  - docs/05-incident/redis-failover.md
related-docs:
  - docs/06-architecture/caching-strategy.md
  - docs/06-architecture/infrastructure.md
related-queues:
  - session-cache
  - rate-limit
  - distributed-lock
related-services:
  - redis-cluster
  - session-service
  - rate-limiter
```

---

## Scenario

Redis cluster experiences latency spikes, connection failures, or memory pressure, impacting session management, caching, and distributed operations.

---

## Symptoms

- `redis_command_duration_p99` > 500ms
- `redis_rejected_connections` increasing
- `redis_memory_used_bytes` > 80% of max
- `redis_evicted_keys` > 0
- Application timeouts on cache operations
- Session invalidation spikes
- Rate limiter false positives

---

## Metrics

```promql
# Command latency
redis_command_duration_seconds{p99}

# Memory pressure
redis_memory_used_bytes / redis_memory_max_bytes

# Connection status
redis_connected_clients
redis_rejected_connections_total

# Key eviction
redis_evicted_keys_total

# Command errors
redis_command_errors_total

# Queue backup (if using Redis for queues)
uicp_redis_queue_depth
```

---

## Mitigation

### Immediate Actions (0-2 min)

1. **Check Redis Cluster Status**
   ```bash
   redis-cli -h redis-cluster-primary.cluster.uicp.io INFO | grep -E "used_memory_human|connected_clients|rejected"
   ```

2. **Identify Problematic Commands**
   ```bash
   redis-cli -h redis-cluster-primary.cluster.uicp.io INFO commandstats | head -20
   ```

3. **Flush Old Sessions (if memory critical)**
   ```bash
   # Clear expired sessions to free memory
   redis-cli --scan --pattern "session:*" | xargs -r redis-cli UNLINK
   ```

4. **Enable Connection Pooling**
   ```bash
   # Increase connection pool size in application config
   kubectl set env deployment/api-gateway REDIS_POOL_SIZE=50 -n uicp
   ```

### Short-term Actions (2-15 min)

1. **Add Read Replica**
   ```bash
   # Promote read replica to handle read-heavy workloads
   redis-cli REPLICAOF no one
   ```

2. **Reduce Cache TTL**
   ```bash
   # Temporarily reduce cache TTL to free memory
   redis-cli CONFIG SET maxmemory-policy allkeys-lru
   ```

3. **Scale Redis Cluster**
   ```bash
   # Add more nodes to cluster
   kubectl scale statefulset redis-node --replicas=6 -n uicp
   ```

4. **Enable Local Caching**
   ```bash
   # Enable in-memory cache fallback
   kubectl set env deployment/api-gateway ENABLE_LOCAL_CACHE=true -n uicp
   ```

---

## Rollback

To restore normal Redis configuration:

```bash
# Restore original memory policy
redis-cli CONFIG SET maxmemory-policy volatile-lru

# Reset connection pool size
kubectl set env deployment/api-gateway REDIS_POOL_SIZE=20 -n uicp

# Disable local cache fallback
kubectl set env deployment/api-gateway ENABLE_LOCAL_CACHE=false -n uicp
```

---

## Recovery

1. Monitor memory usage stabilizes below 70%
2. Verify command latency returns to < 50ms p99
3. Check evicted keys count returns to 0
4. Confirm session operations normalize
5. Review and address root cause (query patterns, memory leak, etc.)

```bash
# Verify recovery
redis-cli INFO | grep -E "used_memory_pct|evicted_keys|instantaneous_ops_per_sec"
```

---

## Observability Queries

```promql
# Redis latency by operation type
redis_command_duration_seconds{p99,cmd="get"}
redis_command_duration_seconds{p99,cmd="set"}
redis_command_duration_seconds{p99,cmd="hgetall"}

# Memory trend
redis_memory_used_bytes - redis_memory_max_bytes

# Connection pool exhaustion
rate(redis_rejected_connections_total[5m])

# Application impact
rate(http_requests_failed_total{reason="redis_timeout"}[5m])
rate(session_creation_failed_total[5m])
rate(rate_limit_blocked_total[5m])
```

---

## Contacts

- Redis Cloud Support: support@redis.com
- Infrastructure Team: #infrastructure-ops
- On-Call: PagerDuty

---

## Related Runbooks

- [Queue Storm](./queue-storm.md) - if queue processing is impacted
- [Session Service Failure](./session-failure.md)