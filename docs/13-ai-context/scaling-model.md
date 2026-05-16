# Scaling Model - AI Context

## Metadata
```yaml
title: Scaling Model
domain: ai-context
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - system-summary.md
  - operational-constraints.md
related-docs:
  - 02-architecture/scaling-strategy.md
  - 06-operations/capacity-planning.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
related-services:
  - api-gateway
  - notification-service
  - worker-pool
related-runtime-states:
  - normal
  - scaled
  - constrained
```

---

## Scaling Strategies

### Horizontal Scaling (Stateless)
- **API Gateway**: Add instances behind load balancer
- **Application Services**: Kubernetes pod replication
- **Worker Pool**: Increase concurrent consumers

### Vertical Scaling (Stateful)
- **Redis**: Increase memory for session storage
- **MySQL**: Increase CPU for query processing
- **Worker**: Increase concurrency per worker

### Database Scaling
- **Read Replicas**: For query-heavy workloads
- **Connection Pooling**: Max 100 connections
- **Sharding**: For tenant-level data separation

---

## Scaling Triggers

| Metric | Threshold | Action |
|--------|-----------|--------|
| API latency | > 200ms avg | Scale API Gateway |
| Queue depth | > 5k messages | Scale workers |
| CPU usage | > 70% | Vertical scale |
| Memory | > 80% | Scale Redis |
| Connection pool | > 80% | Optimize queries |

---

## Scaling Limits

| Resource | Soft Limit | Hard Limit |
|----------|------------|------------|
| API Gateway instances | 10 | 50 |
| Worker concurrency | 20 | 100 |
| Redis memory | 10GB | 100GB |
| MySQL connections | 100 | 200 |
| Queue depth | 10k | 50k |

---

## Tenant Scaling Considerations

| Tenant Type | Scale Factor | Isolation |
|-------------|---------------|-----------|
| Enterprise | 10x baseline | Dedicated resources |
| Standard | 1x baseline | Shared pool |
| Trial | 0.1x baseline | Rate limited |

---

## Cost Optimization

1. **Auto-scaling**: Scale based on demand
2. **Spot instances**: For worker pools
3. **Reserved capacity**: For baseline load
4. **Provider quotas**: Optimize cost per delivery

---

## Related Context Files

- `operational-constraints.md` - Capacity limits
- `fallback-model.md` - Degraded mode scaling
- `system-summary.md` - Architecture overview

---

*AI-Ingestible: true | Scaling context for AI understanding*