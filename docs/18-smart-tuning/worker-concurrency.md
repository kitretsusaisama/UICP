# Worker Concurrency

## Metadata
```yaml
title: Worker Concurrency
domain: smart-tuning
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: NONE
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 02-runtime/worker-runtime
  - 09-queues/queue-overview
  - 18-smart-tuning/queue-tuning.md
related-docs:
  - 18-smart-tuning/queue-tuning.md
  - 18-smart-tuning/adaptive-rate-limits.md
  - 18-smart-tuning/dynamic-prioritization.md
related-queues:
  - All queues
related-services:
  - Worker Pool
  - Queue Consumer
  - Concurrency Manager
related-providers:
  - All providers
```

---

## Overview

Worker concurrency tuning configures how many parallel operations each worker can perform, balancing between throughput optimization and resource consumption. Proper concurrency configuration ensures that the system processes messages as quickly as possible while preventing resource exhaustion that could cause system instability.

The concurrency system adapts dynamically to workload changes, scaling concurrency based on queue depth, provider capacity, and system resource availability. This adaptive approach ensures optimal performance across varying load conditions without manual reconfiguration.

---

## Concurrency Models

Different concurrency models suit different workloads:

**Fixed Concurrency** assigns a static number of concurrent operations per worker, suitable for predictable workloads where resource consumption should remain constant. Default fixed concurrency is 10 operations per worker, providing a balance between throughput and resource usage.

**Dynamic Concurrency** adjusts concurrency based on current conditions, increasing during high-load periods and decreasing during low-load periods. The adjustment algorithm considers queue depth, message priority distribution, and recent error rates.

**Provider-Aware Concurrency** limits concurrency per provider based on rate limits and provider-advertised capacity. Concurrency automatically decreases when provider responses indicate rate limit proximity, preventing rejected requests that would waste worker resources.

---

## Concurrency Limits

System-wide and per-tenant limits prevent resource exhaustion:

| Limit Type | Default Value | Description |
|------------|---------------|-------------|
| Global Max Concurrency | 1000 | Maximum across all workers |
| Per-Worker Max | 50 | Maximum per individual worker |
| Per-Provider Max | 100 | Maximum for single provider |
| Per-Tenant Max | 200 | Maximum for single tenant |

These limits are configurable with tenant-specific overrides available for premium customers requiring higher throughput. Limits are enforced at the worker level, preventing any single component from consuming disproportionate resources.

---

## Scaling Behavior

Worker concurrency scales automatically based on demand:

**Scale-Up Triggers** activate when queue depth exceeds 1000 messages for more than 60 seconds, or when average message processing time exceeds 500ms. Scale-up increases concurrency by 20% per trigger, up to the configured maximum.

**Scale-Down Triggers** activate when queue depth falls below 100 messages and processing latency is below 100ms for 5 minutes. Scale-down decreases concurrency by 10% per trigger, down to the configured minimum of 2 concurrent operations per worker.

**Hysteresis** prevents oscillation between scale-up and scale-down states by requiring sustained conditions before triggering state changes. This prevents thrashing where the system repeatedly scales up and down in response to minor fluctuations.

---

## Resource Management

Concurrency must be balanced against resource availability:

**Memory-Based Throttling** reduces concurrency when memory utilization exceeds 80%, preventing out-of-memory failures that could terminate workers. The reduction is proportional to memory pressure, scaling down to 50% of normal concurrency at 90% memory utilization.

**CPU-Based Throttling** reduces concurrency when CPU utilization exceeds 85%, preventing CPU saturation that would degrade performance for all processed messages. Concurrency is reduced by 15% for each 5% of CPU utilization above the threshold.

**Network-Bandwidth Awareness** limits concurrency when network bandwidth approaches saturation, preventing connection failures that would result from overwhelming network capacity. This is particularly important for providers in distant geographic regions.

---

## Priority-Based Concurrency Allocation

Different message priorities receive different concurrency treatment:

**Urgent Queue** operates with higher concurrency minimums (always at least 20 concurrent operations) to ensure rapid processing regardless of overall system state. Urgent messages bypass concurrency limits applied to lower-priority traffic.

**Batch Queue** operates with lower concurrency maximums (no more than 5 concurrent operations) to prevent batch processing from consuming resources needed for real-time message delivery. Batch operations are processed during off-peak periods when possible.

**Fair Queuing** ensures that no single tenant can monopolize available concurrency through quota enforcement. Tenant concurrency allocation is tracked in real-time, with excess allocations queued until capacity becomes available.

---

## Monitoring and Adjustment

Concurrency is monitored and adjusted based on metrics:

**Concurrency Metrics** track active concurrency, queued requests, and concurrency limit utilization. These metrics are exposed in dashboards and used for auto-scaling decisions.

**Performance Metrics** track throughput per concurrency unit, identifying the optimal concurrency level where throughput per unit is maximized. Beyond this point, additional concurrency provides diminishing returns.

**Alerting** triggers when concurrency consistently hits limits (indicating insufficient capacity) or when concurrency scaling oscillates frequently (indicating configuration issues requiring adjustment).

---

## Related Documents

- `02-runtime/worker-runtime.md`
- `18-smart-tuning/queue-tuning.md`
- `18-smart-tuning/adaptive-rate-limits.md`