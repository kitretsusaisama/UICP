# Dynamic Prioritization

## Metadata
```yaml
title: Dynamic Prioritization
domain: smart-tuning
owner: Platform Team
criticality: MEDIUM
runtime-impact: HIGH
security-impact: NONE
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 09-queues/queue-overview
  - 18-smart-tuning/queue-tuning.md
  - 18-smart-tuning/worker-concurrency.md
related-docs:
  - 18-smart-tuning/queue-tuning.md
  - 18-smart-tuning/worker-concurrency.md
  - 18-smart-tuning/fallback-tuning.md
related-queues:
  - All queues
related-services:
  - Priority Scheduler
  - Queue Manager
  - Load Balancer
related-providers: []
```

---

## Overview

Dynamic prioritization adjusts message processing order based on real-time conditions, ensuring that critical communications are processed promptly while maintaining fairness for lower-priority traffic. Unlike static priority systems that maintain fixed ordering regardless of circumstances, dynamic prioritization responds to changing load patterns and business requirements.

The prioritization system uses a multi-factor scoring algorithm that considers message urgency, tenant importance, waiting time, and system state to determine optimal processing order. This approach ensures that latency-sensitive communications receive appropriate attention while preventing lower-priority messages from experiencing unbounded delays.

---

## Priority Dimensions

Messages are evaluated across multiple priority dimensions:

**Urgency Priority** reflects the time-sensitivity of the communication. Time-critical alerts receive highest urgency priority, followed by transactional messages, and then promotional or batch communications. Urgency is specified by the sender but can be adjusted by the system based on message characteristics.

**Tenant Priority** reflects the tenant's subscription tier and historical behavior. Premium tenants receive elevated priority, ensuring that their messages are processed ahead of lower-tier tenants during high-load periods. Tenant priority can be temporarily increased during service incidents affecting that tenant.

**Wait-Time Priority** rewards messages that have been waiting longer, preventing starvation of lower-priority messages. The wait-time factor increases as message age exceeds expected processing times, ensuring eventual processing even under sustained high-load conditions.

---

## Priority Scoring Algorithm

The priority score is calculated using weighted factors:

```
PriorityScore = (urgencyWeight * urgencyScore) + (tenantWeight * tenantScore) + (waitTimeWeight * waitTimeScore) + (systemWeight * systemScore)

Where:
- urgencyScore = 1 for critical, 0.8 for high, 0.5 for normal, 0.2 for low
- tenantScore = tenant tier multiplier (1.0 to 3.0)
- waitTimeScore = min(waitTimeMinutes / maxAcceptableWait, 1.0)
- systemScore = adjustment based on queue depth and system load
```

The weights are configurable and can be adjusted to meet different operational requirements. The default configuration prioritizes urgency at 40%, tenant at 20%, wait time at 25%, and system state at 15%.

---

## Dynamic Weight Adjustment

Priority weights automatically adjust based on conditions:

**Load-Based Adjustment** increases the weight of system state factors when queue depth exceeds healthy thresholds, prioritizing messages that can be processed quickly to reduce overall queue depth. This prevents queue buildup during traffic spikes.

**Time-Based Adjustment** shifts priority toward wait-time factors during off-peak hours when system utilization is low, ensuring that lower-priority messages are not indefinitely delayed even when traffic is consistently high.

**Tenant Behavior Adjustment** increases tenant priority weight for tenants with consistent high-priority message patterns, recognizing that these tenants have genuine urgency requirements.

---

## Priority Queue Management

Multiple priority queues enable fine-grained control:

**Urgent Queue** processes time-critical messages with the lowest latency, operating with higher concurrency and shorter polling intervals than other queues. Messages in the urgent queue are processed before any other queue.

**Interactive Queue** handles transactional messages requiring sub-second response times, balancing between latency requirements and resource efficiency. This queue receives preferential treatment during moderate-load periods.

**Batch Queue** handles high-volume lower-priority traffic such as promotional emails and non-critical notifications. Batch processing is deferred to off-peak periods when possible to minimize resource competition.

---

## Starvation Prevention

Mechanisms prevent lower-priority messages from being indefinitely delayed:

**Maximum Wait Time** enforces hard limits on how long any message can wait in queue. When maximum wait time is exceeded, the message is promoted to higher priority regardless of its initial priority classification.

**Priority Decay** gradually reduces the effective priority of messages that remain at the front of the queue without being processed, ensuring that other messages have opportunities to proceed.

**Fair Share Allocation** ensures that no single sender can monopolize processing capacity regardless of priority, preventing priority manipulation through bulk message submission.

---

## Priority and Fallback Integration

Priority affects fallback behavior during provider failures:

**Priority-Aware Fallback** ensures that higher-priority messages are the first to switch to fallback providers when primary providers fail, maintaining reliability for critical communications.

**Priority-Based Retry** schedules retries for higher-priority messages more quickly than lower-priority messages, accelerating recovery for critical communications.

**Priority Preservation** ensures that message priority is maintained throughout the delivery lifecycle, from initial queue placement through all retry attempts and fallback transitions.

---

## Related Documents

- `09-queues/queue-overview.md`
- `18-smart-tuning/queue-tuning.md`
- `18-smart-tuning/worker-concurrency.md`