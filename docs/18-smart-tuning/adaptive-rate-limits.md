# Adaptive Rate Limits

## Metadata
```yaml
title: Adaptive Rate Limits
domain: smart-tuning
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: MEDIUM
provider-impact: HIGH
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 02-runtime/cache-runtime
  - 04-communication/provider-runtime
  - 18-smart-tuning/provider-scoring.md
related-docs:
  - 18-smart-tuning/worker-concurrency.md
  - 18-smart-tuning/queue-tuning.md
  - 18-smart-tuning/operational-guardrails.md
related-queues:
  - Rate Limit Queue
related-services:
  - Rate Limiter
  - Quota Manager
  - Provider Monitor
related-providers:
  - All providers
```

---

## Overview

Adaptive rate limits dynamically adjust request throttling based on real-time system state, provider capacity, and tenant behavior. Unlike static rate limits that remain constant regardless of conditions, adaptive limits ensure that the system operates at optimal capacity while preventing overload that could cause failures.

The adaptive rate limiting system continuously monitors provider health, system load, and tenant consumption patterns, automatically adjusting limits to match current conditions. This approach maximizes throughput during healthy conditions while maintaining protection during adverse conditions.

---

## Rate Limit Components

Rate limits operate at multiple granularities:

**Tenant Rate Limits** control the overall request rate per tenant, preventing any single tenant from monopolizing system resources. Default limits are calculated based on tenant subscription tier, with higher tiers receiving higher allocations.

**Provider Rate Limits** control request rates per provider, ensuring that traffic never exceeds provider-advertised limits. These limits are dynamically adjusted based on remaining provider quota and recent utilization patterns.

**Endpoint Rate Limits** control request rates per specific API endpoint, ensuring that no single operation type consumes disproportionate capacity. Different endpoints have different limits based on their computational cost and frequency of use.

---

## Adaptation Strategies

Rate limits adapt based on multiple factors:

**Provider Capacity Adaptation** increases rate limits when provider health is excellent (low error rates, low latency) and decreases limits when provider health degrades. The adaptation uses a proportional algorithm that gradually adjusts limits to match observed provider capability.

**Time-Based Adaptation** increases limits during historically low-traffic periods and decreases limits during peak periods. Historical traffic patterns are analyzed to predict optimal limit values for each hour of the day and day of the week.

**Tenant Behavior Adaptation** increases limits for tenants with consistent, well-behaved traffic patterns while maintaining stricter limits for tenants with variable or problematic patterns. This incentivizes good behavior while protecting against abuse.

---

## Quota Management

Quota tracking ensures fair resource allocation:

**Quota Allocation** provides each tenant with a daily, weekly, and monthly quota based on subscription tier. Quota consumption is tracked in real-time, with visual indicators available in tenant dashboards.

**Quota Overflow Handling** specifies what happens when tenants exceed allocated quota. Options include queuing messages for later processing (default), rejecting messages immediately, or upgrading to burst quota at additional cost.

**Quota Rollover** specifies whether unused quota rolls over to future periods. Standard tiers do not include rollover, while premium tiers include partial rollover of up to 20% of the period allocation.

---

## Burst Handling

Burst allowances enable short-term traffic spikes:

**Burst Tokens** accumulate during low-traffic periods, enabling burst capacity when needed. Token accumulation rate is proportional to the difference between actual usage and allocated limits, with a maximum burst allowance of 150% of standard limits.

**Burst Exhaustion** triggers gradual throttling as burst tokens are consumed, preventing sudden cutoff that could disrupt critical operations. Throttling continues until traffic returns to within standard limits.

**Burst Recovery** gradually restores burst tokens after burst periods end, ensuring that burst capacity is available for future spikes without penalizing sustained moderate traffic.

---

## Provider Rate Limit Integration

Provider rate limits are integrated into the adaptive system:

**Real-Time Quota Tracking** monitors provider API response headers to track remaining quota, enabling immediate adjustment when quota runs low. The system polls quota status every 10 seconds during high-utilization periods.

**Proactive Throttling** reduces request rate before quota exhaustion, ensuring that in-flight requests do not fail due to quota limits. Proactive throttling uses a safety margin of 10% of remaining quota.

**Post-Quota Recovery** automatically restores full rate limits when provider quota resets, which typically occurs daily or monthly depending on provider. The system monitors quota reset times to immediately restore capacity when available.

---

## Monitoring and Alerts

Rate limit behavior is monitored for optimization opportunities:

**Limit Utilization Metrics** track how close tenants and providers operate to their rate limits, identifying capacity constraints and optimization opportunities. High utilization indicates either appropriate limits or insufficient capacity.

**Throttling Events** are logged and analyzed to identify patterns that could indicate problems. Frequent throttling for specific tenants or providers indicates configuration issues requiring attention.

**Optimization Recommendations** are generated based on observed patterns, suggesting rate limit adjustments that would improve throughput without increasing risk. Recommendations are reviewed by operations before implementation.

---

## Related Documents

- `04-communication/provider-runtime.md`
- `18-smart-tuning/worker-concurrency.md`
- `18-smart-tuning/operational-guardrails.md`