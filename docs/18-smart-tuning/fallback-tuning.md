# Fallback Tuning

## Metadata
```yaml
title: Fallback Tuning
domain: smart-tuning
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: NONE
queue-impact: MEDIUM
provider-impact: HIGH
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 02-runtime/fallback-runtime
  - 18-smart-tuning/provider-scoring.md
  - 18-smart-tuning/retry-tuning.md
related-docs:
  - 18-smart-tuning/fallback-tuning.md
  - 18-smart-tuning/retry-tuning.md
  - 18-smart-tuning/regional-routing.md
related-queues:
  - Retry Queue
  - Fallback Queue
related-services:
  - Fallback Router
  - Provider Monitor
related-providers:
  - All providers
```

---

## Overview

Fallback tuning configures how the system automatically switches to alternative providers or delivery paths when primary paths fail. This is the primary mechanism for achieving high availability in provider operations, ensuring that tenant communications continue even when specific providers experience outages or degradation.

The fallback system evaluates multiple conditions to determine when fallback should trigger, including explicit failure responses, implicit degradation signals, and configurable availability thresholds. The system balances between rapid fallback to minimize latency during outages and avoiding fallback thrashing when primary providers experience brief issues.

---

## Fallback Trigger Conditions

Fallback activation occurs when specific conditions are met:

**Explicit Failure Triggers** activate immediately when providers return error responses indicating inability to process the request. These include HTTP 5xx responses, authentication failures, quota exceeded errors, and timeout responses. Each error type has associated fallback behaviors, with some errors triggering immediate fallback and others enabling retry before fallback.

**Degradation Triggers** activate based on accumulated performance signals rather than individual request failures. When a provider's error rate exceeds 30% over a 60-second window, or average latency exceeds 5 seconds, the system automatically begins routing traffic to fallback providers while the primary recovers.

**Threshold Triggers** activate when provider scores (from the provider scoring system) fall below configurable thresholds. The default threshold of 30 points triggers fallback activation, with more critical messages using higher thresholds (50 points) to ensure maximum reliability.

---

## Fallback Chain Configuration

Fallback chains define the ordered sequence of providers to attempt:

**Default Chain**: Primary Provider -> Secondary Provider -> Tertiary Provider -> Queue for Later Retry

The chain length is configurable per tenant and message type, with critical communications using longer chains to maximize delivery probability. The system tracks which provider in the chain has been attempted, resuming from the next available provider on subsequent retry attempts.

**Chain Depth Limits**: Maximum of 5 providers in any fallback chain to prevent excessive latency accumulation. When all chain providers fail, messages enter the retry queue rather than attempting additional providers.

**Chain Reset**: Fallback chains reset after 5 minutes of successful delivery through the primary provider, ensuring that transient failures do not permanently alter routing behavior.

---

## Fallback Routing Strategies

Different routing strategies optimize for different scenarios:

**Sequential Fallback** attempts providers in order, moving to the next only after the current provider definitively fails. This approach minimizes cost by avoiding unnecessary provider calls but adds latency equal to the sum of failed attempt durations.

**Parallel Fallback** dispatches to multiple providers simultaneously, accepting the first successful response and canceling remaining attempts. This approach minimizes latency at the cost of potentially wasting provider calls but provides the fastest possible recovery.

**Selective Parallel Fallback** uses parallel dispatch only for high-priority messages, falling back to sequential for standard-priority communications. This hybrid approach balances latency optimization against cost management.

---

## Fallback State Management

State tracking ensures consistent fallback behavior across retries:

**Provider State** includes availability status, current score, recent failure count, and last successful delivery timestamp. This state is maintained in Redis and updated after each delivery attempt, enabling rapid decision-making without database queries.

**Circuit Breaker Integration** automatically opens circuits to providers that trigger excessive fallback activation, preventing cascade failures where fallback attempts themselves cause additional failures. Circuits auto-reset after 60 seconds of normal operation.

**Fallback History** tracks which providers have been attempted for each message, preventing redundant attempts and enabling accurate reporting on provider reliability during incidents.

---

## Fallback for Multi-Channel Deliveries

Multi-channel fallback strategies ensure message delivery even when individual channels fail:

**Channel Priority Lists** define fallback order within each communication type (email -> SMS -> webhook for urgent notifications, for example). The system attempts each channel in priority order, escalating to the next channel when the current channel fails.

**Cross-Channel Notification** sends alerts through alternative channels when primary channels fail, ensuring that critical system communications reach recipients regardless of channel availability.

**Channel Capacity Awareness** considers provider capacity and quota remaining when selecting fallback channels, avoiding fallback to providers that are themselves near capacity limits.

---

## Related Documents

- `02-runtime/fallback-runtime.md`
- `18-smart-tuning/provider-scoring.md`
- `18-smart-tuning/regional-routing.md`