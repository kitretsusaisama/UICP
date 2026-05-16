# Recovery Behavior

## Metadata
```yaml
title: Recovery Behavior
domain: smart-tuning
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 02-runtime/retry-runtime
  - 02-runtime/fallback-runtime
  - 16-failure-models/provider-outages
  - 16-failure-models/redis-degradation
related-docs:
  - 18-smart-tuning/retry-tuning.md
  - 18-smart-tuning/fallback-tuning.md
  - 18-smart-tuning/operational-guardrails.md
  - 18-smart-tuning/replay-tuning.md
related-queues:
  - Recovery Queue
  - Retry Queue
related-services:
  - Recovery Manager
  - Health Monitor
  - Circuit Breaker
related-providers:
  - All providers
```

---

## Overview

Recovery behavior defines how the system automatically recovers from failures at various levels - from individual message failures to complete system outages. Effective recovery behavior ensures that transient failures do not become permanent data loss while minimizing the operational burden on administrators during incident response.

The recovery system operates as a layered approach, with different recovery mechanisms activating based on failure scope and severity. Individual message failures trigger retry and fallback mechanisms, while system-wide failures require more complex recovery procedures including state reconstruction and queue replay.

---

## Failure Classification

Failures are classified to determine appropriate recovery responses:

**Transient Failures** are temporary issues that typically resolve without intervention, such as momentary network hiccups or provider rate limiting. Recovery automatically retries with exponential backoff, with the expectation that subsequent attempts will succeed.

**Persistent Failures** are ongoing issues that require intervention, such as provider outages or credential expiration. Recovery shifts traffic to fallback providers and alerts operations teams for investigation.

**Structural Failures** are fundamental issues with system state, such as database corruption or configuration errors. Recovery requires manual intervention and may involve data repair or configuration correction.

---

## Message-Level Recovery

Individual message failures trigger structured recovery:

**Immediate Retry** attempts message delivery again immediately after failure, suitable for transient issues that may resolve quickly. Maximum 3 immediate retries before escalating to delayed retry.

**Delayed Retry** schedules message for retry after backoff delay, allowing time for transient issues to resolve. Backoff starts at 5 seconds and doubles with each retry, up to a maximum of 5 minutes.

**Fallback Routing** routes failed messages to alternative providers when primary providers fail. Fallback routing is triggered after single failures for high-priority messages and after multiple failures for standard messages.

---

## System-Level Recovery

System failures require coordinated recovery procedures:

**Service Restart** terminates and restarts failed services, clearing potentially corrupted state and restoring normal operation. Services are restarted using container orchestration to maintain availability during restart.

**State Reconstruction** rebuilds system state from authoritative sources when local state becomes unreliable. Cache invalidation and database queries restore consistency without requiring full system restart.

**Queue Recovery** replays queued messages that may have been lost during system failures, using persisted state to ensure no messages are lost. Recovery points define how much work may need to be replayed.

---

## Provider Recovery

Provider failures require specific recovery procedures:

**Health Check Cycling** increases the frequency of health checks when providers fail, accelerating detection of provider recovery. Health check frequency increases from 60 seconds to 10 seconds during provider incidents.

**Gradual Traffic Restoration** slowly increases traffic to recovering providers rather than immediately restoring full traffic volume. Traffic increases by 10% every 30 seconds until full capacity is restored, preventing immediate re-overload of providers still recovering.

**Provider Warm-Up** performs test deliveries through recovering providers before routing production traffic, validating that the provider can handle traffic before exposing it to full load.

---

## State Recovery

System state recovery ensures consistency after failures:

**Cache Reconstruction** rebuilds cache contents from database sources, ensuring data consistency across system components. Reconstruction uses a prioritized approach that loads critical data first.

**Session State Recovery** restores active session state from persistent storage, preventing users from being logged out during recovery. Sessions are periodically checkpointed to enable recovery without complete re-authentication.

**Queue State Validation** verifies queue integrity after system restarts, identifying any messages that may have been lost during the incident. Missing messages are recovered from outbox tables or recreated from source systems where possible.

---

## Recovery Metrics

Recovery effectiveness is measured through specific metrics:

**Recovery Time** tracks how long different failure types take to resolve, identifying opportunities for faster recovery. Target recovery times are defined for each failure type.

**Message Loss** tracks whether any messages are lost during failures, ensuring that recovery procedures are effective. Message loss triggers immediate investigation and process improvement.

**Data Consistency** verifies that system state is consistent after recovery, comparing data across replicated systems to identify any divergence requiring correction.

---

## Automated vs Manual Recovery

Recovery automation balances speed against risk:

**Fully Automated Recovery** handles common failure scenarios without human intervention, including transient failures, simple service restarts, and provider fallback. Automation ensures rapid response without requiring on-call presence.

**Semi-Automated Recovery** requires human approval for significant actions such as database recovery or large-scale traffic rerouting. Humans provide judgment that automation cannot replicate while still accelerating routine responses.

**Manual Recovery** is required for novel or complex failures that automated procedures cannot handle. Manual procedures are documented in runbooks that guide operators through recovery steps.

---

## Related Documents

- `02-runtime/retry-runtime.md`
- `02-runtime/fallback-runtime.md`
- `16-failure-models/provider-outages.md`
- `18-smart-tuning/operational-guardrails.md`