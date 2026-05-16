```yaml
title: Retry Runtime
domain: execution
owner: platform-runtime
criticality: critical
runtime-impact: cross-component
security-impact: low
queue-impact: high
provider-impact: high
tenant-impact: low
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - request-lifecycle.md
  - state-machines.md
  - provider-selection.md
related-docs:
  - request-lifecycle.md
  - provider-selection.md
  - fallback-runtime.md
related-queues:
  - retry-delivery
  - retry-scheduling
related-services:
  - retry-coordinator
  - backoff-calculator
  - retry-policy-engine
related-providers:
  - all-configured-providers
related-runtime-states:
  - executing
  - retrying
  - failed
  - completed
related-threat-models:
  - retry-storm
  - resource-exhaustion
  - retry-loop
```

# Retry Runtime

The retry-runtime manages request retry logic when initial executions fail, implementing intelligent retry strategies that maximize success rates while minimizing resource consumption and avoiding systemic impact on providers and downstream systems.

## Retry Triggers

The retry-coordinator initiates retry attempts based on multiple failure classifications. Network timeouts trigger immediate retry eligibility for potentially transient connectivity issues. HTTP error codes with retryable status indicate provider-side issues that may resolve on subsequent attempts. Rate limiting responses trigger retry after backoff delay when provider capacity becomes available. Circuit breaker open states prevent retry attempts to providers currently experiencing elevated failure rates.

## Backoff Strategies

The backoff-calculator computes optimal retry delays based on execution context. Exponential backoff doubles delay between consecutive retries, preventing overwhelm during sustained failures. Jitter randomization prevents thundering herd scenarios where many clients retry simultaneously. Linear backoff provides steady progression for predictable recovery patterns. Adaptive backoff adjusts timing based on observed provider recovery patterns.

## Retry Limits

The retry-policy-engine enforces boundaries on retry attempts to prevent resource exhaustion. Maximum retry count limits total attempts before permanent failure declaration. Timeout-based termination stops retrying requests exceeding overall time budgets. Circuit breaker integration provides automatic retry termination when providers consistently fail. Cost-based limiting prevents excessive spend on requests with low success probability.

## Idempotency Handling

Retry safety requires proper idempotency implementation. Idempotency key generation creates unique identifiers for each request attempt. Client-side idempotency token management ensures consistent tokens across retry attempts. Server-side idempotency verification prevents duplicate execution of retried requests. Idempotency expiration policies clean up stored idempotency records after useful retention periods.

## Observability and Tuning

Comprehensive retry telemetry enables optimization of retry parameters. Retry success rate metrics identify effective retry configurations. Retry latency distributions reveal backoff timing impacts. Provider-specific retry statistics inform provider selection after failures. Circuit breaker state transitions show system protection activation. Retry pattern analysis identifies opportunities for automated tuning.
```