```yaml
title: Fallback Runtime
domain: execution
owner: platform-runtime
criticality: high
runtime-impact: cross-component
security-impact: low
queue-impact: medium
provider-impact: high
tenant-impact: low
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - request-lifecycle.md
  - provider-selection.md
  - retry-runtime.md
related-docs:
  - request-lifecycle.md
  - provider-selection.md
  - retry-runtime.md
related-queues:
  - fallback-routing
  - provider-failover
related-services:
  - fallback-coordinator
  - failover-manager
  - circuit-breaker-service
related-providers:
  - primary-providers
  - fallback-providers
related-runtime-states:
  - executing
  - fallback-initiated
  - failed
  - completed
related-threat-models:
  - fallback-loop
  - cascading-failure
```

# Fallback Runtime

The fallback-runtime provides alternative execution paths when primary providers or execution paths fail, ensuring request completion even when preferred routes become unavailable. This mechanism acts as a safety net that maintains service reliability during provider outages and system failures.

## Fallback Triggers

The fallback-coordinator activates fallback mechanisms based on multiple failure indicators. Provider timeout triggers fallback routing when primary providers exceed response thresholds. Provider error responses with non-retryable status activate alternative provider paths. Circuit breaker open states prevent further requests to failing providers, triggering automatic fallback. Health check failures indicate providers unable to handle requests, enabling preemptive fallback.

## Fallback Hierarchy

Fallback configurations define ordered fallback chains. Primary provider represents the optimal execution path. Secondary providers provide backup execution when primary fails. Tertiary routes offer last-resort options when earlier options fail. Default responses return gracefully when all providers fail, providing meaningful error responses rather than complete failure. Each level in the hierarchy has associated timeout and retry configurations.

## Fallback Execution

The failover-manager orchestrates fallback execution logic. Provider switching updates routing context to use fallback provider. Context preservation maintains request state during provider transitions. Fallback-specific retry logic applies different retry parameters for fallback attempts. Fallback tracking records which fallback level is active for observability.

## Circuit Breaker Integration

The circuit-breaker-service provides automatic fallback activation. Failure threshold monitoring tracks provider failure rates. Recovery timeout determines how long circuit breakers remain open before testing recovery. Half-open state testing verifies provider recovery before full traffic restoration. State transitions emit events enabling responsive fallback routing.

## Fallback Rate Limiting

Fallback paths require protection to prevent overuse. Fallback quota enforcement limits fallback usage to prevent degradation of fallback provider performance. Fallback-only requests may receive lower priority than primary requests. Circuit breaker state influences fallback eligibility, preventing fallback to providers likely to fail. Cost tracking monitors fallback spending to prevent budget overruns.
```