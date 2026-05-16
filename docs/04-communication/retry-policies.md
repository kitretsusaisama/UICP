# Retry Policies

## Metadata
```yaml
title: Retry Policies
domain: communication
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: LOW
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-priorities.md
  - fallback-policies.md
related-docs:
  - provider-runtime.md
  - provider-failure-handling.md
related-queues:
  - email-delivery
  - sms-delivery
  - otp-fastlane
related-services:
  - RetryHandler
  - MessageProcessor
  - BackoffCalculator
related-providers:
  - SES
  - Resend
  - Maileroo
  - Msg91
related-runtime-states:
  - retry_pending
  - retry_in_progress
  - retry_exhausted
  - retry_success
  - retry_failed
related-threat-models:
  - Retry storm
  - Infinite retry loops
```

---

## Overview

Retry Policies define how failed messages are retried, including delay calculations, maximum attempts, and circuit breaker integration. Different channels and message types have tailored retry strategies.

---

## Retry Strategies

### Exponential Backoff

```typescript
function calculateBackoff(attempt: number, baseDelay: number = 1000): number {
  // Exponential: 1s, 2s, 4s, 8s, 16s...
  const delay = baseDelay * Math.pow(2, attempt - 1);

  // Add jitter (±10%)
  const jitter = delay * 0.1 * Math.random();
  return Math.floor(delay + jitter);
}
```

### Linear Backoff

```typescript
function calculateLinearBackoff(attempt: number, increment: number = 1000): number {
  // Linear: 1s, 2s, 3s, 4s...
  return attempt * increment;
}

### Fixed Delay

```typescript
function calculateFixedBackoff(attempt: number, delay: number = 5000): number {
  // Fixed: always 5s
  return delay;
}
```

---

## Channel-Specific Policies

### Email Retry Policy

```typescript
const emailRetryPolicy: RetryPolicy = {
  maxAttempts: 3,
  backoff: {
    strategy: 'exponential',
    baseDelay: 5000,  // 5s, 10s, 20s
    maxDelay: 60000   // 1 minute max
  },
  retryableErrors: [
    'RATE_LIMIT',
    'NETWORK_ERROR',
    'PROVIDER_TIMEOUT',
    'PROVIDER_UNAVAILABLE'
  ],
  nonRetryableErrors: [
    'INVALID_RECIPIENT',
    'INVALID_SENDER',
    'quota_exceeded'
  ]
};
```

### SMS Retry Policy

```typescript
const smsRetryPolicy: RetryPolicy = {
  maxAttempts: 5,
  backoff: {
    strategy: 'linear',
    increment: 2000,  // 2s, 4s, 6s, 8s, 10s
    maxDelay: 30000
  },
  retryableErrors: [
    'NETWORK_ERROR',
    'CARRIER_ERROR',
    'TIMEOUT'
  ],
  nonRetryableErrors: [
    'INVALID_NUMBER',
    'NETWORK_BLOCKED',
    'OPTED_OUT'
  ]
};
```

### OTP Retry Policy

```typescript
const otpRetryPolicy: RetryPolicy = {
  maxAttempts: 1,
  backoff: {
    strategy: 'fixed',
    delay: 0  // Immediate retry only
  },
  // OTP failures must be fast - fail to DLQ immediately
  retryableErrors: [],
  nonRetryableErrors: ['*']
};
```

---

## Circuit Breaker Integration

### Failure Threshold

```typescript
const circuitBreakerConfig = {
  failureThreshold: 5,      // Open after 5 failures
  successThreshold: 2,      // Close after 2 successes
  timeout: 30000,           // 30 second timeout
  resetTimeout: 60000      // 1 minute before retry
};
```

### State Transitions

```
CLOSED (normal) → OPEN (threshold exceeded) → HALF-OPEN (testing)
                    ↑                           ↓
                    └───────────────────────────┘
                        (success/failure)
```

---

## Error Classification

### Retryable Errors

| Error | Retry | Delay |
|-------|-------|-------|
| Network timeout | Yes | Exponential |
| Rate limit (429) | Yes | Linear |
| Provider unavailable | Yes | Exponential |
| Internal error (5xx) | Yes | Exponential |

### Non-Retryable Errors

| Error | Retry | Action |
|-------|-------|--------|
| Invalid recipient | No | Suppress |
| Sender not verified | No | Alert |
| Quota exceeded | No | Queue DLQ |
| Message too large | No | Reject |

---

## Metrics and Observability

### Retry Metrics

| Metric | Description |
|--------|-------------|
| retry_attempted | Retries initiated |
| retry_succeeded | Retries successful |
| retry_exhausted | Max attempts reached |
| retry_duration | Time from first attempt to success |
| backoff_actual | Actual backoff delay used |

---

## Related Documents

- `04-communication/queue-priorities.md`
- `04-communication/fallback-policies.md`
- `04-communication/provider-failure-handling.md`