# Retry Lineage

## Metadata
```yaml
title: Retry Lineage
domain: reliability
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - queue-service
  - retry-strategy
  - exponential-backoff
related-docs:
  - 12-messaging/retry-policies.md
  - 15-runtime-lineage/queue-lineage.md
  - 15-runtime-lineage/provider-lineage.md
related-queues:
  - email-outbound
  - sms-outbound
  - webhook-delivery
related-services:
  - retry-handler
  - worker-service
  - dead-letter-processor
related-providers:
  - twilio
  - sendgrid
  - aws-sns
```

---

## Overview

Retry lineage tracks all retry attempts for failed operations, enabling circuit breaker analysis, backoff tuning, and incident reconstruction when providers experience sustained failures.

---

## Retry Flow Lineage

### Initial Failure Detection

```
Provider API Call
    ↓
Response Processing
    ↓
Failure Detection (Status Code/Timeout/Exception)
    ↓
Retry Eligibility Check (Retryable Error Types)
    ↓
Retry Policy Evaluation
    ↓
Retry Decision (Accept/Reject)
    ↓
Schedule Next Attempt (with backoff)
```

### Exponential Backoff Lineage

```
Attempt 1 Failed
    ↓
Calculate Backoff: baseDelay * 2^attempt
    ↓
Add Jitter (random ±10%)
    ↓
Schedule Retry Timestamp
    ↓
Message Returned to Queue
    ↓
Wait for Scheduled Time
    ↓
Worker Picks Up Message
    ↓
Attempt 2 Execution
```

---

## Retry Strategy Configuration

### Per-Provider Retry Policies

Each provider maintains distinct retry configurations:

**SendGrid (Email)**
- Max Retries: 5
- Base Delay: 30 seconds
- Max Delay: 15 minutes
- Retryable Codes: 429, 5xx

**Twilio (SMS/Voice)**
- Max Retries: 3
- Base Delay: 10 seconds
- Max Delay: 2 minutes
- Retryable Codes: 429, 503, 5xx

**AWS SNS (Push Notifications)**
- Max Retries: 10
- Base Delay: 5 seconds
- Max Delay: 5 minutes
- Retryable Codes: 429, 5xx, throttling

---

## Circuit Breaker Integration

Retry lineage interfaces with circuit breaker state:

```
Success Threshold: 3 consecutive successes
Failure Threshold: 5 consecutive failures
Timeout: 60 seconds open state
    ↓
Circuit Closed (Normal retries)
    ↓
Failure Count Increment
    ↓
Threshold Reached → Circuit Open
    ↓
All Requests Fail Fast (No retries)
    ↓
Timeout Elapsed → Circuit Half-Open
    ↓
Probe Requests Begin
    ↓
Success/Failure Determines State
```

---

## Trace Correlation

Each retry attempt captures:
- **attemptNumber**: Current attempt count
- **previousAttemptId**: Link to prior attempt
- **backoffDuration**: Calculated delay applied
- **jitterApplied**: Randomization factor
- **circuitState**: Circuit breaker status at attempt time
- **providerErrorCode**: Original provider error
- **retryReason**: Classification of failure type

---

## Dead Letter Handling

After exhausting retries:
1. Message moves to dead-letter queue
2. Original lineage preserved for inspection
3. Manual intervention flags set
4. Alert triggered for operations team
5. SLO breach tracking updated

---

## Analysis and Tuning

Retry lineage enables:
- Failure pattern identification by provider
- Backoff algorithm effectiveness measurement
- Circuit breaker threshold calibration
- SLO impact assessment during provider outages

---

## Related Documents

- `15-runtime-lineage/queue-lineage.md` - Queue processing
- `15-runtime-lineage/provider-lineage.md` - Provider-specific behavior
- `12-messaging/retry-policies.md` - Retry configuration