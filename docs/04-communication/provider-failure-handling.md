# Provider Failure Handling

## Metadata
```yaml
title: Provider Failure Handling
domain: communication
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: LOW
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - provider-health.md
  - fallback-policies.md
  - retry-policies.md
related-docs:
  - communication-overview.md
  - provider-selection.md
  - queue-priorities.md
related-queues:
  - failure-recovery
  - email-delivery
  - sms-delivery
related-services:
  - FailureHandler
  - CircuitBreakerManager
  - AutoRecoveryService
  - AlertDispatcher
related-providers:
  - SES
  - Resend
  - Maileroo
  - Msg91
related-runtime-states:
  - failure_detected
  - failure_isolating
  - failure_recovering
  - failure_recovered
  - failure_escalated
related-threat-models:
  - Cascading failures
  - Thundering herd
```

---

## Overview

Provider Failure Handling manages the detection, isolation, and recovery from provider outages and degradations. The system includes automated failover, circuit breakers, and progressive recovery strategies.

---

## Failure Detection

### Detection Methods

```typescript
interface FailureDetector {
  // Method: Provider health check
  detectHealthFailure(): boolean;

  // Method: API response analysis
  detectApiFailure(error: ProviderError): boolean;

  // Method: Timeout tracking
  detectTimeoutFailure(duration: number): boolean;

  // Method: Pattern matching
  detectPatternFailure(errorPattern: ErrorPattern): boolean;
}

function analyzeFailure(
  context: FailureContext
): FailureAnalysis {
  const detector = new FailureDetector();

  return {
    type: detector.determineType(context),
    severity: detector.determineSeverity(context),
    scope: detector.determineScope(context),
    recoverability: detector.assessRecoverability(context)
  };
}
```

### Failure Types

| Type | Detection | Response |
|------|-----------|----------|
| Partial outage | >10% errors | Increase monitoring |
| Full outage | >90% errors | Trigger fallback |
| Degraded | High latency | Route around |
| Quota exhausted | 429 responses | Switch provider |

---

## Circuit Breaker Integration

### Circuit Breaker States

```typescript
interface CircuitBreakerConfig {
  failureThreshold: number;
  successThreshold: number;
  timeout: number;
  resetTimeout: number;
}

const circuitBreaker = {
  ses: {
    failureThreshold: 10,
    successThreshold: 3,
    timeout: 30000,
    resetTimeout: 60000
  },
  resend: {
    failureThreshold: 5,
    successThreshold: 2,
    timeout: 15000,
    resetTimeout: 30000
  }
};
```

### State Machine

```
CLOSED (normal) → OPEN (too many failures) → HALF-OPEN (testing recovery)
       ↑                                       ↓
       └────────── (success threshold) ───────┘
```

---

## Recovery Strategies

### Immediate Recovery

For transient failures:

```typescript
async function handleTransientFailure(
  message: OutboundMessage,
  error: ProviderError
): Promise<RecoveryResult> {
  // 1. Quick retry with same provider
  const retryResult = await retryWithBackoff(message, {
    strategy: 'immediate',
    maxAttempts: 2
  });

  if (retryResult.success) {
    return { recovered: true, method: 'immediate_retry' };
  }

  // 2. Fallback to alternate provider
  const fallbackResult = await attemptFallback(message);

  return fallbackResult;
}
```

### Progressive Recovery

For sustained outages:

```typescript
async function handleSustainedOutage(
  provider: string,
  duration: TimeWindow
): Promise<void> {
  // 1. Mark provider as degraded
  await healthMonitor.updateStatus(provider, 'degraded');

  // 2. Enable aggressive fallback
  fallbackManager.enableStrictMode(provider);

  // 3. Increase queue monitoring
  queueMonitor.setAlertThreshold(provider, 0.5);

  // 4. Notify operations team
  await alertDispatcher.send({
    severity: 'high',
    message: `Provider ${provider} degraded for ${duration}`
  });

  // 5. Begin automated recovery checks
  startRecoveryChecks(provider);
}
```

---

## Queue Impact Management

### Message Preservation

When provider fails:

```typescript
async function preserveMessages(
  provider: string,
  pendingCount: number
): Promise<void> {
  // 1. Stop new sends to failed provider
  await router.disableProvider(provider);

  // 2. Re-queue pending messages
  const pending = await queue.getPending(provider);
  await queue.requeue(pending, {
    priority: 'high',
    clearProvider: true
  });

  // 3. Increase DLQ monitoring
  dlqMonitor.setWatch(provider, true);
}
```

### Backpressure Handling

| Condition | Action |
|-----------|--------|
| Queue depth > 1000 | Enable backpressure |
| Queue depth > 5000 | Pause new messages |
| Queue depth > 10000 | Alert critical |

---

## Escalation Procedures

### Escalation Levels

| Level | Condition | Action |
|-------|-----------|--------|
| L1 | Single provider degraded | Auto-fallback |
| L2 | All providers degraded | Operations alert |
| L3 | >1 hour outage | Management alert |
| L4 | >4 hour outage | Incident response |

### Notification Flow

```
L1: System handles automatically
L2: Slack channel alert
L3: On-call page
L4: Management escalation
```

---

## Post-Incident Analysis

### Analysis Report

```typescript
interface IncidentReport {
  incidentId: string;
  startTime: Date;
  endTime: Date;
  duration: number;
  affectedProvider: string;
  affectedMessages: number;
  rootCause: string;
  impact: ImpactAssessment;
  recoveryActions: Action[];
  preventionRecommendations: string[];
}
```

### Metrics Captured

- Time to detection (TTD)
- Time to recovery (TTR)
- Messages affected
- Messages failed
- SLA impact

---

## Related Documents

- `04-communication/provider-health.md`
- `04-communication/fallback-policies.md`
- `04-communication/retry-policies.md`