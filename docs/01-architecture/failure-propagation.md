# Failure Propagation

## Metadata
```yaml
title: Failure Propagation
domain: resilience
owner: Reliability Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-first-design.md
  - replay-safe-design.md
related-docs:
  - runtime-summary.md
  - provider-outages.md
  - redis-degradation.md
related-queues:
  - all-queues
related-runtime-states:
  - running
  - degraded
  - recovering
related-threat-models:
  - mysql-outage
  - redis-degradation
  - provider-outage
```

---

## Overview

Failure propagation defines how failures cascade through the system. UICP implements defense mechanisms to contain failures and prevent cascading outages.

---

## Failure Types

### Single Component Failure

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│  API Node   │ ───→ │    MySQL    │ ───→ │   Redis     │
└─────────────┘      └─────────────┘      └─────────────┘
                         │                      │
                         ▼                      ▼
                    [Failure]              [Failure]
                         │                      │
                         ▼                      ▼
                  ┌───────────┐         ┌───────────┐
                  │ Degraded  │         │ Degraded  │
                  │   Mode    │         │   Mode    │
                  └───────────┘         └───────────┘
```

### Failure Propagation Patterns

| Pattern | Description | Example |
|---------|-------------|---------|
| Direct | Failure directly affects dependent component | MySQL down → API returns 500 |
| Retry | Repeated failures exhaust resources | 1000 retries → connection pool exhausted |
| Cascade | One failure triggers another | Redis down → rate limit bypassed → database overload |

---

## Containment Strategies

### Circuit Breaker

```typescript
class CircuitBreaker {
  private state: 'closed' | 'open' | 'half-open' = 'closed';
  private failures = 0;
  private lastFailureTime: Date | null = null;

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === 'open') {
      if (this.shouldAttemptReset()) {
        this.state = 'half-open';
      } else {
        throw new CircuitOpenError('Circuit open, rejecting request');
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failures = 0;
    this.state = 'closed';
  }

  private onFailure(): void {
    this.failures++;
    this.lastFailureTime = new Date();

    if (this.failures >= 5) {
      this.state = 'open';
    }
  }

  private shouldAttemptReset(): boolean {
    const resetTimeout = 30000; // 30 seconds
    return Date.now() - this.lastFailureTime!.getTime() > resetTimeout;
  }
}
```

### Bulkhead Pattern

```typescript
// Isolate resources per component
class BulkheadExecutor {
  private executors: Map<string, Semaphore> = new Map();

  async execute<T>(
    component: string,
    operation: () => Promise<T>,
    maxConcurrent: number
  ): Promise<T> {
    let executor = this.executors.get(component);

    if (!executor) {
      executor = new Semaphore(maxConcurrent);
      this.executors.set(component, executor);
    }

    return executor.execute(operation);
  }
}

// Usage: Limit concurrent database connections per tenant
await bulkhead.execute('database', () => dbQuery(), 10);
```

### Timeout Enforcement

```typescript
function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number
): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new TimeoutError()), timeoutMs)
    ),
  ]);
}

// Apply timeouts to all external calls
const result = await withTimeout(externalApiCall(), 5000);
```

---

## Graceful Degradation

### When Redis Fails

```typescript
async function getSessionWithFallback(token: string): Promise<Session | null> {
  try {
    // Try Redis first
    const cached = await this.redis.get(`session:${token}`);
    if (cached) {
      return JSON.parse(cached);
    }
  } catch (error) {
    // Redis failed, fall back to MySQL
    this.logger.warn('Redis failed, falling back to MySQL', error);
  }

  // Fallback to database
  return await this.sessionRepository.findByToken(token);
}
```

### When Provider Fails

```typescript
async function sendMessageWithFallback(
  request: ProviderRequest
): Promise<ProviderResponse> {
  const providers = this.getProvidersForChannel(request.channel);

  for (const provider of providers) {
    try {
      return await provider.send(request);
    } catch (error) {
      this.logger.warn(`Provider ${provider.type} failed, trying next`, error);
      continue;
    }
  }

  // All providers failed: queue for retry
  await this.queueService.add('message-retry', request, {
    delay: 60000, // Retry in 1 minute
  });

  throw new ProviderUnavailableException('All providers failed, queued for retry');
}
```

---

## Failure Notification

### Alerting

```typescript
class FailureNotifier {
  async notifyFailure(
    component: string,
    failureType: FailureType,
    details: FailureDetails
  ): Promise<void> {
    const severity = this.determineSeverity(failureType, details);

    if (severity === 'critical') {
      await this.pagerDuty.trigger({
        title: `Critical: ${component} failure`,
        severity: 'critical',
        details,
      });
    }

    // Always log for later analysis
    await this.failureLog.record({
      component,
      type: failureType,
      details,
      timestamp: new Date(),
    });

    // Update health status
    await this.healthRegistry.setComponentStatus(component, 'degraded');
  }
}
```

---

## Recovery Patterns

### Retry with Backoff

```typescript
async function retryWithBackoff<T>(
  operation: () => Promise<T>,
  options: RetryOptions
): Promise<T> {
  let attempt = 0;

  while (attempt < options.maxAttempts) {
    try {
      return await operation();
    } catch (error) {
      attempt++;

      if (attempt >= options.maxAttempts) {
        throw error;
      }

      const delay = Math.pow(2, attempt) * options.baseDelay;
      await this.sleep(delay);
    }
  }

  throw new Error('Max retries exceeded');
}
```

### Idempotent Recovery

```typescript
// Replay protection ensures retries don't cause duplicate operations
async function recoverJob(jobId: string): Promise<void> {
  // 1. Check if already processed
  const exists = await this.idempotencyStore.exists(jobId);

  if (exists) {
    this.logger.log(`Job ${jobId} already processed, skipping recovery`);
    return;
  }

  // 2. Reprocess
  await this.processJob(jobId);
}
```

---

## Related Documents

- `queue-first-design.md`
- `replay-safe-design.md`
- `16-failure-models/provider-outages.md`
- `16-failure-models/redis-degradation.md`