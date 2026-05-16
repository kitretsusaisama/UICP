# Chaos Tests

## Metadata
```yaml
title: Chaos Tests
domain: resilience
owner: SRE Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: weekly
last-reviewed: 2026-05-16
depends-on:
  - src/infrastructure/resilience/circuit-breaker.ts
  - src/infrastructure/resilience/retry-handler.ts
  - src/infrastructure/chaos/chaos-injection.service.ts
related-docs:
  - docs/10-operations/chaos-engineering.md
  - docs/11-incident-response/runbooks.md
related-queues:
  - chaos-injection-queue
  - recovery-verification
related-services:
  - CircuitBreaker
  - RetryHandler
  - ChaosInjectionService
```

---

## Overview

Chaos tests validate system resilience by intentionally injecting failures and observing system behavior. These tests ensure the system can withstand various failure modes without data loss or extended downtime.

---

## Test Scenarios

### Infrastructure Failures

| Scenario | Injection Method | Expected Behavior |
|----------|------------------|------------------|
| Network partition | Block traffic to specific region | Requests route to healthy regions |
| Database connection loss | Terminate DB connections | Read from cache, queue writes |
| Redis outage | Stop Redis service | Fallback to in-memory cache |
| Kafka broker failure | Kill Kafka broker | Failover to replica partition |

### Application Failures

| Scenario | Injection Method | Expected Behavior |
|----------|------------------|------------------|
| High CPU usage | Inject CPU load | Throttling activates, latency increases |
| Memory leak | Allocate until OOM | Container restarts, no data loss |
| Deadlock detection | Block threads | Timeout triggers, request fails gracefully |
| Exception storm | Throw random exceptions | Circuit breaker opens, fallback activates |

### Dependency Failures

| Scenario | Injection Method | Expected Behavior |
|----------|------------------|------------------|
| Provider timeout | Delay responses 30s | Fallback provider used |
| Provider error rate | Return 50% 500 errors | Retries with exponential backoff |
| API key invalid | Expire API keys | Re-authentication triggered |
| Rate limit exceeded | Return 429 consistently | Queue requests, process after cooldown |

---

## Test Implementation

```typescript
describe('Chaos Engineering', () => {
  describe('Network Failures', () => {
    it('should failover when provider becomes unreachable', async () => {
      await chaosInjector.injectNetworkFailure({
        target: 'aws-provider',
        failureType: 'timeout',
        duration: '30s'
      });

      const startTime = Date.now();
      const result = await providerService.send(request);

      expect(result.provider.id).not.toBe('aws');
      expect(Date.now() - startTime).toBeLessThan(10000);
    });
  });

  describe('Database Failures', () => {
    it('should read from cache when database is down', async () => {
      await chaosInjector.killDatabaseConnections();

      const cachedData = await service.getUserData('user-123');

      expect(cachedData).toBeDefined();
      expect(cachedData.source).toBe('cache');
    });
  });

  describe('Circuit Breaker', () => {
    it('should open circuit after threshold failures', async () => {
      for (let i = 0; i < 10; i++) {
        await providerService.send(failingRequest);
      }

      const circuitState = await circuitBreaker.getState('provider-aws');
      expect(circuitState).toBe('OPEN');
    });
  });
});
```

---

## Blast Radius Control

All chaos experiments must respect these constraints:
- Maximum 5% of traffic affected
- Maximum 30-second failure duration
- No degradation to critical path
- Automatic recovery after experiment
- Rollback capability within 60 seconds

---

## Validation Checklist

- System remains available during failure injection
- No data corruption or loss
- Circuit breakers activate correctly
- Fallback paths execute successfully
- Alerting triggers appropriately
- Recovery occurs within expected time