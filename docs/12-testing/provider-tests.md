# Provider Tests

## Metadata
```yaml
title: Provider Tests
domain: provider-routing
owner: Platform Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: LOW
queue-impact: MEDIUM
provider-impact: CRITICAL
tenant-impact: HIGH
ai-ingestable: true
review-cycle: weekly
last-reviewed: 2026-05-16
depends-on:
  - src/application/services/provider-routing.service.ts
  - src/infrastructure/providers/aws-provider.adapter.ts
  - src/infrastructure/providers/gcp-provider.adapter.ts
  - src/infrastructure/providers/azure-provider.adapter.ts
related-docs:
  - docs/04-architecture/provider-routing.md
  - docs/10-operations/provider-failover.md
related-queues:
  - provider-health-check
  - provider-failover
related-services:
  - ProviderRoutingService
  - HealthCheckService
  - FailoverController
```

---

## Overview

Provider tests validate provider routing logic, health check mechanisms, failover behavior, and retry/fallback strategies. These tests ensure traffic flows to healthy providers and failover occurs automatically during outages.

---

## Test Coverage

### Provider Routing

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Healthy provider | Route request when all providers healthy | Request sent to primary provider |
| Provider selection | Multiple healthy providers available | Request routed by latency/load |
| Weighted routing | Configure 70/30 split between providers | Traffic distributed accordingly |
| Geographic routing | Request from EU region | Routed to eu-west-1 provider |

### Health Check Behavior

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Healthy provider | Provider returns 200 OK | Provider marked as healthy |
| Unhealthy provider | Provider returns 503 | Provider marked as unhealthy after 3 failures |
| Recovery detection | Previously unhealthy provider recovers | Provider marked healthy after 2 consecutive successes |
| Health check frequency | Check every 30 seconds | Health status updated accordingly |

### Failover Behavior

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Automatic failover | Primary provider fails | Traffic fails over to secondary within 10s |
| Failback recovery | Primary recovers after failover | Traffic returns to primary after 60s stabilization |
| Multi-tier failover | Primary and secondary fail | Request routed to tertiary provider |
| No healthy providers | All providers unhealthy | Request queued for retry with backoff |

### Retry and Fallback

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Transient error | Provider returns 500 temporarily | Request retried on same provider |
| Timeout fallback | Provider times out after 30s | Request retried on fallback provider |
| Circuit breaker | Provider fails 10 times in 1 minute | Circuit opens, requests skip provider |

---

## Test Implementation

```typescript
describe('Provider Routing', () => {
  describe('Health Check', () => {
    it('should mark provider as unhealthy after 3 failures', async () => {
      const provider = getTestProvider('aws');

      for (let i = 0; i < 3; i++) {
        await healthCheck.check(provider);
      }

      const status = await healthCheck.getStatus(provider.id);
      expect(status.healthy).toBe(false);
    });

    it('should recover provider after 2 consecutive successes', async () => {
      const provider = getTestProvider('gcp', { healthy: false });

      await healthCheck.markUnhealthy(provider);

      for (let i = 0; i < 2; i++) {
        await healthCheck.check(provider);
      }

      const status = await healthCheck.getStatus(provider.id);
      expect(status.healthy).toBe(true);
    });
  });

  describe('Failover', () => {
    it('should failover to secondary when primary fails', async () => {
      const providers = [awsProvider, gcpProvider];
      jest.spyOn(awsProvider, 'send').mockRejectedValue(new Error('Failed'));

      const result = await routingService.route(providers);

      expect(result.provider.id).toBe('gcp');
    });

    it('should failback to primary after recovery', async () => {
      await failoverController.failoverToSecondary(awsProvider);
      await waitFor(60000);
      jest.spyOn(awsProvider, 'healthCheck').mockResolvedValue(true);

      const result = await routingService.route([awsProvider, gcpProvider]);

      expect(result.provider.id).toBe('aws');
    });
  });
});
```

---

## Performance Targets

- Failover completion: < 10 seconds
- Health check latency: < 500ms
- Routing decision: < 50ms
- Circuit breaker activation: < 100ms