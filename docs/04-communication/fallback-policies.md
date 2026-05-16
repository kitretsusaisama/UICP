# Fallback Policies

## Metadata
```yaml
title: Fallback Policies
domain: communication
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: LOW
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - provider-selection.md
  - retry-policies.md
  - provider-failure-handling.md
related-docs:
  - communication-overview.md
  - provider-health.md
  - queue-priorities.md
related-queues:
  - email-delivery
  - sms-delivery
related-services:
  - FallbackManager
  - ProviderRouter
  - CircuitBreaker
related-providers:
  - SES
  - Resend
  - Maileroo
  - Msg91
related-runtime-states:
  - fallback_pending
  - fallback_triggered
  - fallback_success
  - fallback_exhausted
related-threat-models:
  - Cascade failures
  - Fallback loop
```

---

## Overview

Fallback Policies define how the system automatically switches to alternate providers when the primary provider fails. This ensures message delivery continuity even during provider outages.

---

## Fallback Hierarchy

### Email Provider Chain

```
Primary: SES
  ↓ (failure)
Secondary: Resend
  ↓ (failure)
Tertiary: Maileroo
  ↓ (failure)
Queue for later → DLQ
```

### SMS Provider Chain

```
Primary: Msg91
  ↓ (failure)
Queue for later → DLQ
```

### Configurable Fallbacks

```typescript
interface FallbackConfig {
  channel: 'email' | 'sms';
  chain: ProviderChain;
  maxFallbacks: number;
  fallbackTimeout: number;
  circuitBreakerIntegration: boolean;
}

const defaultEmailFallback: FallbackConfig = {
  channel: 'email',
  chain: ['ses', 'resend', 'maileroo'],
  maxFallbacks: 2,
  fallbackTimeout: 30000,
  circuitBreakerIntegration: true
};
```

---

## Trigger Conditions

### Automatic Triggers

| Condition | Fallback Action |
|-----------|-----------------|
| Provider 5xx error | Immediate switch |
| Rate limit (429) | Switch after 2 failures |
| Timeout (>30s) | Switch after 1 failure |
| Circuit breaker open | Switch immediately |
| Health check failed | Switch with health threshold |

### Manual Triggers

```typescript
async function triggerFallback(tenantId: string, reason: string): Promise<void> {
  await audit.log({
    action: 'fallback_triggered',
    tenantId,
    reason,
    timestamp: new Date()
  });

  await notify.tenant(tenantId, {
    type: 'provider_fallback',
    provider: currentProvider,
    reason
  });
}
```

---

## Fallback Execution

### Step-by-Step Process

```typescript
async function executeFallback(message: OutboundMessage): Promise<SendResult> {
  const chain = getFallbackChain(message.channel);

  for (const providerId of chain) {
    // Check if provider is available
    if (!await isProviderAvailable(providerId)) {
      continue;
    }

    try {
      const result = await sendWithProvider(message, providerId);
      await recordFallbackSuccess(providerId);
      return result;
    } catch (error) {
      await recordFallbackFailure(providerId, error);
      log.warn(`Fallback to ${providerId} failed:`, error);
      // Continue to next provider
    }
  }

  // All fallbacks exhausted
  throw new FallbackExhaustedError(message.messageId);
}
```

---

## Fallback State Management

### Tracking Fallback State

```typescript
interface FallbackState {
  messageId: string;
  originalProvider: string;
  currentProvider: string;
  attempts: number;
  startedAt: Date;
  history: FallbackAttempt[];
}

interface FallbackAttempt {
  provider: string;
  attemptedAt: Date;
  error?: string;
  success: boolean;
}
```

---

## Circuit Breaker Integration

### Integration Logic

```typescript
async function attemptFallbackWithBreaker(
  message: OutboundMessage,
  providerId: string
): Promise<SendResult> {
  const breaker = circuitBreakers.get(providerId);

  if (breaker.isOpen()) {
    throw new CircuitOpenError(providerId);
  }

  try {
    return await sendWithProvider(message, providerId);
  } catch (error) {
    breaker.recordFailure();
    throw error;
  } finally {
    breaker.recordSuccess();
  }
}
```

---

## Tenant Configuration

### Per-Tenant Fallback Settings

```typescript
interface TenantFallbackConfig {
  tenantId: string;
  enableFallback: boolean;
  customChain?: string[];    // Override default chain
  fallbackNotifications: boolean;
  maxFallbackCostMultiplier: number;
}
```

---

## Metrics and Alerts

| Metric | Description | Alert |
|--------|-------------|-------|
| fallback_triggered_total | Total fallbacks | > 10/min |
| fallback_success_rate | % successful | < 80% |
| fallback_duration | Avg time to deliver | > 30s |
| fallback_exhausted_total | All providers failed | Any |

---

## Related Documents

- `04-communication/provider-selection.md`
- `04-communication/retry-policies.md`
- `04-communication/provider-failure-handling.md`