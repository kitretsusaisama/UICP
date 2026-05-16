# Provider Runtime

## Metadata
```yaml
title: Provider Runtime
domain: communication
owner: Platform Team
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
  - communication-overview.md
  - provider-health.md
related-docs:
  - provider-selection.md
  - delivery-intelligence.md
  - fallback-policies.md
related-queues:
  - email-delivery
  - sms-delivery
  - otp-fastlane
related-services:
  - ProviderAdapter
  - ProviderHealthMonitor
  - MessageSerializer
related-providers:
  - SES
  - Resend
  - Maileroo
  - Msg91
related-runtime-states:
  - provider_initializing
  - provider_ready
  - provider_busy
  - provider_degraded
  - provider_failed
  - provider_rate_limited
related-threat-models:
  - Provider API changes
  - Credentials rotation failure
  - Connection pool exhaustion
```

---

## Overview

Provider Runtime manages the lifecycle of provider connections, handles API interactions, and maintains connection pools. Each provider has a dedicated adapter that normalizes API differences and provides consistent error handling.

---

## Provider Adapters

### Architecture

```
┌─────────────────────────────────────┐
│      Communication Service          │
├─────────────────────────────────────┤
│         Provider Router             │
├───────┬───────┬───────┬─────────────┤
│  SES  │Resend │Maileroo│   Msg91    │
│Adapter│Adapter│Adapter │  Adapter   │
├───────┴───────┴───────┴─────────────┤
│       Connection Pool Manager       │
└─────────────────────────────────────┘
```

### Adapter Interface

```typescript
interface IProviderAdapter {
  // Send message
  send(message: OutboundMessage): Promise<ProviderResponse>;

  // Verify credentials
  validateCredentials(): Promise<boolean>;

  // Get provider status
  getHealth(): Promise<ProviderHealth>;

  // Handle rate limits
  handleRateLimit(retryAfter: number): Promise<void>;
}
```

---

## Connection Management

### Pool Configuration

| Provider | Max Connections | Timeout (ms) | Keep-Alive |
|----------|-----------------|--------------|------------|
| SES | 50 | 30000 | 5 min |
| Resend | 30 | 15000 | 3 min |
| Maileroo | 20 | 20000 | 5 min |
| Msg91 | 40 | 10000 | 2 min |

### Connection Lifecycle

```
1. Initialize pool on startup
2. Acquire connection from pool
3. Execute API call
4. Return connection to pool
5. Monitor idle connections
6. Close stale connections
```

---

## Message Serialization

### Email Format

```typescript
interface EmailPayload {
  from: string;
  to: string[];
  subject: string;
  html?: string;
  text?: string;
  attachments?: Attachment[];
  headers?: Record<string, string>;
}
```

### SMS Format

```typescript
interface SMSPayload {
  to: string;
  message: string;
  senderId?: string;
  unicode?: boolean;
}
```

---

## Error Handling

### Error Categories

| Category | Handling |
|----------|----------|
| Authentication error | Rotate credentials, alert |
| Rate limit | Backoff and retry |
| Transient error | Retry with exponential backoff |
| Permanent error | Mark failed, no retry |
| Timeout | Retry up to 3 times |

### Retry Logic

```
Retry delay sequence:
- Attempt 1: immediate
- Attempt 2: 1 second
- Attempt 3: 5 seconds
- Attempt 4: 30 seconds (final)
```

---

## Runtime Metrics

| Metric | Description |
|--------|-------------|
| provider_connections_active | Current active connections |
| provider_connections_idle | Idle connections in pool |
| provider_request_total | Total requests sent |
| provider_request_failed | Failed requests |
| provider_latency_avg | Average response time |

---

## Health Monitoring

Each adapter performs health checks:

```typescript
async function performHealthCheck(adapter: IProviderAdapter): Promise<HealthStatus> {
  const start = Date.now();
  try {
    await adapter.validateCredentials();
    return {
      status: 'healthy',
      latency: Date.now() - start,
      checkedAt: new Date()
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      error: error.message,
      checkedAt: new Date()
    };
  }
}
```

---

## Related Documents

- `04-communication/communication-overview.md`
- `04-communication/provider-selection.md`
- `04-communication/provider-health.md`