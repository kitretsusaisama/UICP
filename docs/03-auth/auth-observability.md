# Authentication Observability

## Metadata
```yaml
title: Authentication Observability
domain: operations
owner: platform-team
criticality: HIGH
runtime-impact: LOW
security-impact: MEDIUM
queue-impact: LOW
provider-impact: LOW
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - auth-overview.md
  - auth-security.md
  - session-management.md
related-docs:
  - suspicious-login-detection.md
  - auth-failure-recovery.md
  - auth-rate-limits.md
related-queues:
  - auth-analytics
  - audit-events
  - security-alerts
related-services:
  - AuditService
  - MetricsService
  - AlertingService
related-runtime-states:
  - OBSERVABLE
  - METRICS_RECORDED
  - ALERT_TRIGGERED
```

---

## Metrics Collection

### Authentication Metrics

| Metric | Type | Description |
|--------|------|-------------|
| login_success_total | Counter | Successful logins |
| login_failure_total | Counter | Failed login attempts |
| token_issued_total | Counter | Tokens issued |
| token_refresh_total | Counter | Token refreshes |
| session_created_total | Counter | Sessions created |
| session_expired_total | Counter | Sessions expired |
| mfa_challenge_total | Counter | MFA challenges |
| mfa_success_total | Counter | MFA successes |
| auth_latency | Histogram | Auth request latency |

### Alerting Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| login_failure_rate | > 10% | > 30% |
| auth_latency_p99 | > 500ms | > 2s |
| token_issuance_errors | > 1% | > 5% |
| session_expiry_rate | > 50% | > 80% |

---

## Logging Strategy

### Structured Logs

Authentication events use structured JSON logging:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event": "login_success",
  "userId": "ulid-abc123",
  "tenantId": "ulid-tenant-456",
  "authMethod": "password",
  "ipAddress": "192.168.1.1",
  "deviceFingerprint": "hash-xyz",
  "latencyMs": 45
}
```

### Log Levels

| Level | Events |
|-------|--------|
| ERROR | Authentication failures, security events |
| WARN | Rate limits approached, suspicious activity |
| INFO | Logins, token issuance, session changes |
| DEBUG | Detailed validation steps (dev only) |

---

## Dashboards

### Authentication Health Dashboard

Key metrics displayed:

- Login success/failure rate (time series)
- Active sessions count
- Token refresh rate
- MFA adoption rate
- Auth latency distribution

### Security Dashboard

Security-focused metrics:

- Failed login by account
- Rate limit events
- Suspicious login detections
- Account lockout events

---

## Tracing

### Distributed Tracing

Authentication requests trace across services using OpenTelemetry:

- Trace ID propagates through call chain
- Each service adds spans for operations
- Parent-child relationships maintained
- Sampling rate: 10% for normal, 100% for errors

### Key Traces

- Login flow: credential validation -> risk assessment -> token issuance
- Token refresh: validation -> rotation -> new token issuance
- OAuth: authorize -> callback -> token exchange -> session creation

---

## Related Documents

- `auth-security.md` - Security overview
- `suspicious-login-detection.md` - Anomaly detection
- `auth-failure-recovery.md` - Error handling