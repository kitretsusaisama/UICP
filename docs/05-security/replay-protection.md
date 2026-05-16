# Replay Protection

## Metadata
```yaml
title: Replay Protection
domain: security
owner: Security Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: NONE
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/threat-model.md
  - 05-security/nonce-model.md
  - 03-auth/replay-prevention.md
related-docs:
  - 16-failure-models/replay-attacks.md
  - 05-security/request-signing.md
  - 05-security/hmac-validation.md
related-queues: []
related-services:
  - UnifiedAuthGuard
  - ReplayProtectionService
  - NonceValidator
related-runtime-states:
  - validated
  - replay-detected
  - expired
```

---

## Executive Summary

Replay attacks occur when valid requests are captured and resent to execute unauthorized operations. UICP implements defense-in-depth replay protection through timestamp validation, nonce tracking, and idempotency keys.

---

## Protection Mechanisms

### 1. Timestamp Validation

All authenticated requests MUST include a `X-Timestamp` header with Unix epoch time.

```
Request Flow:
1. Client adds X-Timestamp: 1704067200 (current time)
2. Server validates: |server_time - request_time| <= 300 seconds
3. If valid, proceed to nonce check
4. If invalid, reject with 401 Unauthorized
```

**Failure Mode**: Clock skew between client and server can cause false rejections.

**Recovery Strategy**:
- Implement adaptive tolerance window
- Provide server time via API for client synchronization
- Log clock skew metrics for monitoring

### 2. Nonce Validation

For API key authentication, a nonce is required to prevent request replay.

```
Format: Base64(ULID) - unique per request per API key

Validation Flow:
1. Extract nonce from X-Nonce header
2. Check Redis: EXISTS nonce:{tenantId}:{apiKeyId}:{nonce}
3. If exists → REJECT (replay detected)
4. If not exists → SET with TTL (default 1 hour)
5. Continue authentication
```

**Redis Key Structure**: `nonce:{tenantId}:{apiKeyId}:{hash(nonce)}`

**TTL Configuration**: 3600 seconds (1 hour) - balances replay window vs. storage

**Failure Mode**: Redis unavailability blocks all authenticated requests.

**Recovery Strategy**:
1. Fail open for non-critical operations with degraded logging
2. Fail closed for write operations (require nonce validation)
3. Maintain in-memory nonce cache as fallback

### 3. Idempotency Keys

For state-changing operations, idempotency keys prevent duplicate execution.

```
Header: X-Idempotency-Key

Implementation:
1. Extract idempotency key from request
2. Check Redis: GET idempotency:{tenantId}:{key}
3. If exists → return cached response
4. If not exists → process request, cache result
5. TTL: 24 hours (configurable per operation)
```

**Failure Mode**: Idempotency key collision causes incorrect response caching.

**Recovery Strategy**:
- Include operation type in idempotency key composite
- Set appropriate TTL based on operation type
- Monitor for idempotency key patterns

---

## Request Signing with Replay Protection

API key authentication uses HMAC-signed requests that include replay protection.

```
Signature Components:
1. HTTP Method
2. Path
3. Timestamp (X-Timestamp)
4. Nonce (X-Nonce) - for write operations
5. Body hash (SHA-256)
```

```
HMAC Validation:
1. Reconstruct signing payload
2. Calculate HMAC-SHA256 with API key secret
3. Compare with X-Signature header
4. If valid → proceed to nonce check
5. If invalid → reject with 401
```

---

## Webhook Replay Protection

Incoming webhooks from providers require special replay protection.

```
Protection Strategy:
1. Event ID tracking: Redis SET event:{provider}:{eventId}
2. TTL: 7 days (provider may retry within this window)
3. Duplicate detection before processing
4. Automatic acknowledgment to provider
```

**Failure Mode**: Provider retry logic conflicts with deduplication.

**Recovery Strategy**:
- Accept provider-specific retry windows
- Implement idempotent processing for state changes
- Log webhook delivery attempts

---

## Trust Boundaries

| Component | Trust Level | Justification |
|-----------|-------------|----------------|
| Internet | UNTRUSTED | Any request may be replay attempt |
| API Gateway | BOUNDARY | Validates timestamp and nonce |
| Application | TRUSTED | Request already validated |
| Redis | CONDITIONAL | Internal state, high availability |

---

## Configuration

| Parameter | Default | Environment |
|-----------|---------|-------------|
| timestamp_tolerance | 300s | APP_TIMESTAMP_TOLERANCE |
| nonce_ttl | 3600s | APP_NONCE_TTL |
| idempotency_ttl | 86400s | APP_IDEMPOTENCY_TTL |
| replay_detection_enabled | true | APP_REPLAY_PROTECTION |

---

## Monitoring and Alerting

| Metric | Alert Threshold |
|--------|-----------------|
| replay_detected_total | > 10/min |
| nonce_validation_failures | > 100/min |
| timestamp_skew_seconds | > 60s |

---

## Related Documents

- `05-security/threat-model.md`
- `05-security/nonce-model.md`
- `05-security/request-signing.md`
- `16-failure-models/replay-attacks.md`