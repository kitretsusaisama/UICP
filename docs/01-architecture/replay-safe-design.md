# Replay-Safe Design

## Metadata
```yaml
title: Replay-Safe Design
domain: security
owner: Security Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - queue-first-design.md
  - api-key-runtime.md
related-docs:
  - zero-trust-model.md
  - 16-failure-models/replay-attacks.md
related-queues:
  - all-queues
related-services:
  - all-services
related-runtime-states:
  - running
related-threat-models:
  - replay-attacks
  - token-theft
```

---

## Overview

Replay-safe design prevents attackers from reusing captured credentials or requests to gain unauthorized access. UICP implements multiple layers of protection.

---

## Protection Mechanisms

### 1. Idempotency Keys

Every mutation request requires a unique idempotency key. Duplicate requests with the same key are rejected, even with valid credentials.

**Key Generation:**
```typescript
function generateIdempotencyKey(operation: string, payload: object): string {
  const hash = crypto.createHash('sha256')
    .update(`${operation}:${JSON.stringify(payload)}`)
    .digest('hex');
  return `${operation}:${hash.slice(0, 32)}`;
}
```

**Validation:**
```typescript
async function validateIdempotency(key: string): Promise<boolean> {
  const exists = await this.redis.exists(`idempotency:${key}`);
  if (exists) {
    throw new ConflictException('Duplicate request');
  }
  await this.redis.setex(`idempotency:${key}`, 86400, '1'); // 24h TTL
  return true;
}
```

### 2. Token Rotation

Tokens have short lifespans and rotate on every use.

| Token Type | Lifespan | Rotation |
|------------|----------|----------|
| Access Token | 15 minutes | On use |
| Refresh Token | 7 days | On use |
| API Key | 90 days default | Manual or auto |

```typescript
async function refreshToken(refreshToken: string): Promise<TokenPair> {
  // 1. Validate refresh token
  const payload = await this.jwtService.verify(refreshToken);

  // 2. Invalidate old refresh token (rotation)
  await this.redis.del(`refresh:${payload.sub}`);

  // 3. Generate new token pair
  const accessToken = await this.generateAccessToken(payload);
  const newRefreshToken = await this.generateRefreshToken(payload);

  // 4. Store new refresh token
  await this.redis.setex(`refresh:${payload.sub}`, 604800, newRefreshToken);

  return { accessToken, refreshToken: newRefreshToken };
}
```

### 3. Nonce Validation

API key validation includes timestamp nonce to limit replay window.

```typescript
async function validateNonce(key: string, nonce: string, timestamp: number): Promise<boolean> {
  // 1. Check timestamp not too old (5 minute window)
  const now = Date.now();
  if (now - timestamp > 300000) {
    throw new UnauthorizedException('Request expired');
  }

  // 2. Check nonce not used before
  const nonceKey = `nonce:${key}:${nonce}`;
  const used = await this.redis.setnx(nonceKey, '1');
  if (!used) {
    throw new UnauthorizedException('Nonce already used');
  }
  await this.redis.expire(nonceKey, 300);

  // 3. Verify HMAC includes nonce
  const expectedSig = crypto
    .createHmac('sha256', API_KEY_HMAC_SECRET)
    .update(`${key}:${nonce}:${timestamp}`)
    .digest('base64');

  return signature === expectedSig;
}
```

### 4. Session Binding

Sessions bind to IP address and user agent to detect hijacking.

```typescript
async function validateSession(sessionId: string, clientIp: string, userAgent: string): Promise<boolean> {
  const session = await this.redis.get(`session:${sessionId}`);
  const data = JSON.parse(session);

  // Check IP matches (with optional CIDR flexibility)
  if (!ipMatches(data.ip, clientIp)) {
    // Flag anomaly but don't block (mobile users change IPs)
    await this.anomalyDetector.flag('ip_mismatch', { sessionId, expected: data.ip, actual: clientIp });
  }

  // Check user agent matches
  if (data.userAgent !== userAgent) {
    await this.anomalyDetector.flag('user_agent_mismatch', { sessionId });
  }

  return true;
}
```

---

## Attack Prevention

### Token Theft Prevention

| Control | Implementation |
|---------|----------------|
| Short lifespan | 15-min access tokens |
| Secure storage | HTTP-only cookies, secure storage |
| Transmission | TLS 1.3 required |
| Rotation | Every use invalidates previous |

### Replay Attack Prevention

| Control | Implementation |
|---------|----------------|
| Idempotency keys | Unique per request |
| Nonce validation | 5-minute replay window |
| Timestamp checks | Server time validation |
| Sequence numbers | Per-session monotonic counter |

---

## Detection and Response

### Anomaly Detection

```typescript
async function detectAnomalies(tenantId: TenantId, userId: UserId): Promise<void> {
  const events = await this.auditLog.getRecentEvents(tenantId, userId, '1 hour');

  // Detect impossible travel
  const locations = events.map(e => e.location);
  if (hasImpossibleTravel(locations)) {
    await this.alert.send('impossible_travel', { userId, locations });
  }

  // Detect duplicate authentication
  const authEvents = events.filter(e => e.action === 'auth.success');
  if (authEvents.length > 10) {
    await this.alert.send('auth_spike', { userId, count: authEvents.length });
  }

  // Detect token reuse across IPs
  const tokens = groupBy(authEvents, 'tokenHash');
  for (const [token, evts] of tokens) {
    if (evts.map(e => e.ip).unique().length > 3) {
      await this.alert.send('token_reuse', { token, ips: evts.map(e => e.ip) });
    }
  }
}
```

### Emergency Response

```typescript
async function emergencyRevoke(tenantId: TenantId, reason: string): Promise<void> {
  // 1. Revoke all API keys
  await this.apiKeyRepository.updateMany(tenantId, { status: 'revoked' });

  // 2. Invalidate all sessions
  await this.redis.del(`session:${tenantId}:*`);

  // 3. Rotate all tokens
  await this.tokenRepository.invalidateTenant(tenantId);

  // 4. Log incident
  await this.incidentLog.log({
    type: 'emergency_revoke',
    tenantId,
    reason,
    timestamp: new Date(),
  });

  // 5. Notify security team
  await this.notification.send('security', `Emergency revocation for ${tenantId}: ${reason}`);
}
```

---

## Metrics and Alerts

| Metric | Threshold | Alert |
|--------|-----------|-------|
| `uicp.auth.duplicate_requests` | >10/min | PagerDuty |
| `uicp.session.duplicate_ips` | >3 per session | PagerDuty |
| `uicp.auth.token_reuse` | Any | Security channel |
| `uicp.idempotency.duplicates` | >5/min | PagerDuty |

---

## Related Documents

- `queue-first-design.md`
- `api-key-runtime.md`
- `trust-boundaries.md`
- `16-failure-models/replay-attacks.md`