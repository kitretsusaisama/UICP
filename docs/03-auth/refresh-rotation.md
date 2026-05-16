# Refresh Token Rotation

## Metadata
```yaml
title: Refresh Token Rotation
domain: authentication
owner: identity-team
criticality: CRITICAL
runtime-impact: MEDIUM
security-impact: CRITICAL
queue-impact: LOW
provider-impact: LOW
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - auth-overview.md
  - token-model.md
  - session-management.md
related-docs:
  - jwt-claims.md
  - auth-security.md
  - replay-prevention.md
related-queues:
  - token-rotation-events
related-services:
  - TokenService
  - RefreshTokenStore
  - RedisCacheAdapter
related-runtime-states:
  - TOKEN_REFRESHED
  - TOKEN_ROTATED
  - TOKEN_REVOKED
```

---

## Rotation Mechanism

### Automatic Rotation

Every refresh token use issues a new token pair. The old refresh token invalidates immediately. This design prevents token reuse attacks (replay of stolen refresh tokens).

```
Token Pair Flow:
1. Client presents refresh token
2. Server validates token (signature, claims, not revoked)
3. Server marks old token as used (atomic operation)
4. Server issues new access + refresh token pair
5. New refresh token has new jti and expiry
```

### Rotation Implementation

```typescript
async function rotateTokenPair(refreshToken: string): Promise<TokenPair> {
  const tokenData = await this.refreshStore.get(refreshToken);

  if (!tokenData || tokenData.rotated) {
    throw new InvalidRefreshTokenError();
  }

  // Atomic rotation: mark old as used, issue new pair
  await this.refreshStore.transaction(async (tx) => {
    await tx.markRotated(refreshToken);
    return tx.issueNewPair(tokenData.userId, tokenData.tenantId);
  });
}
```

---

## Rotation Metadata

### Refresh Token ID (rti)

Each refresh token has a rotation token ID (`rti`) claim that persists across rotations. This enables tracking the token lineage without exposing the token ID.

```json
{
  "jti": "ulid-new-token-123",
  "rti": "ulid-original-token-000",
  "sub": "ulid-user-abc"
}
```

### Rotation Count

The token store maintains rotation count per `rti`. Maximum rotations per token: 100 (configurable). After limit, user must re-authenticate.

---

## Revocation Integration

### Single Token Revocation

Individual tokens revoke via `jti` lookup and deletion from Redis. Affects only the specific token instance.

### Session Revocation

All tokens for a user invalidate through the session service. This triggers for password change, admin action, or security event.

### Device Revocation

Specific device sessions revoke through session metadata. Useful for selective logout from lost devices.

---

## Sliding Window vs Fixed Expiration

### Sliding Window Model

Token expiration extends on each use. A user with daily API activity maintains continuous session without re-login.

```
Fixed: Token issued 7 days ago, expires today regardless of use
Sliding: Token used yesterday, now expires 7 days from yesterday
```

### Implementation

UICP uses sliding window model. Each refresh extends expiry by the full token lifetime (7 days). This rewards active usage while preventing indefinite tokens from inactive accounts.

---

## Related Documents

- `token-model.md` - Token structure
- `replay-prevention.md` - Security controls
- `auth-security.md` - Security overview