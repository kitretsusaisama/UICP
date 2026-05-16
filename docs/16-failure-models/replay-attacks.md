# Failure Model: Replay Attacks

## Metadata
```yaml
title: Replay Attack Failure Model
domain: security
criticality: CRITICAL
ai-ingestable: true
```

---

## Description

Replay attacks attempt to reuse previously captured authentication tokens or requests to gain unauthorized access.

---

## Symptoms

- Duplicate authentication events in audit log
- Unusual session count for user
- Same token used from multiple IPs
- Authentication success rate spike without corresponding login events

---

## Propagation Chain

```
1. Attacker captures valid token (man-in-middle or log theft)
2. Attacker replays token to API endpoint
3. System validates token (appears valid)
4. Request succeeds, attacker gains access
5. Original user may be logged out or experience issues
```

---

## UICP Protection Mechanisms

### 1. Idempotency Keys
- Every mutation requires unique idempotency key
- Duplicate requests rejected even with valid credentials
- Keys time out after 24 hours

### 2. Token Rotation
- Refresh tokens rotated on every use
- Old refresh tokens immediately invalidated
- Access tokens have 15-minute lifespan

### 3. Session Invalidation
- Password change invalidates all sessions
- Token compromise allows emergency revocation
- Device trust tracking identifies anomalies

### 4. Nonce Validation
- API key validation includes timestamp nonce
- Replay window limited to 5 minutes
- HMAC prevents token forgery

---

## Metrics & Alerts

| Metric | Threshold | Alert |
|--------|-----------|-------|
| `uicp.auth.duplicate_requests` | >10/min | PagerDuty |
| `uicp.session.duplicate_ips` | >3 per session | PagerDuty |
| `uicp.auth.token_reuse` | Any | Security channel |

---

## Debugging Queries

```sql
-- Find duplicate authentication attempts
SELECT identity, COUNT(*) as attempts 
FROM audit_logs 
WHERE action = 'auth.success' 
AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY identity 
HAVING COUNT(*) > 5;

-- Find token reuse across IPs
SELECT token_hash, array_agg(DISTINCT ip) as ips
FROM sessions 
WHERE created_at > NOW() - INTERVAL '1 hour'
GROUP BY token_hash 
HAVING array_length(array_agg(DISTINCT ip), 1) > 3;
```

---

## Mitigation Steps

1. **Immediate**: Enable emergency revocation for affected tenant
2. **Short-term**: Rotate all tokens,强制用户重新登录
3. **Medium-term**: Review access logs for data exfiltration
4. **Long-term**: Implement FIDO2/WebAuthn for phishing resistance

---

## Rollback Procedure

1. Revoke compromised API keys via `/v1/tenant/api-keys/:id/revoke`
2. Purge Redis session cache: `redis-cli KEYS "session:*" | xargs redis-cli DEL`
3. Issue new tokens to unaffected users

---

## Recovery Strategy

1. User must authenticate with fresh credentials
2. All active sessions invalidated
3. New API keys issued with new HMAC signatures
4. Audit log preserved for forensics

---

## Related Documents

- `05-security/replay-protection.md`
- `03-auth/session-management.md`
- `05-security/threat-model.md`

