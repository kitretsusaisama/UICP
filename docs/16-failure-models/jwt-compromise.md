# Failure Model: JWT Compromise

## Metadata
```yaml
title: JWT Compromise
domain: security
criticality: CRITICAL
security-impact: CRITICAL
ai-ingestable: true
```

---

## Description

JWT access or refresh tokens are compromised, allowing unauthorized access.

---

## Symptoms

- Unusual access patterns (impossible travel, odd hours)
- Session count spike for user
- API calls from unknown IPs
- User reports of "already logged in" state

---

## Propagation Chain

```
1. Token compromised (log theft, MITM, insider)
2. Attacker uses token in API requests
3. System validates token (appears valid)
4. Full tenant access gained
5. Data exfiltration or account takeover
```

---

## UICP Protections

### Short Lifespan
- Access token: 15 minutes
- Refresh token: 7 days (rotates on use)

### Token Rotation
- Every refresh invalidates previous token
- Old tokens added to blocklist in Redis

### Emergency Revocation
- Purge session cache immediately
- Add to token blocklist
- Invalidate all active sessions

---

## Mitigation Steps

```
1. Identify compromised tokens (audit logs)
2. Call emergency revocation endpoint
3. Block user account temporarily
4. Force password reset
5. Issue new tokens to user
6. Review access logs for data access
```

---

## Metrics

| Metric | Threshold |
|--------|-----------|
| `uicp.auth.unusual_ip` | Any |
| `uicp.session.count_spike` | >2x normal |
| `uicp.token.refresh_reuse` | Any |

