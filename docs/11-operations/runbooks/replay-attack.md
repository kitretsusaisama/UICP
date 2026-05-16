# Runbook: Replay Attack

## Metadata
```yaml
title: Replay Attack Runbook
domain: operations
criticality: CRITICAL
```

---

## Scenario

Detected or suspected replay attack on authentication.

---

## Symptoms

- Duplicate authentication from same token
- Authentication from multiple IPs simultaneously
- Audit log shows repeated auth events

---

## Steps

### 1. Identify (0-1 min)
```sql
SELECT identity, COUNT(*) 
FROM audit_logs 
WHERE action = 'auth.success' 
AND created_at > NOW() - INTERVAL '10 min'
GROUP BY identity 
HAVING COUNT(*) > 5;
```

### 2. Contain (1-5 min)
```
1. Revoke all API keys for affected tenant
2. Invalidate all sessions: DEL session:{tenantId}:*
3. Add IPs to blocklist
4. Enable enhanced monitoring
```

### 3. Investigate (5-30 min)
- Review access logs
- Identify attack vector
- Check for data exfiltration

### 4. Recover (30-60 min)
- Force password reset for affected users
- Issue new API keys
- Restore normal operations

### 5. Post-Incident
- Document attack details
- Update threat model
- Implement additional controls

