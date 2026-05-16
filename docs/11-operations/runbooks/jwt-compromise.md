# Runbook: JWT Compromise

## Metadata
```yaml
title: JWT Compromise Runbook
domain: security
owner: security-team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: NONE
provider-impact: NONE
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - docs/11-operations/runbooks/api-key-compromise.md
  - docs/11-operations/runbooks/session-invalidation.md
related-docs:
  - docs/07-security/authentication-design.md
  - docs/07-security/token-management.md
  - docs/07-security/incident-response.md
related-queues:
  - security-alert
  - audit-log
related-services:
  - auth-service
  - token-service
  - api-gateway
```

---

## Scenario

JWT signing key compromised, or suspicious JWT usage detected indicating potential token theft or misuse.

---

## Symptoms

- Unusual JWT issuance patterns
- JWTs used from multiple IPs simultaneously
- JWT usage from known malicious IPs
- Suspicious token refresh patterns
- Security alert from threat detection system
- Employee report of key exposure

---

## Metrics

```sql
-- Unusual token issuance
SELECT tenant_id, COUNT(*) as token_count
FROM jwt_issuance_log
WHERE created_at > NOW() - INTERVAL '1 hour'
GROUP BY tenant_id
HAVING COUNT(*) > AVG(count) * 5;

-- Multi-IP usage
SELECT identity, COUNT(DISTINCT ip_address) as ip_count
FROM authentication_log
WHERE token_type = 'jwt'
AND created_at > NOW() - INTERVAL '10 min'
GROUP BY identity
HAVING COUNT(DISTINCT ip_address) > 3;
```

---

## Metrics (Observability)

```promql
# JWT issuance rate
rate(uicp_jwt_issued_total[5m])

# JWT validation failures
rate(uicp_jwt_validation_failed_total[5m])

# JWT usage by IP count
uicp_jwt_unique_ips_per_token

# Suspicious patterns
uicp_security_alert{jwt_anomaly="true"}
```

---

## Mitigation

### Immediate Actions (0-5 min)

1. **Revoke Compromised Keys**
   ```bash
   # Rotate JWT signing key
   kubectl exec -it auth-service-0 -- rotate-jwt-key
   
   # Or via API
   curl -X POST http://auth-service/internal/keys/rotate \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{"key_type":"jwt","immediate":true}'
   ```

2. **Invalidate All Existing JWTs**
   ```bash
   # Add JWT to blacklist in Redis
   redis-cli SET jwt:blacklist:{SIGNATURE} "compromised" EX 86400
   
   # Or invalidate by tenant
   redis-cli SET jwt:tenant:{TENANT_ID}:invalidate "true"
   ```

3. **Block Suspicious IPs**
   ```bash
   # Add to blocklist
   iptables -A INPUT -s {SUSPICIOUS_IP} -j DROP
   
   # Or via WAF
   curl -X POST https://waf.uicp.io/block \
     -d '{"ip":"{SUSPICIOUS_IP}","reason":"jwt-compromise"}'
   ```

4. **Enable Enhanced Monitoring**
   ```bash
   # Enable JWT debugging
   kubectl set env deployment/api-gateway JWT_DEBUG=true -n uicp
   ```

### Short-term Actions (5-30 min)

1. **Identify Affected Tenants**
   ```bash
   # List tenants with suspicious activity
   psql -U uicp -c "SELECT DISTINCT tenant_id FROM jwt_usage WHERE created_at > NOW() - '1 hour' AND ip_address IN (SELECT ip FROM threat_intel WHERE verdict='malicious')"
   ```

2. **Force Password Reset**
   ```bash
   # Queue password reset for affected users
   redis-cli LPUSH queue:password-reset "{\"tenant_id\":\"$TENANT\",\"user_ids\":[$USER_IDS]}"
   ```

3. **Notify Affected Tenants**
   ```bash
   # Send security notification
   curl -X POST http://notification-service/internal/notify \
     -d '{"type":"security_alert","tenant_id":"$TENANT","template":"jwt_compromise"}'
   ```

4. **Preserve Evidence**
   ```bash
   # Archive logs for forensics
   kubectl exec -it log-archive-job -- archive-logs --start=$(date -d '1 hour ago' +%s) --end=$(date +%s)
   ```

---

## Rollback

Only applicable if false positive:

```bash
# Restore previous key (if rotation was premature)
kubectl exec -it auth-service-0 -- restore-jwt-key --version=previous

# Remove from blacklist
redis-cli DEL jwt:blacklist:{SIGNATURE}

# Remove IP blocks
curl -X DELETE https://waf.uicp.io/block/{IP}

# Disable debug mode
kubectl set env deployment/api-gateway JWT_DEBUG=false -n uicp
```

**Note:** Rollback is rare - if compromise is confirmed, do NOT restore the compromised key.

---

## Recovery

1. Verify no more suspicious JWT usage
2. Monitor for re-occurrence for 24-48 hours
3. Complete security incident report
4. Update threat model
5. Implement additional controls:
   - Shorten JWT expiry
   - Enable token binding
   - Implement token rotation
   - Add behavioral analytics

---

## Observability Queries

```promql
# JWT validation after key rotation
rate(uicp_jwt_valid_total[5m])

# Failed validations (expected after rotation)
rate(uicp_jwt_validation_failed_total[5m])

# Blacklisted token usage attempts
uicp_jwt_blacklist_hits_total

# New key usage
uicp_jwt_key_version{version="new"}
```

---

## Contacts

- Security Team: security@uicp.io
- On-Call Engineer: PagerDuty
- Legal/Compliance: If data breach confirmed

---

## Post-Incident

1. Document timeline
2. Identify root cause
3. Assess scope of compromise
4. Review access logs for exfiltration
5. Update security policies
6. Conduct penetration testing

---

## Related Runbooks

- [API Key Compromise](./api-key-compromise.md)
- [Session Invalidation](./session-invalidation.md)
- [Replay Attack](./replay-attack.md)