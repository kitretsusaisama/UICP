# Attack Scenarios

## Metadata
```yaml
title: Attack Scenarios
domain: security
owner: Security Team
criticality: HIGH
runtime-impact: HIGH
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: CRITICAL
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/threat-model.md
  - 05-security/replay-protection.md
  - 05-security/incident-response.md
related-docs:
  - 05-security/zero-trust-model.md
  - 05-security/tenant-isolation.md
  - 16-failure-models/replay-attacks.md
related-queues:
  - provider:*
  - tenant:*
related-services:
  - UnifiedAuthGuard
  - TenantResolver
  - IncidentService
related-runtime-states:
  - under-attack
  - detected
  - contained
  - recovered
```

---

## Executive Summary

This document provides detailed attack scenarios with attack paths, defense mechanisms, and recovery procedures. Each scenario includes MITRE ATT&CK mapping.

---

## Scenario 1: API Key Compromise via Log Leakage

### Description

Attacker gains access to API key through application logs that inadvertently captured sensitive credentials.

### Attack Path

```
1. Attacker discovers API endpoint returns verbose errors
2. Attacker sends malformed request
3. Error response includes stack trace with API key
4. Attacker extracts key from log
5. Attacker uses key to access tenant data
```

### MITRE ATT&CK Mapping

| Step | Technique | ID |
|------|-----------|-----|
| 1 | Exploit Public Application | T1190 |
| 2 | Exfiltration Over C2 Channel | T1041 |
| 3 | Steal Authentication Credentials | T1552 |

### Defense Mechanisms

- **Log Sanitization**: All logs must redact API keys, secrets
- **Error Handling**: Generic error messages in production
- **Rate Limiting**: Prevent information gathering
- **API Key Rotation**: 90-day rotation limit exposure window

### Detection

- Anomaly: New API key usage from unusual IP
- Alert: API key in logs (regex detection)
- Alert: High-volume data exfiltration

### Recovery

1. Identify compromised key via logs
2. Emergency revoke key
3. Rotate all tenant API keys
4. Review access logs for unauthorized actions
5. Patch log sanitization

---

## Scenario 2: Replay Attack via Network Interception

### Description

Attacker captures valid API request and replays it to execute unauthorized operations.

### Attack Path

```
1. Attacker performs man-in-the-middle attack
2. Captures signed API request (method, timestamp, signature)
3. Attacker replays request to same endpoint
4. If nonce not validated, request succeeds
5. Duplicate operation executed (e.g., duplicate email)
```

### MITRE ATT&CK Mapping

| Step | Technique | ID |
|------|-----------|-----|
| 1 | Man in the Browser | T1189 |
| 2 | Exfiltration Over C2 Channel | T1041 |
| 3 | Exploit Public Application | T1190 |

### Defense Mechanisms

- **Timestamp Validation**: Requests must be within 5 minutes
- **Nonce Validation**: Each request must have unique nonce
- **One-time Use**: Nonces stored in Redis with 1-hour TTL

### Detection

- Alert: Duplicate nonce usage
- Alert: Timestamp outside tolerance
- Alert: Duplicate operation patterns

### Recovery

1. Identify replayed requests via audit logs
2. Reverse duplicate operations where possible
3. Add nonce logging for forensic analysis
4. Review timestamp validation logic

---

## Scenario 3: Tenant Isolation Bypass via Parameter Injection

### Description

Attacker attempts to access another tenant's data by manipulating tenant ID in request parameters.

### Attack Path

```
1. Attacker authenticates with valid credentials (tenant_abc)
2. Attacker modifies X-Tenant-ID header to tenant_xyz
3. Application uses header tenant_id (UNSAFE) instead of credential tenant_id
4. Attacker accesses tenant_xyz resources
5. Cross-tenant data exposure occurs
```

### MITRE ATT&CK Mapping

| Step | Technique | ID |
|------|-----------|-----|
| 1 | Valid Accounts | T1078 |
| 2 | Exploitation for Privilege Escalation | T1068 |

### Defense Mechanisms

- **Tenant ID Extraction**: Always from validated credential
- **Row-Level Security**: Database queries always filter by tenant
- **Response Validation**: Verify response data belongs to requesting tenant

### Detection

- Alert: Cross-tenant access attempt
- Alert: Tenant ID mismatch between credential and request
- Audit: Cross-tenant query patterns

### Recovery

1. Audit all data accessed during attack window
2. Identify exact isolation failure
3. Fix tenant resolution logic
4. Review all endpoints for similar vulnerabilities
5. Report to affected tenants

---

## Scenario 4: Credential Stuffing via Stolen Credentials

### Description

Attacker uses credentials from other breaches to attempt login to UICP.

### Attack Path

```
1. Attacker obtains username/password pairs from other breaches
2. Attacker automates login attempts across UICP
3. Some credentials match valid UICP accounts
4. Attacker gains access to legitimate accounts
5. Attacker accesses or exfiltrates data
```

### MITRE ATT&CK Mapping

| Step | Technique | ID |
|------|-----------|-----|
| 1 | Credential Stuffing | T1110 |
| 2 | Brute Force | T1110 |
| 3 | Valid Accounts | T1078 |

### Defense Mechanisms

- **Rate Limiting**: Per account, per IP
- **Account Lockout**: 5 failed attempts = 15 min lockout
- **MFA**: Enforce for sensitive operations
- **Credential Breach Monitoring**: Check HaveIBeenPwned

### Detection

- Alert: High failed login rate
- Alert: Login from unusual location
- Alert: New device login

### Recovery

1. Force password reset for affected accounts
2. Invalidate all sessions
3. Enable MFA for affected users
4. Notify users of attempt

---

## Scenario 5: Session Hijacking via Cookie Theft

### Description

Attacker steals session cookie and uses it to impersonate legitimate user.

### Attack Path

```
1. User visits attacker-controlled site
2. XSS steals session cookie
3. Attacker sets cookie in their browser
4. Attacker accesses UICP as user
5. Attacker performs actions as user
```

### MITRE ATT&CK Mapping

| Step | Technique | ID |
|------|-----------|-----|
| 1 | Exploit for Client Execution | T1189 |
| 2 | Exfiltration Over C2 Channel | T1041 |
| 3 | Hijack Execution Flow | T1574 |

### Defense Mechanisms

- **HttpOnly Cookies**: Prevents JavaScript access
- **Secure Cookies**: TLS-only transmission
- **Session Binding**: IP + User-Agent validation
- **Short Session TTL**: 15-minute access tokens

### Detection

- Alert: Session from new device
- Alert: Impossible travel (different IP in short time)
- Alert: Concurrent sessions

### Recovery

1. Invalidate all user sessions
2. Force re-authentication
3. Review user activity for unauthorized actions
4. Provide security guidance

---

## Scenario 6: Provider Secret Exfiltration via Insider

### Description

Malicious insider extracts provider secrets from database.

### Attack Path

```
1. Insider has database read access (for support)
2. Insider queries provider_credential table
3. Secrets are encrypted but key is accessible
4. Insider decrypts and exfiltrates secrets
5. Attacker uses secrets for provider accounts
```

### MITRE ATT&CK Mapping

| Step | Technique | ID |
|------|-----------|-----|
| 1 | Abuse of Elevation Control | T1548 |
| 2 | Exfiltration Over C2 Channel | T1041 |
| 3 | Modify Authentication Process | T1556 |

### Defense Mechanisms

- **Least Privilege**: Minimal database access
- **Encryption at Rest**: AES-256-GCM
- **Access Logging**: All queries logged
- **Secret Isolation**: DEK per tenant

### Detection

- Alert: Unusual query patterns on credential tables
- Alert: Bulk data access
- Audit: Access to sensitive tables

### Recovery

1. Rotate all provider secrets
2. Review access logs for exfiltration
3. Limit database access permissions
4. Implement query whitelisting

---

## Related Documents

- `05-security/threat-model.md`
- `05-security/replay-protection.md`
- `05-security/tenant-isolation.md`
- `16-failure-models/replay-attacks.md`