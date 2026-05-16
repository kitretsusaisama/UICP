# Emergency Procedures

## Metadata
```yaml
title: Emergency Procedures
domain: operations
owner: platform-team
criticality: CRITICAL
runtime-impact: CRITICAL
security-impact: CRITICAL
queue-impact: CRITICAL
provider-impact: CRITICAL
tenant-impact: CRITICAL
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - docs/11-operations/runbooks/ses-outage.md
  - docs/11-operations/runbooks/redis-degradation.md
  - docs/11-operations/runbooks/jwt-compromise.md
  - docs/11-operations/runbooks/regional-failover.md
related-docs:
  - docs/07-security/incident-response.md
  - docs/09-compliance/emergency-communication.md
  - docs/09-compliance/data-breach-response.md
related-queues:
  - security-incidents
  - emergency-notifications
related-services:
  - all-services
```

---

## Overview

This document outlines emergency procedures for critical incidents affecting the UICP platform. These procedures are designed to minimize downtime, protect data, and ensure rapid recovery.

---

## Emergency Classification

### Level 1 - Critical (P0)

**Criteria**:
- Complete service outage
- Security breach confirmed
- Data loss or corruption
- Multi-region failure

**Response Time**: 15 minutes
**Escalation**: Immediate CEO/CTO notification

### Level 2 - High (P1)

**Criteria**:
- Single service failure affecting > 50% tenants
- Significant performance degradation
- Partial security incident

**Response Time**: 30 minutes
**Escalation**: VP Engineering notification

### Level 3 - Medium (P2)

**Criteria**:
- Minor service degradation
- Single tenant impact
- Non-critical system failure

**Response Time**: 2 hours
**Escalation**: Team lead notification

---

## Emergency Contacts

| Role | Name | Phone | Slack |
|------|------|-------|-------|
| On-Call Engineer | rotation | +1-555-0100 | #oncall |
| Platform Lead | [NAME] | +1-555-0101 | #platform-leads |
| Security Lead | [NAME] | +1-555-0102 | #security |
| VP Engineering | [NAME] | +1-555-0103 | #engineering-leadership |
| CEO | [NAME] | +1-555-0104 | #exec |

---

## Emergency Response Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    INCIDENT DETECTED                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                 ASSESS & CLASSIFY                                │
│  - Is this a real emergency?                                    │
│  - What is the impact level?                                    │
│  - Who needs to be notified?                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
         ┌───────────────────────────────────────────┐
         │         LEVEL 1 (P0)                      │
         │  - Create PagerDuty incident              │
         │  - Alert all on-call engineers           │
         │  - Notify executive team                 │
         │  - Activate incident channel              │
         └───────────────────────────────────────────┘
                              │
         ┌───────────────────────────────────────────┐
         │         LEVEL 2 (P1)                      │
         │  - Create PagerDuty incident              │
         │  - Alert primary on-call                  │
         │  - Notify team lead                       │
         └───────────────────────────────────────────┘
                              │
         ┌───────────────────────────────────────────┐
         │         LEVEL 3 (P2)                      │
         │  - Create issue ticket                   │
         │  - Alert via Slack                       │
         │  - Plan response during business hours   │
         └───────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                 MITIGATE & CONTAIN                              │
│  - Execute runbook for known issue                             │
│  - Isolate affected systems                                    │
│  - Preserve evidence for forensics                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                 RESOLVE & RECOVER                               │
│  - Apply fix or rollback               │
│  - Verify service restoration          │
│  - Monitor for recurrence              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                 POST-INCIDENT                                   │
│  - Document timeline                   │
│  - Conduct root cause analysis         │
│  - Update runbooks and procedures      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Emergency Communication

### Initial Notification

```bash
# Create Slack incident channel
/incline create-incident #incident-{date}-{type}

# Send alert
curl -X POST https://slack.com/api/chat.postMessage \
  -H "Authorization: Bearer $BOT_TOKEN" \
  -d '{"channel":"#incident-2024-001","text":"🚨 INCIDENT: Service down - investigating"}'
```

### Status Page Updates

```bash
# Update status page
curl -X POST https://status.uicp.io/incidents \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"status":"investigating","message":"We are investigating reports of API errors"}'
```

### Customer Communication Template

> **Incident**: API Service Degradation
> **Status**: Investigating
> **Impact**: Some customers may experience timeouts
> **Next Update**: 30 minutes
> **Contact**: support@uicp.io

---

## Common Emergency Procedures

### Service Outage

1. **Verify outage**
   ```bash
   curl -s -o /dev/null -w "%{http_code}" https://api.uicp.io/health
   ```

2. **Check system status**
   ```bash
   kubectl get pods -n uicp
   kubectl get nodes
   ```

3. **Check logs**
   ```bash
   kubectl logs -n uicp -l app=api-gateway --tail=100
   ```

4. **Execute runbook** or escalate

5. **Update status**

---

### Security Incident

1. **Preserve evidence**
   ```bash
   # Capture current state
   kubectl get pods -n uicp > pods-state.txt
   kubectl logs -n uicp --all-containers > logs-state.txt
   
   # Isolate affected system
   kubectl delete ingress -n uicp {affected-ingress}
   ```

2. **Block attack vector**
   ```bash
   # Block IP
   iptables -A INPUT -s {ATTACKER_IP} -j DROP
   
   # Revoke compromised credentials
   curl -X POST http://auth-service/internal/revoke -d '{"token":"{TOKEN}"}'
   ```

3. **Notify security team**

4. **Document everything**

---

### Data Loss

1. **Stop write operations**
   ```bash
   # Enable read-only mode
   redis-cli CONFIG SET readonly yes
   ```

2. **Verify backup availability**
   ```bash
   # List recent backups
   aws s3 ls s3://uicp-backups/database/ | tail -5
   
   # Test backup integrity
   ./scripts/verify-backup.sh --latest
   ```

3. **Restore from backup**
   ```bash
   # For database
   ./scripts/restore-database.sh --backup={timestamp}
   
   # For Redis
   redis-cli -h redis-backup.cluster.io SLAVEOF primary
   ```

4. **Verify data integrity**
   ```bash
   # Run integrity checks
   psql -h db.uicp.io -U uicp -c "SELECT count(*) FROM users;"
   ```

---

## Emergency Command Reference

| Action | Command |
|--------|---------|
| Enable maintenance mode | `redis-cli SET maintenance:enabled "true"` |
| Block all traffic | `kubectl scale ingress default 0 -n uicp` |
| Scale to zero (service) | `kubectl scale deployment {svc} --replicas=0 -n uicp` |
| Rollback deployment | `kubectl rollout undo deployment/{svc} -n uicp` |
| Enable Read-Only DB | `psql -h db.uicp.io -U uicp -c "ALTER SYSTEM SET default_transaction_read_only = on;"` |
| Flush Redis cache | `redis-cli FLUSHDB async` |
| Kill long-running queries | `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'active' AND query_start < now() - interval '5 minutes';` |

---

## Post-Incident Requirements

1. **Timeline**: Create detailed incident timeline within 24 hours
2. **RCA**: Complete root cause analysis within 72 hours
3. **Documentation**: Update runbooks and procedures
4. **Prevention**: Identify and implement prevention measures
5. **Communication**: Share lessons learned with team

---

## Related Documents

- [Rollback Strategy](./rollback-strategy.md)
- [Runbooks Index](./runbooks/index.md)
- [Security Incident Response](./security-incident-response.md)