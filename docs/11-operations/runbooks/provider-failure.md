# Runbook: Provider Failure

## Metadata
```yaml
title: Provider Failure Runbook
domain: operations
criticality: HIGH
```

---

## Scenario

Primary email/SMS provider experiences outage.

---

## Symptoms

- `uicp.provider.delivery_failure` > 5%
- `uicp.queue.email.backlog` increasing
- Customer complaints about missing OTPs/emails

---

## Steps

### 1. Verify (0-2 min)
```bash
curl https://api.uicp.example/v1/providers/health
```

### 2. Check Failover
- System should auto-failover to backup
- Verify messages being processed

### 3. Monitor (2-30 min)
- Watch queue backlog decrease
- Confirm provider health improves

### 4. If No Failover (manual intervention)
```
1. Edit Redis key: provider:scores
2. Set backup provider as primary
3. Clear provider cache
```

### 5. Post-Incident
- Process DLQ messages
- Review provider SLA
- Update runbook if needed

---

## Contacts

- SES: AWS Support
- Resend: support@resend.com
- Msg91: support@msg91.com

