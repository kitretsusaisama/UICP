# Reconciliation Lineage

## Metadata
```yaml
title: Reconciliation Lineage
domain: billing-audit
owner: Finance/Platform Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: LOW
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - event-store
  - audit-log
  - billing-repository
related-docs:
  - 16-billing/reconciliation.md
  - 15-runtime-lineage/delivery-lineage.md
  - 15-runtime-lineage/auth-lineage.md
related-queues: []
related-services:
  - reconciliation-engine
  - audit-service
  - billing-service
related-providers:
  - sendgrid
  - twilio
  - aws-sns
```

---

## Overview

Reconciliation lineage tracks the correlation between system records, provider callbacks, and billing events. This lineage enables financial audit, usage verification, and discrepancy detection across communication operations.

---

## Reconciliation Flow

### Usage Collection Lineage

```
Message Processing Complete
    ↓
Event Emission (Message Processed)
    ↓
Event Store Persistence
    ↓
Daily Aggregation Job
    ↓
Tenant Usage Summary Generated
    ↓
Provider Cost Lookup
    ↓
Billing Record Creation
    ↓
Reconciliation Data Prepared
```

### Provider Reconciliation Lineage

```
Provider API Query (Usage Summary)
    ↓
Provider Data Extraction
    ↓
System Data Comparison
    ↓
Discrepancy Detection
    ↓
Variance Calculation
    ↓
Reconciliation Report Generation
    ↓
Alert on Threshold Breach
```

---

## Reconciliation Types

### Volume Reconciliation

```
System Message Count: 10,000
Provider Message Count: 9,985
    ↓
Variance: 15 messages (0.15%)
    ↓
Root Cause Analysis
    ↓
Classification: Network Loss / Duplicates / Provider Error
    ↓
Adjustment Decision
    ↓
Reconciliation Entry Logged
```

### Cost Reconciliation

```
System Calculated Cost: $150.00
Provider Invoiced Cost: $152.50
    ↓
Variance: $2.50 (1.67%)
    ↓
Rate Lookup Verification
    ↓
Tier Application Check
    ↓
Currency Conversion Validation
    ↓
Dispute or Acceptance Decision
```

---

## Trace Correlation

Each reconciliation event captures:
- **reconciliationId**: Unique reconciliation identifier
- **periodStart**: Billing period start date
- **periodEnd**: Billing period end date
- **tenantId**: Tenant for billing attribution
- **systemCount**: Internal message count
- **providerCount**: Provider reported count
- **variance**: Difference calculation
- **varianceReason**: Root cause classification
- **resolution**: Adjustment applied

---

## Audit Trail

Reconciliation maintains complete audit:
1. Source data snapshots preserved
2. Calculation methodology logged
3. Approval workflow tracked
4. Adjustment justifications recorded
5. Historical comparison available

---

## Discrepancy Resolution

When variances detected:

1. **Automatic Resolution** (< 0.1% variance)
   - System auto-adjusts
   - Log entry created

2. **Manual Review** (0.1% - 1% variance)
   - Alert generated
   - Finance team review
   - Approval workflow

3. **Investigation Required** (> 1% variance)
   - Detailed analysis initiated
   - Provider contact if needed
   - Escalation to management

---

## SLA Impact

Reconciliation affects service metrics:
- Accurate usage reporting for customer billing
- Provider cost verification for financial planning
- Variance trends indicating system issues
- Audit readiness for compliance requirements

---

## Related Documents

- `15-runtime-lineage/delivery-lineage.md` - Delivery tracking
- `15-runtime-lineage/auth-lineage.md` - Authentication context
- `16-billing/reconciliation.md` - Billing reconciliation design
- `10-security/audit-logging.md` - Audit system