# SES Runtime

## Metadata
```yaml
title: SES Runtime
domain: communication
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - provider-runtime.md
  - communication-overview.md
related-docs:
  - provider-selection.md
  - delivery-intelligence.md
  - regional-routing.md
related-queues:
  - email-delivery
  - otp-fastlane
related-services:
  - SESAdapter
  - SESConfigurationManager
related-providers:
  - SES
related-runtime-states:
  - ses_initializing
  - ses_ready
  - ses_sending
  - ses_rate_limited
  - ses_suspended
  - ses_failed
related-threat-models:
  - SES quota exhaustion
  - Sending identity verification
  - Dedicated IP pool management
```

---

## Overview

SES (Simple Email Service) is the primary email provider for UICP, handling the majority of outbound email traffic. It provides global reach, high reliability, and detailed delivery analytics.

---

## Configuration

### Sender Identities

UICP supports multiple sender identities:

```typescript
interface SESSenderConfig {
  identityArn: string;        // Verified identity
  domain: string;             // Sending domain
  region: string;            // AWS region
  feedbackForwarding: boolean;
  configurationSet?: string;
}
```

### Configuration Sets

Tracking and routing configuration:

```typescript
interface SESConfigurationSet {
  name: string;
  trackingOptions: {
    clickTracking: boolean;
    openTracking: boolean;
    headerTopics?: string[];
  };
  deliveryOptions: {
    tlsPolicy: 'require' | 'optional';
    sendingPool?: string;
  };
}
```

---

## Sending Methods

### Direct Send

For transactional messages:

```typescript
async function sendDirectEmail(params: SES.SendEmailParams): Promise<string> {
  const result = await sesClient.sendEmail({
    Source: params.from,
    Destination: {
      ToAddresses: params.to,
      CcAddresses: params.cc,
      BccAddresses: params.bcc
    },
    Message: {
      Subject: { Data: params.subject },
      Body: {
        Html: { Data: params.html },
        Text: { Data: params.text }
      }
    },
    ConfigurationSetName: 'uicp-default'
  });
  return result.MessageId;
}
```

### Bulk Send

For high-volume campaigns:

```typescript
async function sendBulkEmail(templateName: string, recipients: Recipient[]): Promise<BulkSendResult> {
  const destination = recipients.map(r => ({
    Destination: { ToAddresses: [r.email] },
    ReplacementTemplateData: JSON.stringify(r.variables)
  }));

  return await sesClient.sendBulkTemplatedEmail({
    Source: config.source,
    Template: templateName,
    Destinations: destination,
    ConfigurationSetName: 'uicp-bulk'
  }).promise();
}
```

---

## Rate Limits and Quotas

### Sending Quotas

| Quota | Value | Notes |
|-------|-------|-------|
| Per second | 50 | Burst up to 100 |
| Per day | 100,000 | Regional limit |
| Max recipients/message | 50 | Per email |

### Quota Monitoring

```typescript
async function checkSESQuota(): Promise<QuotaStatus> {
  const quota = await sesClient.getSendQuota().promise();
  return {
    maxPerDay: quota.Max24HourSend,
    sentToday: quota.SentLast24Hours,
    maxPerSecond: quota.MaxSendRate,
    remaining: quota.Max24HourSend - quota.SentLast24Hours
  };
}
```

---

## Delivery Metrics

### Available Metrics

| Metric | Source | Update Frequency |
|--------|--------|------------------|
| Bounces | CloudWatch | Real-time |
| Complaints | SNS webhook | On event |
| Opens | Click tracking | On open |
| Clicks | Click tracking | On click |
| Delivery latency | CloudWatch | 1 min |

### Event Publishing

```
SES Events → SNS Topic → SQS Queue → Webhook Processor → Delivery Tracker
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|-------------|
| Throttling | Exceeded quota | Implement backoff |
| Account suspended | High bounce rate | Review sending practices |
| Identity not verified | Unverified sender | Complete verification |
| Template error | Invalid template | Validate template |

---

## Security

### Credential Management

- IAM role with least privilege
- Temporary credentials via STS
- Rotation every 90 days

### IP Allowlist

- Dedicated IP pool
- Warming schedule: 2 weeks
- Reputation monitoring

---

## Related Documents

- `04-communication/communication-overview.md`
- `04-communication/provider-runtime.md`
- `04-communication/regional-routing.md`