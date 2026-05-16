# Maileroo Runtime

## Metadata
```yaml
title: Maileroo Runtime
domain: communication
owner: Platform Team
criticality: MEDIUM
runtime-impact: MEDIUM
security-impact: LOW
queue-impact: LOW
provider-impact: MEDIUM
tenant-impact: LOW
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - provider-runtime.md
  - fallback-policies.md
related-docs:
  - provider-selection.md
  - delivery-intelligence.md
related-queues:
  - email-delivery
related-services:
  - MailerooAdapter
related-providers:
  - Maileroo
related-runtime-states:
  - maileroo_initializing
  - maileroo_ready
  - maileroo_sending
  - maileroo_failed
related-threat-models:
  - Low deliverability reputation
```

---

## Overview

Maileroo is a cost-effective email provider used primarily as a fallback option. While not as feature-rich as SES or Resend, it provides reliable delivery for non-critical communications and serves as a tertiary backup.

---

## Configuration

### API Configuration

```typescript
interface MailerooConfig {
  apiKey: string;
  domain: string;
  webhookUrl: string;
  isTransactional: boolean;   // Higher priority queue
}
```

### Sender Setup

```typescript
async function configureSender(config: MailerooConfig): Promise<void> {
  await mailerooClient.verifyDomain({
    domain: config.domain,
    webhookUrl: config.webhookUrl
  });

  // Add SPF and DKIM records to DNS
  const spfRecord = 'v=spf1 include:_spf.maileroo.com ~all';
  const dkimRecord = 'v=DKIM1; k=rsa; p=...';
}
```

---

## Sending Email

### Standard Send

```typescript
async function sendEmail(request: EmailRequest): Promise<string> {
  const response = await maileroo.emails.send({
    from: `noreply@${request.senderDomain}`,
    to: request.recipients,
    subject: request.subject,
    html: request.htmlBody,
    text: request.textBody,
    custom_id: request.messageId
  });

  return response.data.id;
}
```

### Bulk Operations

```typescript
async function sendBulk(emails: EmailRequest[]): Promise<BulkResult> {
  // Maileroo batch limit: 500 per request
  const batches = chunk(emails, 500);
  const results = [];

  for (const batch of batches) {
    const result = await maileroo.emails.sendBatch({
      emails: batch.map(e => ({
        from: `noreply@${e.senderDomain}`,
        to: e.recipients,
        subject: e.subject,
        html: e.htmlBody
      }))
    });
    results.push(result);
  }

  return mergeResults(results);
}
```

---

## Capabilities

### Supported Features

| Feature | Support | Notes |
|---------|---------|-------|
| HTML email | Yes | Full support |
| Plain text | Yes | Required fallback |
| Attachments | Yes | 10MB max |
| Templates | Yes | Basic substitution |
| Webhooks | Yes | Limited events |
| Tracking | Partial | Opens only |

### Limitations

- No dedicated IP pool
- Limited analytics
- No A/B testing
- Basic template system
- Lower sending limits

---

## Performance Characteristics

### Delivery Metrics

| Metric | Target | Actual |
|--------|--------|--------|
| Inbox rate | 90% | 92% |
| Delivery time | < 5s | 3.2s |
| Bounce rate | < 2% | 1.5% |
| Spam rate | < 1% | 0.8% |

### Use Cases

| Use Case | Recommended | Notes |
|----------|-------------|-------|
| Transactional | Sometimes | Use SES/Resend instead |
| Marketing | No | Not recommended |
| Fallback | Yes | Primary use case |
| Testing | Yes | Good for dev |

---

## Cost Structure

| Plan | Monthly Fee | Included | Overage |
|------|-------------|----------|---------|
| Starter | $29 | 10,000 | $0.003 |
| Growth | $79 | 50,000 | $0.002 |
| Scale | $199 | 150,000 | $0.001 |
| Enterprise | Custom | Custom | Custom |

---

## Monitoring

### Key Metrics

```typescript
interface MailerooMetrics {
  sent: number;
  delivered: number;
  bounced: number;
  opened: number;
  avgLatency: number;
  costThisMonth: number;
}
```

---

## Related Documents

- `04-communication/communication-overview.md`
- `04-communication/fallback-policies.md`
- `04-communication/provider-selection.md`