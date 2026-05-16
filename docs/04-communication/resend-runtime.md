# Resend Runtime

## Metadata
```yaml
title: Resend Runtime
domain: communication
owner: Platform Team
criticality: MEDIUM
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: MEDIUM
provider-impact: MEDIUM
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
  - template-runtime.md
related-queues:
  - email-delivery
related-services:
  - ResendAdapter
  - ResendConfigurationManager
related-providers:
  - Resend
related-runtime-states:
  - resend_initializing
  - resend_ready
  - resend_sending
  - resend_rate_limited
  - resend_failed
related-threat-models:
  - API key exposure
  - Domain verification bypass
```

---

## Overview

Resend is a modern email delivery service used as a secondary provider. It offers a developer-friendly API, competitive pricing, and reliable delivery for transactional and marketing emails.

---

## Configuration

### API Setup

```typescript
interface ResendConfig {
  apiKey: string;
  domain: string;           // Verified sending domain
  webhooks: {
    deliveried: string;     // Delivery webhook URL
    bounced: string;        // Bounce webhook URL
    complained: string;     // Complaint webhook URL
  };
}
```

### Domain Verification

Resend requires domain verification via DNS records:

```
Type: TXT
Name: resend._domainkey.{domain}
Value: v=DKIM1; k=rsa; p={public_key}
```

---

## Sending Email

### Single Email

```typescript
async function sendEmail(email: EmailRequest): Promise<string> {
  const response = await resend.emails.send({
    from: `noreply@${email.senderDomain}`,
    to: email.recipients,
    subject: email.subject,
    html: email.htmlBody,
    text: email.textBody,
    reply_to: email.replyTo,
    headers: {
      'X-Message-ID': email.messageId,
      'X-Tenant-ID': email.tenantId
    }
  });

  return response.data?.id;
}
```

### Batch Sending

```typescript
async function sendBatch(emails: EmailRequest[]): Promise<BatchResult> {
  const result = await resend.batch.send({
    emails: emails.map(e => ({
      from: `noreply@${e.senderDomain}`,
      to: e.recipients,
      subject: e.subject,
      html: e.htmlBody
    }))
  });
  return result.data;
}
```

---

## Template Integration

### Dynamic Templates

```typescript
interface ResendTemplate {
  name: string;
  html: string;
  variables: string[];
}

// Render template
function renderTemplate(template: ResendTemplate, data: Record<string, any>): string {
  let html = template.html;
  for (const [key, value] of Object.entries(data)) {
    html = html.replace(new RegExp(`{{${key}}}`, 'g'), value);
  }
  return html;
}
```

---

## Rate Limits

| Plan | Emails/Month | Emails/Second |
|------|---------------|---------------|
| Free | 3,000 | 1 |
| Pro | 50,000 | 10 |
| Business | 150,000 | 50 |
| Enterprise | Custom | Custom |

UICP uses the Business plan with burst capacity.

---

## Webhook Events

| Event | Description | Handling |
|-------|-------------|----------|
| email.sent | Successfully sent | Update state |
| email.delivered | Delivered to inbox | Mark delivered |
| email.bounced | Delivery failed | Log bounce |
| email.complained | Spam complaint | Mark complaint |
| email.opened | Recipient opened | Track open |
| email.clicked | Recipient clicked | Track click |

---

## Delivery Performance

### Metrics Comparison

| Metric | SES | Resend | Notes |
|--------|-----|--------|-------|
| Inbox rate | 98% | 97% | Similar performance |
| Avg latency | 1.2s | 0.8s | Resend faster |
| Bounce rate | 0.5% | 0.8% | SES more strict |
| Spam rate | 0.1% | 0.2% | Both excellent |

---

## Cost Model

| Volume | Price/1000 | UICP Markup |
|--------|------------|--------------|
| 0-10K | $0.10 | 10% |
| 10K-50K | $0.08 | 10% |
| 50K-100K | $0.06 | 10% |
| 100K+ | $0.04 | 10% |

---

## Related Documents

- `04-communication/communication-overview.md`
- `04-communication/provider-runtime.md`
- `04-communication/template-runtime.md`