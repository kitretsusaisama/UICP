# Webhook Security

## Metadata
```yaml
title: Webhook Security
domain: security
owner: Platform Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/replay-protection.md
  - 05-security/threat-model.md
related-docs:
  - 04-communication/webhook-reconciliation.md
  - 05-security/encryption-model.md
related-queues:
  - provider:webhook:*
related-services:
  - WebhookReceiver
  - WebhookValidator
  - EventProcessor
related-runtime-states:
  - webhook-received
  - webhook-validated
  - webhook-processed
```

---

## Executive Summary

Webhooks are inbound HTTP callbacks from providers (email, SMS, etc.) that require special security handling. This document covers webhook signature validation, deduplication, and processing.

---

## Webhook Security Measures

### 1. Signature Validation

All webhooks must include valid signatures to verify authenticity.

```
Provider sends:
- X-Webhook-Signature: hmac-sha256=...
- X-Webhook-Timestamp: 1704067200
```

```typescript
async function validateWebhookSignature(
  payload: string,
  signature: string,
  timestamp: string,
  secret: string
): Promise<boolean> {
  // 1. Validate timestamp (prevent replay)
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(timestamp)) > 300) {
    return false;
  }

  // 2. Construct signing payload
  const payloadToSign = `${timestamp}.${payload}`;

  // 3. Calculate expected signature
  const expected = crypto
    .createHmac('sha256', secret)
    .update(payloadToSign)
    .digest('base64url');

  // 4. Compare signatures
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}
```

### 2. Event Deduplication

Providers may retry webhooks, so deduplication is critical.

```
┌─────────────────────────────────────────────────────────────────┐
│                  WEBHOOK DEDUPLICATION                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Webhook received with eventId                                  │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────┐                                           │
│  │ Check Redis     │                                           │
│  │ EXISTS event:{provider}:{eventId}                          │
│  └────────┬────────┘                                           │
│           │                                                    │
│      ┌────┴────┐                                               │
│      │ Exists? │                                               │
│      └────┬────┘                                               │
│      Yes  │  No                                                │
│      ┌────┴────┐                                               │
│      ▼         ▼                                               │
│  ┌────────┐ ┌─────────────────┐                                │
│  │ Return │ │ Process webhook │                                │
│  │ 200 OK │ │ Store event ID  │                                │
│  └────────┘ │ with 7-day TTL  │                                │
│             └────────┬────────┘                                │
│                      ▼                                         │
│             ┌─────────────────┐                                │
│             │ Process event   │                                │
│             │ Queue async     │                                │
│             └─────────────────┘                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3. Processing Pipeline

```typescript
@Controller('/webhooks')
export class WebhookController {
  @Post('/:provider')
  async handleWebhook(
    @Param('provider') provider: string,
    @Req() request: Req,
    @Headers('x-webhook-signature') signature: string,
    @Headers('x-webhook-timestamp') timestamp: string
  ) {
    // 1. Get provider secret
    const secret = await this.getProviderSecret(provider);

    // 2. Validate signature
    const payload = await request.text();
    const isValid = await validateWebhookSignature(
      payload, signature, timestamp, secret
    );

    if (!isValid) {
      throw new UnauthorizedException('Invalid signature');
    }

    // 3. Parse event
    const event = JSON.parse(payload);

    // 4. Deduplicate
    const processed = await this.deduplicate(provider, event.id);
    if (processed) {
      return { status: 'already_processed' };
    }

    // 5. Queue for processing
    await this.eventQueue.publish({
      provider,
      eventId: event.id,
      payload: event,
      receivedAt: new Date()
    });

    return { status: 'accepted' };
  }
}
```

---

## Supported Providers

| Provider | Signature Header | Validation Method |
|----------|-----------------|-------------------|
| SendGrid | X-Signature-MD5 | HMAC-MD5 |
| Resend | Resend-Signature | Ed25519 |
| Twilio | X-Twilio-Signature | HMAC-SHA1 |
| Mailgun | Signature | HMAC-SHA256 |
| AWS SES | AWS-Signature | AWS Signature v4 |

---

## Failure Modes

| Mode | Impact | Mitigation |
|------|--------|------------|
| Signature validation fails | Event rejected | Log, alert, manual reprocess |
| Duplicate processing | State corruption | Event ID deduplication |
| Provider retry storm | Queue backup | Backoff, max retries |
| Secret compromised | Fake webhooks | Rotation, alert monitoring |

---

## Trust Boundaries

| Zone | Trust Level |
|------|-------------|
| Internet → Webhook Endpoint | UNTRUSTED |
| Webhook Validator | BOUNDARY |
| Event Processor | TRUSTED |
| Event Queue | TRUSTED |

---

## Monitoring

| Metric | Alert |
|--------|-------|
| webhook_invalid_signature | > 5/min |
| webhook_duplicate_events | > 100/min |
| webhook_processing_failures | > 10/min |

---

## Related Documents

- `05-security/replay-protection.md`
- `04-communication/webhook-reconciliation.md`
- `05-security/encryption-model.md`