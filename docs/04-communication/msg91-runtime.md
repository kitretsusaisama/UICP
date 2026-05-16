# Msg91 Runtime

## Metadata
```yaml
title: Msg91 Runtime
domain: communication
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: LOW
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
  - queue-priorities.md
related-queues:
  - sms-delivery
  - otp-fastlane
related-services:
  - Msg91Adapter
  - OTPGenerator
related-providers:
  - Msg91
related-runtime-states:
  - msg91_initializing
  - msg91_ready
  - msg91_sending
  - msg91_delivered
  - msg91_failed
  - msg91_otp_expired
related-threat-models:
  - SMS fraud
  - OTP bypass attacks
```

---

## Overview

Msg91 is the primary SMS provider for UICP, specializing in Indian telecommunications. It provides reliable OTP delivery, transactional messaging, and marketing campaign capabilities with excellent coverage across Indian carriers.

---

## Configuration

### Sender ID

```typescript
interface Msg91Config {
  authKey: string;
  senderId: string;         // 6-char alphanumeric
  route: 'transactional' | 'promotional';
  country: '91';            // India
  webhookUrl: string;
}
```

### Supported Routes

| Route | Use Case | Priority | DLT Registration |
|-------|----------|----------|-------------------|
| Transactional | OTPs, alerts | Highest | Required |
| Promotional | Marketing | Low | Required |

---

## Sending SMS

### Single Message

```typescript
async function sendSMS(to: string, message: string): Promise<string> {
  const response = await msg91.sms.send({
    mobiles: to,
    message: message,
    sender: config.senderId,
    route: 'transactional'
  });

  return response.data[0].id;
}
```

### OTP Delivery

```typescript
async function sendOTP(phoneNumber: string): Promise<OTPResult> {
  const otp = generateOTP();
  const message = `Your verification code is ${otp}. Valid for 10 minutes.`;

  const result = await msg91.sms.send({
    mobiles: phoneNumber,
    message: message,
    sender: config.senderId,
    route: 'transactional',
    DLTTemplateId: '1234567890'
  });

  // Store OTP for verification
  await cache.set(`otp:${phoneNumber}`, otp, { ttl: 600 });

  return { messageId: result.data[0].id, expiresIn: 600 };
}
```

---

## OTP System

### Generation

```typescript
function generateOTP(): string {
  const digits = '0123456789';
  let otp = '';
  for (let i = 0; i < 6; i++) {
    otp += digits[Math.floor(Math.random() * 10)];
  }
  return otp;
}
```

### Verification

```typescript
async function verifyOTP(phoneNumber: string, submittedOTP: string): Promise<boolean> {
  const cached = await cache.get(`otp:${phoneNumber}`);
  if (!cached) return false;
  return cached === submittedOTP;
}
```

### Rate Limiting

- Maximum 5 OTP requests per phone per hour
- Maximum 3 verification attempts per OTP
- Auto-lock after 10 failed attempts

---

## Delivery Status

### Status Codes

| Status | Description | Action |
|--------|-------------|--------|
| QUEUED | Message queued | Wait |
| SUBMITTED | Sent to carrier | Processing |
| DELIVERED | Received by phone | Success |
| FAILED | Delivery failed | Retry/DLQ |
| UNKNOWN | Status unknown | Re-query |

### DLT Registration

All SMS requires DLT (Distributed Ledger Technology) registration:

```typescript
interface DLTConfig {
  entityId: string;
  templateId: string;
  header: string;
  content: string;
}
```

---

## Carrier Coverage

### Supported Carriers

| Carrier | Coverage | Reliability |
|---------|----------|-------------|
| Airtel | 99% | Excellent |
| Jio | 99% | Excellent |
| Vodafone Idea | 97% | Good |
| BSNL | 90% | Moderate |

### Delivery Time

- OTP: < 5 seconds (typical)
- Transactional: < 10 seconds
- Promotional: 1-5 minutes

---

## Cost Structure

| Message Type | Price/Message |
|--------------|----------------|
| OTP | $0.02 |
| Transactional | $0.025 |
| Promotional | $0.015 |

---

## Related Documents

- `04-communication/communication-overview.md`
- `04-communication/provider-runtime.md`
- `04-communication/queue-priorities.md`