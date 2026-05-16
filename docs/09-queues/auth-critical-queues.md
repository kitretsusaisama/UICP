# Auth-Critical Queues

## Metadata
```yaml
title: Auth-Critical Queues
domain: queues
owner: Security Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: CRITICAL
provider-impact: HIGH
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - queue-overview.md
  - queue-topology.md
  - replay-safe-processing.md
  - queue-isolation.md
related-docs:
  - 05-security/otp-delivery.md
  - 05-security/mfa-requirements.md
  - 16-failure-models/auth-failures.md
related-queues:
  - otp-fastlane
related-services:
  - BullMQ
  - Redis cluster
  - Twilio
  - SendGrid
related-providers:
  - Twilio (SMS OTP)
  - SendGrid (Email OTP)
related-runtime-states:
  - OTP_GENERATED
  - OTP_SENT
  - OTP_DELIVERED
  - OTP_FAILED
  - OTP_EXPIRED
  - OTP_VERIFIED
related-threat-models:
  - OTP interception
  - OTP brute force
  - OTP resend abuse
  - Delivery mechanism exploitation
```

---

## Overview

Auth-critical queues handle one-time password (OTP) generation and delivery, which is essential for authentication and authorization. These queues have the highest security requirements and require special handling to prevent unauthorized access, fraud, and security breaches.

---

## OTP Queue: otp-fastlane

### Queue Characteristics

| Property | Value |
|----------|-------|
| Priority | CRITICAL (1) |
| Max Concurrent | 50 |
| TTL | 300 seconds |
| Retry Policy | Immediate (max 2 attempts) |
| DLQ | None (synchronous failure) |
| SLA | < 500ms p99 |

### Processing Flow

```
User Request → Validate Request → Generate OTP → Store in Redis
     → Queue for Delivery → Send via Provider → Update Status
     → Return to User
```

---

## Security Controls

### OTP Generation

```typescript
class SecureOTPGenerator {
  private otpLength = 6;
  private entropyBits = 20; // ~1 million combinations

  generateOTP(): string {
    // Use cryptographically secure random
    const buffer = crypto.randomBytes(4);
    const otp = parseInt(buffer.toString('hex'), 16) % 1000000;
    return otp.toString().padStart(6, '0');
  }

  async storeOTP(phone: string, otp: string): Promise<void> {
    const hashedOTP = await hashOTP(otp);
    await redis.set(`otp:${phone}`, hashedOTP, { EX: 300 }); // 5 min TTL

    // Rate limit storage
    await incrementRateLimit(`ratelimit:otp:${phone}`, 60, 5); // 5 per minute
  }

  async verifyOTP(phone: string, input: string): Promise<boolean> {
    const storedHash = await redis.get(`otp:${phone}`);
    const inputHash = await hashOTP(input);

    if (storedHash === inputHash) {
      // Delete after successful verification
      await redis.del(`otp:${phone}`);
      return true;
    }

    // Increment failed attempts
    await incrementRateLimit(`otp:failed:${phone}`, 3600, 3);
    return false;
  }
}
```

### Rate Limiting

| Action | Limit | Window | Penalty |
|--------|-------|--------|---------|
| Request OTP | 5 | Per minute | Reject |
| Verify OTP | 3 | Per hour | Lock account |
| Failed verification | 5 | Per hour | 15 min lockout |

---

## Delivery Mechanisms

### SMS Delivery

```typescript
async function deliverOTPBySMS(phone: string, otp: string): Promise<void> {
  // Validate phone number format
  const validatedPhone = validatePhoneNumber(phone);
  if (!validatedPhone) {
    throw new ValidationError('Invalid phone number');
  }

  // Send via Twilio with tracking
  const message = await twilio.messages.create({
    body: `Your UICP verification code: ${otp}. Valid for 5 minutes.`,
    from: process.env.OTP_FROM_NUMBER,
    to: validatedPhone
  });

  // Store message SID for debugging
  await redis.hset(`otp:message:${phone}`, {
    sid: message.sid,
    status: message.status,
    sentAt: Date.now()
  });
}
```

### Email Delivery

```typescript
async function deliverOTPByEmail(email: string, otp: string): Promise<void> {
  // Validate email format
  const validatedEmail = validateEmail(email);
  if (!validatedEmail) {
    throw new ValidationError('Invalid email');
  }

  // Send via SendGrid
  await sendgrid.send({
    to: validatedEmail,
    from: 'noreply@uicp.com',
    subject: 'Your UICP Verification Code',
    templateId: 'd-otp-verification',
    dynamicTemplateData: {
      otp: otp,
      validFor: '5 minutes',
      ip: getClientIP(),
      timestamp: new Date().toISOString()
    }
  });
}
```

---

## Threat Mitigation

### OTP Interception Prevention

- **HSTS**: Enforce HTTPS for all OTP delivery endpoints
- **PII Masking**: Log phone numbers partially (***1234)
- **Provider TLS**: Ensure provider connections use TLS 1.2+
- **No URL in SMS**: Prevent clickable links in OTP messages

### Brute Force Prevention

```typescript
async function checkBruteForce(phone: string): Promise<void> {
  const failedAttempts = await redis.get(`otp:failed:${phone}`);

  if (failedAttempts >= 5) {
    // Lock account
    await redis.setex(`otp:locked:${phone}`, 900, '1'); // 15 min lock
    throw new SecurityError('Too many failed attempts. Account temporarily locked.');
  }

  // Add exponential backoff for repeated failures
  const waitTime = Math.pow(2, failedAttempts) * 1000;
  if (waitTime > 1000) {
    await sleep(waitTime);
  }
}
```

### Resend Abuse Prevention

```typescript
async function handleResendRequest(phone: string): Promise<void> {
  const lastSendTime = await redis.get(`otp:last:${phone}`);

  if (lastSendTime) {
    const timeSinceLastSend = Date.now() - parseInt(lastSendTime);
    if (timeSinceLastSend < 60000) { // 1 minute cooldown
      throw new RateLimitError('Please wait before requesting a new code');
    }
  }

  // Update last send time
  await redis.set(`otp:last:${phone}`, Date.now().toString(), { EX: 3600 });
}
```

---

## Audit Logging

### Required Audit Events

| Event | Data | Retention |
|-------|------|-----------|
| OTP generated | phone, method, requester IP | 7 years |
| OTP sent | message SID, provider response | 7 years |
| OTP verified | success/failure, IP | 7 years |
| OTP failed | failure reason, IP | 7 years |
| Rate limit triggered | phone, limit type | 1 year |

```typescript
async function auditOTPEvent(event: OTPEvent): Promise<void> {
  await auditLog.insert({
    eventType: event.type,
    tenantId: event.tenantId,
    phoneMasked: maskPhone(event.phone),
    ipAddress: event.ip,
    timestamp: new Date(),
    metadata: {
      success: event.success,
      method: event.method,
      provider: event.provider
    }
  });
}
```

---

## Monitoring

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `uicp.otp.generated` | OTPs generated | > 10000/min |
| `uicp.otp.delivery.success` | Successful delivery | < 95% |
| `uicp.otp.verification.success` | Successful verification | < 80% |
| `uicp.otp.brute_force.detected` | Brute force attempts | > 10/min |
| `uicp.otp.resend.abuse` | Resend abuse | > 100/min |

---

## Related Documents

- `09-queues/queue-overview.md`
- `09-queues/replay-safe-processing.md`
- `09-queues/queue-isolation.md`
- `05-security/otp-delivery.md`
- `05-security/mfa-requirements.md`
- `16-failure-models/auth-failures.md`