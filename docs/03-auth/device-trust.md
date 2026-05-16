# Device Trust

## Metadata
```yaml
title: Device Trust and Fingerprinting
domain: authentication
owner: security-team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: LOW
provider-impact: LOW
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - session-management.md
  - login-flow.md
  - auth-security.md
related-docs:
  - suspicious-login-detection.md
  - auth-edge-cases.md
  - replay-prevention.md
related-queues:
  - device-events
  - security-alerts
related-services:
  - DeviceTrustService
  - FingerprintService
  - SessionService
related-runtime-states:
  - DEVICE_TRUSTED
  - DEVICE_UNKNOWN
  - DEVICE_REVOKED
```

---

## Device Fingerprinting

### Fingerprint Generation

The client device fingerprint combines multiple signals into a hash:

| Signal | Source | Weight |
|--------|--------|--------|
| User Agent | HTTP Header | High |
| Screen Resolution | JavaScript API | Medium |
| Timezone | JavaScript API | Low |
| Platform | navigator.platform | High |
| Language | navigator.language | Low |
| Installed Fonts | JavaScript Detection | Medium |
| Canvas Fingerprint | Canvas API | High |

```typescript
interface DeviceFingerprint {
  hash: string; // SHA-256 of normalized signals
  signals: {
    userAgent: string;
    platform: string;
    screenResolution: string;
    timezone: string;
    language: string;
    canvasHash: string;
  };
  createdAt: Date;
}
```

### Fingerprint Stability

Fingerprints may change due to browser updates, OS upgrades, or configuration changes. The system maintains fingerprint history per user to detect significant changes while allowing minor variations.

---

## Trust Levels

### Trusted Device

A device that has been explicitly trusted by the user or verified through MFA. Trusted devices bypass step-up authentication for low-risk operations.

```
Trust Level: TRUSTED
Requirements: MFA verified OR user explicit trust action
Expiration: 30 days (configurable)
```

### Verified Device

A device that has completed one successful authentication with full verification. May require MFA for sensitive operations.

```
Trust Level: VERIFIED
Requirements: Successful login with any method
Expiration: 90 days (sliding)
```

### Unknown Device

A new device without prior authentication history. Always requires additional verification (OTP or MFA) before granting access.

```
Trust Level: UNKNOWN
Requirements: None (default for new devices)
```

---

## Device Trust Workflow

### Trust Action

Users can trust a device through security settings or after successful MFA login. Trust actions require recent MFA verification and create a device trust record.

```typescript
async function trustDevice(userId: string, fingerprint: string): Promise<void> {
  const recentMfa = await this.mfaService.verifyRecentMfa(userId);

  if (!recentMfa) {
    throw new MfaRequiredError();
  }

  await this.deviceTrustStore.create({
    userId,
    fingerprint,
    trustedAt: new Date(),
    expiresAt: addDays(new Date(), 30),
    trustLevel: 'TRUSTED'
  });
}
```

### Trust Revocation

Users can revoke device trust at any time. Security events (password change, suspicious activity) automatically revoke all device trusts for the user.

---

## Device-Based Access Control

### Risk-Based Step-Up

Authentication risk assessment considers device trust level. Unknown devices trigger OTP challenge regardless of session state. Trusted devices allow streamlined authentication.

```json
{
  "deviceTrust": {
    "level": "UNKNOWN",
    "requiresMfa": true,
    "requiresVerification": true
  }
}
```

### Device Bound Sessions

Sessions store device fingerprint. Requests with matching fingerprint validate normally. Mismatched fingerprint triggers re-authentication for sensitive endpoints.

---

## Related Documents

- `session-management.md` - Session binding
- `suspicious-login-detection.md` - Anomaly detection
- `auth-security.md` - Security controls