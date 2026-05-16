# Suspicious Login Detection

## Metadata
```yaml
title: Suspicious Login Detection
domain: security
owner: security-team
criticality: CRITICAL
runtime-impact: MEDIUM
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - login-flow.md
  - device-trust.md
  - auth-security.md
related-docs:
  - auth-edge-cases.md
  - auth-failure-recovery.md
  - auth-observability.md
related-queues:
  - security-alerts
  - anomaly-events
related-services:
  - AnomalyDetector
  - GeoipService
  - DeviceFingerprintService
related-runtime-states:
  - LOGIN_NORMAL
  - LOGIN_SUSPICIOUS
  - LOGIN_BLOCKED
```

---

## Detection Signals

### Location-Based Signals

| Signal | Description | Threshold |
|--------|-------------|-----------|
| Impossible Travel | Login from distant locations | < 2 hours between > 500km apart |
| New Country | First login from new country | Any new country code |
| Unexpected Location | Login from unusual location for user | Deviation from historical pattern |
| VPN/Proxy Detection | IP from known VPN/proxy range | Match known VPN ranges |

### Device Signals

| Signal | Description | Threshold |
|--------|-------------|-----------|
| Unknown Device | Device fingerprint not recognized | New fingerprint |
| Device Change | Significant fingerprint change | > 30% signal difference |
| Multiple Devices | Simultaneous sessions from different devices | > 5 devices in 1 hour |

### Behavioral Signals

| Signal | Description | Threshold |
|--------|-------------|-----------|
| Unusual Time | Login at unusual hour for user | Outside 2 standard deviations |
| Failed Then Success | Failed attempts followed by success | > 3 failures before success |
| Rapid Attempts | High frequency of login attempts | > 10 attempts in 5 minutes |

---

## Risk Scoring

### Score Calculation

The anomaly detector calculates risk score (0-100) from weighted signals:

```typescript
interface RiskScore {
  total: number;
  signals: {
    name: string;
    weight: number;
    value: number;
  }[];
  recommendation: 'allow' | 'challenge' | 'block';
}
```

### Score Thresholds

| Score Range | Action | Description |
|-------------|--------|-------------|
| 0-30 | Allow | Normal login, no additional verification |
| 31-70 | Challenge | Require OTP or MFA verification |
| 71-100 | Block | Deny login, require admin review |

---

## Response Actions

### Challenge

For moderate risk, the system requires additional verification (OTP email/SMS, MFA). The login flow returns `MFA_REQUIRED` status.

### Notification

For any suspicious login, the user receives notification via email or push (if enabled). Notification includes login details: time, IP, device.

### Audit

All suspicious login attempts log to security queue with full context. Security team reviews high-risk events.

---

## Machine Learning Model

### Features

The ML model uses these features for detection:

- User historical login patterns (times, locations, devices)
- Account age and activity
- Peer group behavior (similar users)
- Global threat intelligence

### Model Updates

Model retrains weekly with recent labeled data. False positives feed back into training to improve accuracy.

---

## Related Documents

- `login-flow.md` - Login process
- `device-trust.md` - Device verification
- `auth-observability.md` - Monitoring and alerts