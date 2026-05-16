# Observability - Auth Observability

## Metadata
```yaml
title: Observability - Auth Observability
domain: observability
owner: Security Engineering
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
  - 10-observability/metrics
  - 10-observability/tracing
  - 10-observability/logging
related-docs:
  - 04-security/authentication
  - 10-observability/incident-debugging
related-queues: []
related-services:
  - auth-service
  - token-service
  - session-manager
```

---

## Overview

Auth observability monitors authentication and authorization systems, providing visibility into credential validation, session management, and access control decisions. This document establishes metrics, security events, and monitoring procedures.

---

## Authentication Metrics

Authentication attempt metrics track credential validation events. The `auth.attempts.total` counter records attempts by result (success, failure), method (password, API key, OAuth, SAML), and tenant. Success rate metrics compute success percentage per method and tenant. Failure rate spikes indicate potential attacks or system issues.

Authentication latency metrics track credential validation time. The `auth.latency` histogram reports validation duration including provider calls. Latency degradation may indicate provider issues or credential database problems. p95 latency exceeding 500ms triggers investigation.

MFA metrics track multi-factor authentication usage. The `auth.mfa.attempts.total` counter records MFA challenges by result and method (TOTP, SMS, email). MFA adoption rates per tenant are tracked for security posture assessment.

---

## Security Event Monitoring

Brute force detection monitors failed authentication patterns. The `auth.failures.ip.rate` metric tracks failures per source IP over time. Rate exceeding 10 failures per minute triggers brute force alerts. Account lockout events are tracked in `auth.lockouts.total`.

Credential stuffing detection identifies automated attacks using stolen credentials. The `auth.credentials.reused.rate` metric tracks attempts using credentials already flagged in breaches. High reuse rates trigger credential stuffing alerts and password reset recommendations.

Suspicious location detection flags authentication from unusual locations. The `auth.locations.anomalous` metric tracks requests from locations inconsistent with user history. Geolocation anomalies trigger risk scoring updates and potential MFA challenges.

---

## Session Monitoring

Session creation metrics track active session volume. The `sessions.created.total` counter records new sessions by authentication method and tenant. Concurrent session metrics in `sessions.active` gauge report current session count per tenant.

Session duration metrics track session lifetime distribution. The `sessions.duration` histogram reports session length percentiles. Short sessions may indicate issues, while excessively long sessions may indicate security concerns.

Session anomaly detection identifies suspicious session patterns. The `sessions.parallel.count` metric tracks concurrent sessions per user. High parallel session counts indicate credential sharing or compromise. Session location changes trigger re-authentication requirements.

---

## API Key Monitoring

API key usage metrics track key-based authentication. The `apikey.requests.total` counter records requests by key ID, key type (primary, secondary), and result. Key activity metrics in `apikey.calls.daily` track usage patterns per key.

Key lifecycle events are logged for audit. Key creation, rotation, and revocation events are tracked. Rotation compliance metrics in `apikey.rotation.overdue` report keys exceeding rotation policy. Overdue keys trigger alerts and potential automatic revocation.

Key anomaly detection identifies unusual usage patterns. The `apikey.usage.anomalous` metric flags requests with unusual patterns (time, volume, endpoints). Anomalous usage triggers key suspension pending user verification.

---

## Authorization Monitoring

Authorization decision metrics track access control checks. The `authz.decisions.total` counter records decisions by result (allow, deny), resource type, and permission. Denial rate spikes indicate permission issues or misconfigurations.

Permission usage metrics track resource access patterns. The `authz.resource.access` histogram reports access frequency per resource and permission. Unusual access patterns trigger security review.

Privilege escalation detection monitors permission changes. The `authz.privileges.escalated` metric tracks elevated permission grants. Escalation events trigger audit logging and may require approval workflows.

---

## Related Documents

- `04-security/authentication`
- `10-observability/incident-debugging`
- `10-observability/logging`