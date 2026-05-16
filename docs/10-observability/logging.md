# Observability - Logging

## Metadata
```yaml
title: Observability - Logging
domain: observability
owner: Platform Engineering
criticality: HIGH
runtime-impact: LOW
security-impact: HIGH
queue-impact: LOW
provider-impact: LOW
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - 10-observability/tracing
  - 10-observability/metrics
related-docs:
  - 10-observability/incident-debugging
  - 10-observability/telemetry-pipelines
related-queues: []
related-services:
  - elasticsearch
  - fluentd
  - kibana
```

---

## Overview

Logging provides detailed event records for debugging, audit compliance, and security monitoring. This document establishes logging standards for UICP, including structured logging formats, log levels, retention policies, and sensitive data handling requirements.

---

## Log Format

All UICP services emit structured JSON logs conforming to the Logstash JSON format. Each log entry includes a timestamp, severity level, service name, trace context, message, and contextual fields. The timestamp uses ISO 8601 format with millisecond precision and UTC timezone.

```json
{
  "timestamp": "2026-05-16T10:30:00.123Z",
  "level": "INFO",
  "service": "uicp-auth-service",
  "traceId": "req-abc123def456",
  "spanId": "span-789xyz",
  "message": "Authentication successful",
  "tenantId": "tenant-001",
  "userId": "user-12345",
  "authMethod": "api_key",
  "durationMs": 45
}
```

---

## Log Levels

The platform uses four log levels with specific triggers. ERROR level captures exceptions, validation failures, and security events requiring immediate attention. WARN level records degraded performance, retry attempts, and configuration warnings. INFO level documents normal operational events including authentication attempts, token issuance, and configuration changes. DEBUG level provides detailed flow tracing for development and troubleshooting.

---

## Security Logging

Security-relevant events require enhanced logging with comprehensive context. Authentication events log the attempt, result, credential type, source IP, and tenant. Authorization events log the permission check, resource, action, and result. API key operations log key creation, rotation, revocation, and usage.

Audit logging captures all data access and modification events. User profile changes log the user, field modified, old value (redacted), and new value. Role assignments log the user, role, grantor, and timestamp. Tenant configuration changes log the tenant, setting modified, and actor. These logs support compliance requirements and forensic analysis.

---

## Sensitive Data Handling

Logs must not contain sensitive data in plaintext. Passwords, API keys, and tokens are replaced with placeholder values before logging. Email addresses are partially masked (first character and domain only). Phone numbers are replaced with hash identifiers.

PII logging requires explicit configuration per data type. When PII logging is enabled, it must comply with tenant data residency requirements. Logs containing PII are marked with `containsPii: true` and are subject to enhanced retention controls and access restrictions.

---

## Log Retention

Log retention follows a tiered policy based on log criticality. Security logs are retained for 365 days to support compliance and incident investigation. Application logs are retained for 90 days for debugging and performance analysis. Debug logs are retained for 7 days and only in non-production environments.

---

## Related Documents

- `10-observability/tracing`
- `10-observability/incident-debugging`
- `10-observability/telemetry-pipelines`