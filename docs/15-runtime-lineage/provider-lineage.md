# Provider Lineage

## Metadata
```yaml
title: Provider Lineage
domain: routing
owner: Infrastructure Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: CRITICAL
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - provider-router
  - provider-routing-repository
  - kms-service
related-docs:
  - 11-routing/provider-routing.md
  - 15-runtime-lineage/queue-lineage.md
  - 15-runtime-lineage/delivery-lineage.md
related-queues:
  - provider-routing
  - email-outbound
  - sms-outbound
related-services:
  - provider-router
  - kms-service
  - api-gateway
related-providers:
  - sendgrid
  - twilio
  - aws-sns
  - mailgun
```

---

## Overview

Provider lineage tracks routing decisions from request receipt through provider selection and API invocation. This lineage enables provider performance analysis, cost optimization, and incident attribution when provider failures occur.

---

## Provider Selection Flow

### Initial Routing Decision

```
Message Received (Validated)
    ↓
Message Type Detection (Email/SMS/Push/Voice)
    ↓
Tenant Provider Config Lookup
    ↓
Provider Capability Matching
    ↓
Health Check Query
    ↓
Cost Optimization Layer
    ↓
Final Provider Selection
    ↓
Credentials Retrieval (KMS)
    ↓
API Request Construction
```

### Multi-Provider Fallback Lineage

```
Primary Provider Selected
    ↓
Provider API Call Attempt
    ↓
Failure Detection
    ↓
Fallback Eligibility Check
    ↓
Next Provider Selection
    ↓
Credentials Rotation
    ↓
Retry with Alternate Provider
    ↓
Success or Final Failure
```

---

## Provider Configuration Lineage

### Routing Rules Storage

```
Configuration Change Request
    ↓
Validation (Schema/Permissions)
    ↓
Routing Rules Update (Database)
    ↓
Cache Invalidation
    ↓
Configuration Propagation
    ↓
Active Routing Applied
    ↓
Audit Log Entry
```

### Credential Management

```
Provider Credential Creation
    ↓
KMS Encryption
    ↓
Secure Storage (Encrypted at Rest)
    ↓
Credential Reference Created (Non-sensitive ID)
    ↓
Runtime Decryption (On-demand)
    ↓
API Request Signing
    ↓
Credential Rotation Schedule Set
```

---

## Trace Correlation

Each provider interaction captures:
- **providerId**: Selected provider identifier
- **providerEndpoint**: Actual API endpoint called
- **credentialsUsed**: Credential reference (not secrets)
- **routingReason**: Selection logic applied
- **healthCheckResult**: Provider availability at selection time
- **costTier**: Provider pricing classification
- **attemptLatency**: Time to provider response
- **providerResponseCode**: API status returned

---

## Provider Health Integration

Provider lineage maintains real-time health state:

1. **Active Health Monitoring**: Periodic provider API checks
2. **Failure Detection**: Automatic provider marking as unhealthy
3. **Automatic Removal**: Unhealthy providers excluded from routing
4. **Recovery Tracking**: Health restoration monitoring
5. **Degraded Mode**: Reduced capacity provider handling

---

## Cost Optimization

Provider lineage supports cost analysis:
- Per-provider message volume tracking
- Cost per message by provider tier
- Traffic shift recommendations during capacity events
- Provider rate limit utilization monitoring

---

## Incident Attribution

During provider outages:
1. Identify all messages affected by provider failure
2. Determine retry success rate
3. Calculate customer impact (SLA breach assessment)
4. Document failure timeline for post-mortem

---

## Related Documents

- `15-runtime-lineage/queue-lineage.md` - Queue processing
- `15-runtime-lineage/delivery-lineage.md` - Delivery confirmation
- `15-runtime-lineage/retry-lineage.md` - Retry handling
- `11-routing/provider-routing.md` - Routing architecture