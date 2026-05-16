# UICP Provider Model Summary

## Metadata

```yaml
title: UICP Provider Model Summary
domain: architecture
owner: Platform Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - architecture-summary.md
  - platform-philosophy.md
  - queue-first-philosophy.md
related-docs:
  - trust-model-summary.md
  - operational-thinking.md
related-queues:
  - email-delivery
  - sms-delivery
  - otp-fastlane
  - webhook-processing
related-services:
  - communication-service
  - api-key-service
related-providers:
  - twilio
  - sendgrid
  - aws-ses
  - postmark
  - vonage
  - sns
related-runtime-states:
  - running
  - degraded
related-threat-models:
  - provider-outage
  - provider-data-breach
```

---

## Provider Abstraction Layer

UICP abstracts external providers through a consistent interface layer. This enables:

- **Provider Hot-Swapping** — Change providers without deployment
- **Smart Routing** — Select provider based on rules
- **Cost Optimization** — Route to cheapest viable option
- **Compliance Flexibility** — Switch providers for regulatory needs
- **Resilience** — Automatic failover on provider failure

---

## Provider Interface

Each provider type implements a standardized interface:

```typescript
// Email Provider Interface
interface IEmailProvider {
  send(dto: SendEmailDTO): Promise<SendResult>;
  getStatus(messageId: string): Promise<DeliveryStatus>;
  healthCheck(): Promise<ProviderHealth>;
  getCapabilities(): ProviderCapabilities;
}

// SMS Provider Interface
interface ISmsProvider {
  send(dto: SendSmsDTO): Promise<SendResult>;
  getStatus(messageId: string): Promise<DeliveryStatus>;
  healthCheck(): Promise<ProviderHealth>;
  getCapabilities(): ProviderCapabilities;
}
```

---

## Supported Providers

### Email Providers

| Provider | Status | Capabilities | Regions |
|----------|--------|--------------|---------|
| SendGrid | Active | Bulk, Templates, Tracking | Global |
| AWS SES | Active | Dedicated IP, Compliance | AWS Regions |
| Postmark | Active | Deliverability, Templates | Global |
| Mailgun | Available | Developer-friendly | Global |

### SMS Providers

| Provider | Status | Capabilities | Coverage |
|----------|--------|--------------|----------|
| Twilio | Active | Voice, WhatsApp, Verify | Global |
| AWS SNS | Active | Bulk, P2P | AWS Regions |
| Vonage | Active | Number masking | Global |

---

## Provider Routing

The ProviderRouter selects the optimal provider based on:

```typescript
interface RoutingRule {
  name: string;
  priority: number;
  condition: RoutingCondition;
  provider: string;
}

// Example: Prioritize SendGrid for transactional emails
const transactionalRule: RoutingRule = {
  name: 'transactional-email',
  priority: 10,
  condition: {
    type: 'email_type',
    equals: 'transactional',
  },
  provider: 'sendgrid',
};

// Example: Fallback to SES if SendGrid fails
const fallbackRule: RoutingRule = {
  name: 'ses-fallback',
  priority: 100,
  condition: {
    type: 'previous_failure',
    provider: 'sendgrid',
  },
  provider: 'aws-ses',
};
```

### Routing Strategies

1. **Priority-Based** — Fixed provider order
2. **Cost-Based** — Cheapest provider meeting SLA
3. **Latency-Based** — Fastest provider per region
4. **Availability-Based** — Only healthy providers
5. **Tenant-Preferred** — Tenant-specific provider settings

---

## Failover Configuration

Provider failover is automatic and configured per provider type:

```typescript
const providerConfig: ProviderChainConfig = {
  email: {
    primary: 'sendgrid',
    failover: ['aws-ses', 'postmark'],
    healthCheckInterval: 30000,
    failoverThreshold: 3,
  },
  sms: {
    primary: 'twilio',
    failover: ['sns', 'vonage'],
    healthCheckInterval: 30000,
    failoverThreshold: 2,
  },
};
```

### Failover Trigger Conditions
- Provider returns 5xx error
- Provider timeout exceeds 30s
- Health check fails 3 consecutive times

---

## Provider Health Monitoring

Each provider has a health score calculated from:

| Metric | Weight |
|--------|--------|
| Success Rate | 40% |
| Latency (p99) | 30% |
| Error Rate | 20% |
| Health Check | 10% |

```typescript
interface ProviderHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  score: number;
  lastCheck: Date;
  issues: string[];
}
```

---

## Tenant-Level Provider Selection

Tenants can configure preferred providers:

```typescript
interface TenantProviderConfig {
  tenantId: string;
  email: {
    preferredProvider: string;
    fallbackEnabled: boolean;
  };
  sms: {
    preferredProvider: string;
    fallbackEnabled: boolean;
  };
}
```

---

## Cost Management

Provider costs are tracked per tenant:

| Provider | Per-Unit Cost | Volume Discount |
|----------|---------------|-----------------|
| SendGrid | $0.001/email | 10K+ emails: 20% off |
| AWS SES | $0.0001/email | 100K+ emails: 30% off |
| Twilio | $0.0075/SMS | 50K+ SMS: 15% off |

---

## Security Considerations

- **API Key Rotation** — All provider credentials rotated quarterly
- **IP Whitelisting** — Restrict provider access to UICP IPs only
- **Encryption in Transit** — TLS 1.3 for all provider communication
- **Audit Logging** — All provider API calls logged for compliance

---

*Last Updated: 2026-05-16 | AI-Ingestible: true*