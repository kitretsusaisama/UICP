# Template Runtime

## Metadata
```yaml
title: Template Runtime
domain: communication
owner: Platform Team
criticality: MEDIUM
runtime-impact: MEDIUM
security-impact: MEDIUM
queue-impact: LOW
provider-impact: LOW
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - communication-overview.md
related-docs:
  - provider-runtime.md
  - resend-runtime.md
related-queues:
  - template-compilation
related-services:
  - TemplateEngine
  - TemplateStore
  - VariableResolver
related-providers:
  - SES
  - Resend
  - Maileroo
related-runtime-states:
  - template_loaded
  - template_rendering
  - template_rendered
  - template_error
related-threat-models:
  - Template injection
  - Variable injection
```

---

## Overview

Template Runtime provides a unified templating system for email and SMS messages. It supports variable substitution, conditional content, loops, and custom helpers while maintaining compatibility across all providers.

---

## Template Format

### Supported Syntax

```handlebars
Subject: {{subject}}

Dear {{user.name}},

{{#if hasOrder}}
Your order #{{order.id}} has been shipped!

{{#each order.items}}
- {{this.name}} (x{{this.quantity}})
{{/each}}

Tracking: {{order.trackingUrl}}
{{else}}
Thank you for your recent purchase. Browse our new arrivals!
{{/if}}

Best regards,
{{company.name}}
```

---

## Variable Resolution

### Context Structure

```typescript
interface TemplateContext {
  // Standard variables
  user: {
    id: string;
    name: string;
    email: string;
    locale: string;
  };
  // Custom variables from payload
  [key: string]: any;
  // Built-in helpers
  now: Date;
  uuid: string;
}
```

### Variable Types

| Type | Syntax | Example |
|------|--------|---------|
| String | {{var}} | {{user.name}} |
| Number | {{var}} | {{order.total}} |
| Boolean | {{#if var}} | {{#if user.premium}} |
| Array | {{#each var}} | {{#each items}} |
| Object | {{var.prop}} | {{order.shipping.address}} |

---

## Built-in Helpers

### Conditionals

```handlebars
{{#if user.premium}}
  Premium content here
{{else if user.trial}}
  Trial period: {{daysLeft}} days left
{{else}}
  Upgrade to premium
{{/if}}
```

### Formatting

```handlebars
{{formatDate order.createdAt "MMMM DD, YYYY"}}
{{currency order.total "USD"}}
{{uppercase company.name}}
```

### Localization

```handlebars
{{t "greeting" locale=user.locale}}
{{i18n "order_confirmation" params}}
```

---

## Security

### Sandboxing

Templates run in isolated contexts:
- No access to global scope
- No function constructors
- No prototype chain access
- Variable access logged

### Injection Prevention

```typescript
function sanitizeVariable(value: any): string {
  if (typeof value === 'string') {
    // Remove potential script injection
    return value.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  }
  return String(value);
}
```

---

## Caching

### Cache Strategy

| Template Type | Cache TTL | Invalidation |
|---------------|-----------|--------------|
| System | 1 hour | Version bump |
| Tenant | 30 minutes | Update |
| Dynamic | 5 minutes | Manual |

### Cache Key

```
template:{tenantId}:{templateId}:{version}
```

---

## Provider-Specific Rendering

### Email to HTML

```typescript
function renderEmailTemplate(template: string, context: TemplateContext): EmailContent {
  const rendered = engine.render(template, context);

  return {
    html: sanitizeHtml(rendered.html),
    text: rendered.plainText,
    subject: rendered.subject,
    headers: rendered.headers
  };
}
```

### SMS Text

```typescript
function renderSMSTemplate(template: string, context: TemplateContext): SMSContent {
  const rendered = engine.render(template, context);

  // Truncate if needed
  const message = truncate(rendered.text, 160);

  return {
    message,
    encoding: detectEncoding(message)
  };
}
```

---

## Observability

### Metrics

| Metric | Description |
|--------|-------------|
| template_render_total | Total renders |
| template_render_duration | Render time |
| template_cache_hit | Cache effectiveness |
| template_error_total | Render failures |

---

## Related Documents

- `04-communication/communication-overview.md`
- `04-communication/provider-runtime.md`
- `04-communication/communication-security.md`