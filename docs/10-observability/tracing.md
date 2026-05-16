# Observability - Tracing

## Metadata
```yaml
title: Observability - Tracing
domain: observability
criticality: HIGH
ai-ingestable: true
```

---

## Trace Context

Every request receives a correlation ID that propagates through all services.

### Trace Flow

```
Request → API Gateway (generate traceId)
   ↓
UnifiedAuthGuard (add span)
   ↓
Controller (add span)
   ↓
Service (add span)
   ↓
Repository (add span)
   ↓
Response
```

---

## Key Traces

| Trace Name | Description | Typical Duration |
|------------|-------------|------------------|
| `uicp.request` | Full request lifecycle | 50-500ms |
| `uicp.auth.attempt` | Authentication flow | 20-100ms |
| `uicp.provider.send` | Provider API call | 100-500ms |
| `uicp.queue.process` | Queue message processing | 200-1000ms |

---

## Attributes

### Required Attributes
- `tenant.id` - Tenant identifier
- `user.id` - User identifier (if authenticated)
- `request.method` - HTTP method
- `request.path` - Request path

### Optional Attributes
- `api.key.id` - API key identifier
- `session.id` - Session identifier
- `correlation.id` - Request correlation ID

---

## Related Documents

- `10-observability/metrics.md`
- `10-observability/logging.md`

