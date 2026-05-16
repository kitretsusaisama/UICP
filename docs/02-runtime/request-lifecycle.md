```yaml
title: Request Lifecycle
domain: execution
owner: platform-runtime
criticality: critical
runtime-impact: cross-component
security-impact: high
queue-impact: high
provider-impact: medium
tenant-impact: high
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on: []
related-docs:
  - state-machines.md
  - runtime-context-propagation.md
  - orchestration-runtime.md
  - delivery-runtime.md
related-queues:
  - ingress-requests
  - async-processing
related-services:
  - api-gateway
  - unified-auth-guard
  - controller-handler
  - execution-coordinator
related-providers:
  - all-configured-providers
related-runtime-states:
  - pending
  - authenticated
  - authorized
  - processing
  - executing
  - completed
  - failed
related-threat-models:
  - request-injection
  - authentication-bypass
  - authorization-escalation
```

# Request Lifecycle

Every request in UICP follows a predictable lifecycle from entry to response. Understanding this flow is critical for debugging, security analysis, and performance optimization.

## Lifecycle Phases

### Phase 1: Ingress (0-5ms)

The request enters through the load balancer performing TLS termination, then reaches the API Gateway built on NestJS. The UnifiedAuthGuard performs initial auth validation, generating correlation IDs and parsing the incoming request.

**Operations**: TLS handshake, request parsing, correlation ID generation, auth method detection.

### Phase 2: Authentication (5-50ms)

The UnifiedAuthGuard extracts credentials from the request, supporting multiple methods. JWT tokens undergo RS256 signature verification with exp/iss/aud validation. API keys are validated for ULID format and HMAC signature correctness. Session tokens are validated against Redis storage. The tenantId is extracted from the credential itself, never from request headers.

**Critical Security Rule**: tenantId NEVER from request header - always derived from authenticated credential.

### Phase 3: Authorization (50-60ms)

With request context established including tenantId, userId, and permissions, the system performs permission checks if the endpoint requires authorization. Tenant isolation is verified to ensure proper boundaries. Rate limit checks execute based on per-API key limits.

### Phase 4: Processing (60-200ms

The controller handler processes the request using the CQRS pattern, dispatching to command or query handlers. Application services execute business logic, invoking domain logic and repository calls as needed.

### Phase 5: External I/O (200-500ms)

For async operations, messages queue via BullMQ and return 202 Accepted immediately. Workers process messages asynchronously, invoking external providers for email, SMS, or other delivery services. Delivery confirmations track completion status.

### Phase 6: Response (500-600ms)

Response construction wraps data in envelope format, adds rate limit headers, and sends the response to the client.

## Trace Spans

| Span | Typical Duration | Description |
|------|------------------|--------------|
| `uicp.request.ingress` | 2-5ms | Request parsing |
| `uicp.request.auth` | 10-45ms | Credential validation |
| `uicp.request.authorize` | 5-15ms | Permission check |
| `uicp.request.process` | 50-150ms | Business logic |
| `uicp.request.io` | 100-400ms | Database/cache/queue |
| `uicp.request.response` | 5-10ms | Response construction |

## Error Handling

| Error Type | HTTP Status | Flow |
|------------|-------------|------|
| Validation Error | 400 | Fast fail |
| Unauthorized | 401 | Auth guard reject |
| Forbidden | 403 | Authorization fail |
| Not Found | 404 | Repository empty |
| Rate Limited | 429 | Rate limit exceed |
| Server Error | 500 | Exception handler |

## Observability

Every request receives a correlation ID enabling parent-child span relationships across all external calls. Metrics track request duration at p50, p95, and p99 percentiles, along with error counts by type and endpoint. Structured JSON logs include tenant IDs with correlation IDs in all log entries.

## Related Documents

- `01-architecture/system-architecture.md`
- `09-queues/queue-overview.md`
- `10-observability/tracing.md`