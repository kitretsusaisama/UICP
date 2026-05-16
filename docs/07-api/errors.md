# API Errors

## Metadata
```yaml
title: API Error Handling
domain: api
owner: platform-team
criticality: HIGH
runtime-impact: low
security-impact: MEDIUM
queue-impact: none
provider-impact: none
tenant-impact: isolated
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on: []
related-docs:
  - rate-limits.md
  - idempotency.md
related-queues: []
related-services: []
```

---

## Overview

All API errors follow a consistent JSON structure. Errors are categorized by domain and HTTP status code. Client errors (4xx) should be handled by the caller; server errors (5xx) should be retried with exponential backoff.

---

## Error Response Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": [
      {
        "field": "email",
        "message": "Invalid email format"
      }
    ],
    "traceId": "ulid-string",
    "timestamp": "2026-05-16T10:00:00Z"
  }
}
```

---

## HTTP Status Codes

| Status | Meaning |
|--------|---------|
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Invalid/missing credentials |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource does not exist |
| 409 | Conflict - Resource already exists |
| 422 | Unprocessable Entity - Business logic error |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error |
| 502 | Bad Gateway - Upstream error |
| 503 | Service Unavailable |
| 504 | Gateway Timeout |

---

## Error Codes

### Authentication Errors

| Code | Description |
|------|-------------|
| AUTH_INVALID_TOKEN | Token is invalid or expired |
| AUTH_MISSING_TOKEN | Authentication token not provided |
| AUTH_INSUFFICIENT_PERMISSIONS | User lacks required permissions |
| API_KEY_INVALID | API key is invalid or revoked |
| API_KEY_EXPIRED | API key has expired |

### Validation Errors

| Code | Description |
|------|-------------|
| VALIDATION_ERROR | General validation failure |
| INVALID_PARAMETER | Parameter value is invalid |
| MISSING_PARAMETER | Required parameter is missing |
| PARAMETER_TOO_LONG | Parameter exceeds maximum length |
| INVALID_FORMAT | Data format is incorrect |

### Resource Errors

| Code | Description |
|------|-------------|
| RESOURCE_NOT_FOUND | Requested resource does not exist |
| RESOURCE_ALREADY_EXISTS | Resource with same identifier exists |
| RESOURCE_CONFLICT | Resource state conflicts with request |
| RESOURCE_DELETED | Resource has been deleted |

### Rate Limit Errors

| Code | Description |
|------|-------------|
| RATE_LIMIT_EXCEEDED | Too many requests |
| QUOTA_EXCEEDED | Resource quota exceeded |

### Server Errors

| Code | Description |
|------|-------------|
| INTERNAL_ERROR | Unexpected internal error |
| SERVICE_UNAVAILABLE | Service is temporarily unavailable |
| DATABASE_ERROR | Database operation failed |
| EXTERNAL_SERVICE_ERROR | Upstream service failed |

---

## Error Details

Each error may include a `details` array with field-specific information:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed for user creation",
    "details": [
      {
        "field": "password",
        "message": "Password must be at least 8 characters"
      },
      {
        "field": "email",
        "message": "Email already exists"
      }
    ]
  }
}
```

---

## Trace ID

All errors include a `traceId` for correlation. Include this ID when contacting support:

```json
{
  "error": {
    "code": "INTERNAL_ERROR",
    "message": "An unexpected error occurred",
    "traceId": "01ARZ3NDEKTSV4RRFFQ69G5RVY"
  }
}
```

---

## Client Error Handling

| Status | Retry | Action |
|--------|-------|--------|
| 400 | No | Fix request payload |
| 401 | No | Re-authenticate |
| 403 | No | Check permissions |
| 404 | No | Resource does not exist |
| 409 | No | Handle conflict |
| 422 | No | Fix business logic |
| 429 | Yes | Respect rate limits |
| 500 | Yes | Exponential backoff |
| 502 | Yes | Exponential backoff |
| 503 | Yes | Exponential backoff |
| 504 | Yes | Exponential backoff |

---

## Example Errors

### 400 Bad Request

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": [
      {
        "field": "email",
        "message": "Invalid email format"
      }
    ],
    "traceId": "01ARZ3NDEKTSV4RRFFQ69G5RVY",
    "timestamp": "2026-05-16T10:00:00Z"
  }
}
```

### 401 Unauthorized

```json
{
  "error": {
    "code": "AUTH_INVALID_TOKEN",
    "message": "The provided authentication token has expired",
    "traceId": "01ARZ3NDEKTSV4RRFFQ69G5RVY",
    "timestamp": "2026-05-16T10:00:00Z"
  }
}
```

### 429 Too Many Requests

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Please retry after 60 seconds",
    "retryAfter": 60,
    "traceId": "01ARZ3NDEKTSV4RRFFQ69G5RVY",
    "timestamp": "2026-05-16T10:00:00Z"
  }
}
```