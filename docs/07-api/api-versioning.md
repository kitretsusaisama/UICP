# API Versioning

## Metadata
```yaml
title: API Versioning
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
  - openapi-links.md
related-queues: []
related-services: []
```

---

## Overview

The API uses URL-based versioning. The version is embedded in the path (e.g., `/api/v1/...`). This approach ensures stable client integrations while allowing backward-incompatible changes in new versions.

---

## Version Format

```
/api/v{major}/...
```

- **Major version** (v1, v2): Breaking changes
- **Minor version** (implied): Backward-compatible additions

---

## Supported Versions

| Version | Status | Release Date | Sunset Date |
|---------|--------|--------------|-------------|
| v1 | Active | 2025-01-01 | - |
| v2 | Beta | 2026-04-01 | - |
| v0 | Deprecated | 2024-06-01 | 2025-12-31 |

---

## Version Negotiation

### Via URL Path (Recommended)

```
GET /api/v1/users
GET /api/v2/users
```

### Via Accept Header

```
Accept: application/vnd.uicp.v1+json
Accept: application/vnd.uicp.v2+json
```

---

## Deprecation Policy

### Timeline

1. **Announcement**: Deprecation warning in response headers
2. **Grace Period**: 6 months from announcement
3. **Sunset**: Version no longer served
4. **Removal**: Version removed from documentation

### Deprecation Headers

```
Deprecation: true
Sunset: Sat, 01 Jun 2025 00:00:00 GMT
Link: <https://api.example.com/docs/v2>; rel="successor-version"
```

### Example Response (Deprecated)

```json
{
  "data": {...},
  "warning": {
    "code": "DEPRECATED_VERSION",
    "message": "v1 is deprecated. Please migrate to v2.",
    "sunsetDate": "2025-06-01T00:00:00Z"
  }
}
```

---

## Version Differences

### v1 to v2 Breaking Changes

| Change | v1 | v2 |
|--------|----|----|
| Pagination | offset/limit | cursor |
| Date Format | Unix timestamp | ISO8601 |
| User Response | flat object | nested object |
| Error Format | code/message | code/message/details |

### Migration Guide

See [v2 Migration Guide](./migration-v1-to-v2.md) for detailed instructions.

---

## Choosing a Version

### Use v1 If:
- Existing production integration
- Stability is priority
- No need for new features

### Use v2 If:
- Building new integrations
- Need improved performance
- Want latest features

---

## Version Lifecycle

1. **Beta**: Open to all, may have bugs
2. **GA (General Availability)**: Stable, fully supported
3. **Deprecated**: Still works, no new features
4. **Sunset**: Returns 410 Gone
5. **Removed**: No longer exists

---

## Best Practices

1. **Pin versions** in production integrations
2. **Test new versions** before upgrading
3. **Monitor deprecation warnings** in responses
4. **Plan migration** early in deprecation window
5. **Use latest stable** for new projects

---

## Version Header Response

All responses include version information:

```
X-API-Version: v1
X-API-Version-Status: deprecated
X-API-Version-Sunset: 2025-06-01T00:00:00Z
```

---

## Documentation

- [OpenAPI Specification](./openapi-links.md)
- [Changelog](./changelog.md)
- [Migration Guide](./migration-v1-to-v2.md)
- [Deprecation Schedule](./deprecation.md)