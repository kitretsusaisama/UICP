# OpenAPI Specification Links

## Metadata
```yaml
title: OpenAPI Links
domain: api
owner: platform-team
criticality: HIGH
runtime-impact: low
security-impact: none
queue-impact: none
provider-impact: none
tenant-impact: isolated
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - api-versioning.md
related-docs:
  - api-versioning.md
  - authentication.md
related-queues: []
related-services: []
```

---

## Overview

This document provides links to the OpenAPI (Swagger) specifications for all API versions. The OpenAPI specs provide machine-readable documentation including endpoints, schemas, and example requests/responses.

---

## OpenAPI Specifications

### v1 (Stable)

| Format | URL |
|--------|-----|
| JSON | `/api/v1/openapi.json` |
| YAML | `/api/v1/openapi.yaml` |
| Swagger UI | `/api/v1/docs` |

### v2 (Beta)

| Format | URL |
|--------|-----|
| JSON | `/api/v2/openapi.json` |
| YAML | `/api/v2/openapi.yaml` |
| Swagger UI | `/api/v2/docs` |

---

## Download Instructions

### Using curl

```bash
# Download JSON spec
curl -o openapi-v1.json https://api.example.com/api/v1/openapi.json

# Download YAML spec
curl -o openapi-v1.yaml https://api.example.com/api/v1/openapi.yaml
```

### Using wget

```bash
wget https://api.example.com/api/v1/openapi.json
```

---

## Schema References

Each endpoint references reusable schemas. Key schemas:

### Authentication

- [AuthRequest](./schemas/auth-request.json)
- [AuthResponse](./schemas/auth-response.json)
- [ApiKey](./schemas/api-key.json)

### Users

- [User](./schemas/user.json)
- [UserCreateRequest](./schemas/user-create-request.json)
- [UserUpdateRequest](./schemas/user-update-request.json)
- [UserListResponse](./schemas/user-list-response.json)

### Organizations

- [Organization](./schemas/organization.json)
- [OrganizationCreateRequest](./schemas/organization-create-request.json)

### Communications

- [EmailRequest](./schemas/email-request.json)
- [SmsRequest](./schemas/sms-request.json)
- [MessageResponse](./schemas/message-response.json)

### Errors

- [ErrorResponse](./schemas/error-response.json)
- [ValidationError](./schemas/validation-error.json)

---

## Code Generation

The OpenAPI specs support code generation for multiple languages:

### TypeScript

```bash
npm install -g openapi-generator-cli
openapi-generator-cli generate -i openapi.json -g typescript-axios -o ./src/api
```

### Python

```bash
openapi-generator-cli generate -i openapi.json -g python -o ./client
```

### Go

```bash
openapi-generator-cli generate -i openapi.json -g go -o ./client
```

### Additional Languages

| Language | Generator |
|----------|-----------|
| Java | java |
| C# | csharp |
| Ruby | ruby |
| PHP | php |
| Swift | swift5 |
| Kotlin | kotlin |

---

## Postman Collection

Download Postman collection with all endpoints:

- [v1 Collection](./postman/uicp-v1.postman-collection.json)
- [v2 Collection](./postman/uicp-v2.postman-collection.json)

### Import to Postman

1. Open Postman
2. Click Import
3. Select the JSON file
4. Set environment variables (baseUrl, apiKey)

---

## Interactive Documentation

### Swagger UI

Access interactive API documentation at:

- v1: `https://api.example.com/api/v1/docs`
- v2: `https://api.example.com/api/v2/docs`

### ReDoc

Alternative documentation format:

- v1: `https://api.example.com/api/v1/redoc`
- v2: `https://api.example.com/api/v2/redoc`

---

## Version Sync

The OpenAPI spec is automatically generated from the API codebase. Any changes to endpoints or schemas are reflected within 5 minutes.

Last sync: 2026-05-16T10:00:00Z

---

## SDK Repositories

Official client SDKs are available:

| Language | Repository |
|----------|------------|
| TypeScript | github.com/uicp/sdk-typescript |
| Python | github.com/uicp/sdk-python |
| Go | github.com/uicp/sdk-go |
| Java | github.com/uicp/sdk-java |

---

## Additional Resources

- [API Changelog](./changelog.md)
- [API Versioning](./api-versioning.md)
- [Authentication Guide](./authentication.md)
- [Error Reference](./errors.md)
- [Rate Limits](./rate-limits.md)

---

## Support

- **Documentation Issues**: docs@example.com
- **API Support**: support@example.com
- **SDK Issues**: Visit respective repository issues page