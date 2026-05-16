# Contract Tests

## Metadata
```yaml
title: Contract Tests
domain: api-contract
owner: API Team
criticality: HIGH
runtime-impact: LOW
security-impact: MEDIUM
queue-impact: NONE
provider-impact: NONE
tenant-impact: HIGH
ai-ingestable: true
review-cycle: per-release
last-reviewed: 2026-05-16
depends-on:
  - src/interfaces/rest/v1/api.schema.ts
  - src/interfaces/graphql/schema.gql
  - src/application/ports/driver/i-provider-api.port.ts
related-docs:
  - docs/02-architecture/api-design.md
  - docs/08-api/api-contract.md
related-queues: NONE
related-services:
  - RESTAPIController
  - GraphQLResolver
  - ProviderAPIClient
```

---

## Overview

Contract tests ensure that APIs adhere to their defined specifications and that changes to contracts don't break existing consumers. These tests validate request/response schemas, HTTP status codes, and error formats.

---

## Test Coverage

### REST API Contracts

| Endpoint | Contract Version | Test Scope |
|----------|------------------|------------|
| POST /auth/login | v1.0 | Request/response validation |
| GET /api/v1/providers | v1.0 | Query params, pagination |
| POST /api/v1/providers | v1.0 | Request body schema |
| PUT /api/v1/providers/:id | v1.0 | Path params, response |
| DELETE /api/v1/providers/:id | v1.0 | 204 No Content |

### Schema Validation

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Valid request | Send request matching schema | Request accepted, 200 returned |
| Missing required field | Omit required field | 400 Bad Request with field error |
| Invalid type | Send string for number field | 400 Bad Request with type error |
| Additional properties | Send extra field | 400 Bad Request |
| Enum validation | Send invalid enum value | 400 Bad Request with allowed values |

### Error Contract

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Not found error | GET non-existent resource | 404 with error code |
| Validation error | POST invalid data | 422 with details |
| Rate limit error | Exceed rate limit | 429 with retry-after header |
| Auth error | Missing token | 401 with WWW-Authenticate |

### Consumer-Driven Contracts

| Consumer | Contract Requirement | Validation |
|----------|---------------------|------------|
| Web Dashboard | /api/v1/providers returns id, name, status | Contract test passes |
| Mobile App | POST /api/v1/providers returns created provider | Contract test passes |
| Admin CLI | DELETE returns 204 with empty body | Contract test passes |

---

## Test Implementation

```typescript
import { validate } from 'contract-validator';

describe('Contract Tests', () => {
  describe('Provider API Contract', () => {
    it('should return valid provider response schema', async () => {
      const response = await request(app).get('/api/v1/providers');

      const validation = validate(response.body, providerSchema);
      expect(validation.valid).toBe(true);
    });

    it('should reject request with missing required fields', async () => {
      const response = await request(app)
        .post('/api/v1/providers')
        .send({ name: 'test' }); // Missing type, region

      expect(response.status).toBe(400);
      expect(response.body.errors).toContainEqual(
        expect.objectContaining({ field: 'type', reason: 'required' })
      );
    });

    it('should follow error contract', async () => {
      const response = await request(app).get('/api/v1/providers/non-existent');

      expect(response.status).toBe(404);
      expect(response.body).toMatchObject({
        error: { code: 'NOT_FOUND', message: expect.any(String) }
      });
    });
  });
});
```

---

## Contract Versioning

- All contracts versioned in URL: /api/v1/
- Breaking changes require new version: /api/v2/
- Deprecated versions supported for 12 months
- Contract changes require consumer notification

---

## Validation Tools

- OpenAPI schema validation
- Consumer-driven contract testing with Pact
- JSON Schema validators
- GraphQL schema validation