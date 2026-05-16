# Edge Cases

## Metadata
```yaml
title: Edge Cases
domain: testing
owner: QA Team
criticality: MEDIUM
runtime-impact: MEDIUM
security-impact: MEDIUM
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: per-release
last-reviewed: 2026-05-16
depends-on:
  - src/application/services/api-gateway.service.ts
  - src/infrastructure/validation/input-validator.ts
  - src/domain/exceptions/domain.exception.ts
related-docs:
  - docs/02-architecture/error-handling.md
  - docs/07-security/input-validation.md
related-queues:
  - edge-case-queue
  - boundary-testing
related-services:
  - InputValidator
  - ErrorHandler
  - BoundaryChecker
```

---

## Overview

Edge case tests validate behavior at boundaries and with unusual inputs. These tests ensure the system handles unexpected scenarios gracefully without crashes or security vulnerabilities.

---

## Test Coverage

### Input Validation Edge Cases

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Maximum string length | Send 10,000 character string | Rejected with 400 |
| Empty string | Send empty field | Rejected with validation error |
| Unicode characters | Send emoji/chinese characters | Processed correctly |
| Null value | Send null for optional field | Accepted |
| Leading/trailing spaces | Send " test " | Trimmed or rejected |

### Numeric Boundaries

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Maximum integer | Send 2^53 - 1 | Processed correctly |
| Negative number | Send -1 for positive field | Rejected with 422 |
| Zero value | Send 0 for required positive | Rejected |
| Scientific notation | Send 1e10 | Parsed correctly |
| Precision loss | Send 1.123456789 | Maintains precision |

### Time-Based Edge Cases

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Future timestamp | Create with date + 100 years | Accepted or rejected based on policy |
| Past timestamp | Create with date in 1900 | Accepted |
| Timezone handling | Send UTC+14 timestamp | Converted correctly |
| Leap second | Send timestamp during leap second | Handled gracefully |
| DST transition | Send timestamp during DST change | Consistent behavior |

### Concurrency Edge Cases

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Race condition | 100 concurrent updates to same record | Only one succeeds or all merged |
| Lock timeout | Hold lock for 30+ seconds | Timeout error returned |
| Deadlock detection | Two transactions waiting on each other | One rolled back |
| Memory pressure | 1,000 concurrent requests | Requests queued or rejected |

### Malformed Data

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Truncated JSON | Send partial JSON | 400 Bad Request |
| Invalid JSON | Send non-JSON as JSON | 400 Bad Request |
| Large payload | Send 10MB JSON | 413 Payload Too Large |
| Binary in JSON | Send base64 in string field | Accepted if allowed |

### State Transitions

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Double deletion | Delete already deleted item | 404 or idempotent success |
| Invalid state transition | Update deleted provider | 400 Bad Request |
| Concurrent state change | Two requests change same resource | One wins, other fails |

---

## Test Implementation

```typescript
describe('Edge Cases', () => {
  describe('Input Boundaries', () => {
    it('should handle maximum string length', async () => {
      const longString = 'a'.repeat(10000);

      const response = await request(app)
        .post('/api/v1/providers')
        .send({ name: longString });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('MAX_LENGTH_EXCEEDED');
    });

    it('should handle unicode characters', async () => {
      const unicode = '_provider_αβγδ_测试_🎉';

      const response = await request(app)
        .post('/api/v1/providers')
        .send({ name: unicode });

      expect(response.status).toBe(200);
      expect(response.body.name).toBe(unicode);
    });
  });

  describe('Numeric Boundaries', () => {
    it('should handle maximum integer', async () => {
      const maxInt = Number.MAX_SAFE_INTEGER;

      const response = await request(app)
        .post('/api/v1/counters')
        .send({ value: maxInt });

      expect(response.status).toBe(200);
      expect(response.body.value).toBe(maxInt);
    });

    it('should reject negative for positive-only field', async () => {
      const response = await request(app)
        .post('/api/v1/providers')
        .send({ priority: -1 });

      expect(response.status).toBe(422);
    });
  });

  describe('Concurrency', () => {
    it('should handle race condition gracefully', async () => {
      const updates = Array(100).fill(null).map(() =>
        request(app).put('/api/v1/providers/prov-1')
          .send({ status: 'active' })
      );

      const results = await Promise.allSettled(updates);
      const succeeded = results.filter(r => r.status === 'fulfilled');

      expect(succeeded.length).toBe(100); // All succeed or properly merged
    });
  });

  describe('State Transitions', () => {
    it('should handle double deletion idempotently', async () => {
      await request(app).delete('/api/v1/providers/prov-1');

      const secondDelete = await request(app)
        .delete('/api/v1/providers/prov-1');

      expect(secondDelete.status).toBe(200); // Idempotent
    });
  });
});
```

---

## Validation Checklist

- No crashes on any edge case input
- Proper error messages for all rejections
- Security: no injection vulnerabilities
- Performance: no degradation on boundary inputs
- Logging: all edge cases logged appropriately

---

## Common Edge Case Categories

- Empty/minimal values
- Maximum allowed sizes
- Invalid types
- Race conditions
- Time boundary conditions
- Network edge cases (timeout, disconnection)
- Third-party service failures