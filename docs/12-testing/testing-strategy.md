# Testing Strategy

## Metadata
```yaml
title: Testing Strategy
domain: testing
criticality: HIGH
ai-ingestable: true
```

---

## Overview

UICP employs multiple testing layers for reliability and security.

---

## Test Types

| Type | Coverage | Run Time |
|------|----------|----------|
| Unit | 80% | < 5 min |
| Integration | 60% | 5-15 min |
| E2E | 30% | 15-30 min |
| Contract | 100% API | 2-5 min |
| Load | Performance | 30-60 min |
| Chaos | Resilience | 15-30 min |

---

## Critical Test Suites

### Auth Tests
- Password authentication flow
- OTP generation and verification
- Token validation and refresh
- Session lifecycle

### Queue Tests
- Message processing
- Retry behavior
- DLQ handling
- Race conditions

### Replay Tests
- Idempotency key validation
- Token reuse prevention
- Duplicate request rejection

### Provider Tests
- Provider routing
- Failover behavior
- Retry and fallback

---

## CI/CD Integration

```yaml
# Example pipeline
stages:
  - unit
  - integration
  - contract
  - security-scan
  - load-test (nightly)
  - chaos-test (weekly)
```

