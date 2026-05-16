# Request Lineage

## Metadata
```yaml
title: Request Lineage
domain: lineage
criticality: HIGH
ai-ingestable: true
```

---

## Overview

Request lineage tracks every operation through the system, enabling debugging, audit, and replay analysis.

---

## Lineage Types

### 1. Authentication Lineage
```
Auth Attempt → Credential Validation → Token Issue → Session Create
```

### 2. Communication Lineage
```
Send Request → Provider Router → Queue → Worker → Provider API → Delivery Confirm
```

### 3. Session Lineage
```
Login → Session Create → Token Issue → Refresh → Session Update → Logout
```

---

## Trace Correlation

Every operation includes:
- `traceId` - Full request ID
- `spanId` - Current operation
- `parentSpanId` - Parent operation
- `tenantId` - Tenant context

---

## Related Documents

- `15-runtime-lineage/auth-lineage.md`
- `15-runtime-lineage/delivery-lineage.md`

