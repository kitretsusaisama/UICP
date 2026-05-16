# Failure Model: Redis Degradation

## Metadata
```yaml
title: Redis Degradation
domain: infrastructure
criticality: HIGH
ai-ingestable: true
```

---

## Description

Redis becomes slow, unresponsive, or experiences data loss.

---

## Symptoms

- Session validation failures
- Rate limit bypass (cache miss)
- Slow response times
- Connection pool exhaustion

---

## Impact Matrix

| Service | Impact | Fallback |
|---------|--------|----------|
| Sessions | HIGH | In-memory cache |
| Rate Limits | MEDIUM | Allow all |
| API Key Cache | MEDIUM | DB lookup |
| Provider Cache | LOW | Skip cache |

---

## Mitigation

1. Circuit breaker opens
2. Fall back to in-memory
3. Alert on fallback usage
4. Auto-recovery when Redis healthy

