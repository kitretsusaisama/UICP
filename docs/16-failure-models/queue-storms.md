# Failure Model: Queue Storms

## Metadata
```yaml
title: Queue Storms
domain: queues
criticality: HIGH
queue-impact: CRITICAL
ai-ingestable: true
```

---

## Description

Sudden spike in queue messages overwhelms workers.

---

## Symptoms

- Queue backlog > 10,000
- Processing time > 10s
- DLQ filling up
- Worker CPU at 100%

---

## Causes

- Provider outage (messages accumulate)
- Traffic spike (viral campaign)
- Bug in worker (re-processing)
- Retry amplification (exponential retry)

---

## Mitigation

1. Backpressure at API layer
2. Rate limit queue producers
3. Circuit breaker on workers
4. DLQ size limits

---

## Recovery

1. Scale workers horizontally
2. Process DLQ in batches
3. Enable slow mode
4. Monitor for secondary storms

