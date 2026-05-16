---
title: Queue Analysis
domain: Message Queues
owner: Infrastructure Team
criticality: High
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
---

# Queue Analysis Prompt

## Purpose
Use this prompt when debugging message queue issues, examining queue health, or analyzing queue-related failures.

---

## Context

Message queues are critical for async processing, reliable delivery, and system decoupling in UICP.

## Analysis Steps

### 1. Queue Health Check
- What is the current queue depth?
- Are there any messages in DLQ?
- What's the average processing time?
- Any backpressure indicators?

### 2. Message Flow Analysis
- Are messages being produced correctly?
- Are consumers keeping up?
- Is there message ordering issues?
- What's the retry rate?

### 3. Failure Mode Analysis
- What happens when queue is unavailable?
- Are there circuit breakers configured?
- Is there message persistence?
- What's the recovery procedure?

### 4. Performance Considerations
- Batch size appropriate?
- Concurrency settings optimal?
- Connection pooling configured?
- Any memory pressure?

---

## Output Format

```markdown
## Queue Health Report

### Status: [Healthy/Degraded/Critical]

### Metrics
- Queue Depth: ...
- Processing Rate: ...
- Error Rate: ...

### Issues Identified
1. ...

### Recommendations
1. ...
```