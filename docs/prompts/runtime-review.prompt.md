---
title: Runtime Review
domain: Application Runtime
owner: Platform Team
criticality: High
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
---

# Runtime Review Prompt

## Purpose
Use this prompt when analyzing runtime behavior, performance issues, or resource utilization.

---

## Context

UICP runs on Node.js runtime. Runtime review helps identify memory leaks, CPU bottlenecks, and stability issues.

## Analysis Steps

### 1. Resource Utilization
- CPU usage patterns?
- Memory consumption and growth?
- Event loop lag?
- Connection pool status?

### 2. Performance Metrics
- Request latency distribution?
- Throughput trends?
- Error rate changes?
- Dependency health?

### 3. Stability Analysis
- Unhandled exceptions?
- Uncaught promise rejections?
- Process crashes?
- Graceful shutdown working?

### 4. Health Checks
- Are all endpoints responding?
- Database connections healthy?
- Cache hit rates acceptable?
- Queue consumers running?

---

## Output Format

```markdown
## Runtime Health Report

### Status: [Healthy/Degraded/Critical]

### Resource Usage
- CPU: ...
- Memory: ...
- Connections: ...

### Issues Found
1. ...

### Recommendations
1. ...
```