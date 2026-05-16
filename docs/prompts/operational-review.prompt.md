---
title: Operational Review
domain: Operations
owner: Infrastructure Team
criticality: Medium
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
---

# Operational Review Prompt

## Purpose
Use this prompt when conducting routine operational reviews, checking system health, or preparing operational reports.

---

## Context

Operational review ensures system runs smoothly, identifies issues early, and maintains operational excellence.

## Analysis Steps

### 1. System Health
- All services running?
- Health checks passing?
- No active alerts?
- Dependencies healthy?

### 2. Performance Review
- Response times within SLA?
- Error rates acceptable?
- Resource utilization normal?
- Throughput stable?

### 3. Security Review
- Any suspicious activity?
- Failed login attempts?
- Rate limiting triggered?
- API key rotation current?

### 4. Operations Summary
- Recent deployments?
- Configuration changes?
- Known issues?
- Upcoming maintenance?

---

## Output Format

```markdown
## Operational Review

### Overall Status: [Green/Yellow/Red]

### Health Check
- Services: ...
- Dependencies: ...
- Alerts: ...

### Metrics Summary
- Uptime: ...
- Avg Response: ...
- Error Rate: ...

### Action Items
1. ...
```