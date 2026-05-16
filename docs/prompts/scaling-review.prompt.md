---
title: Scaling Review
domain: Capacity Planning
owner: Infrastructure Team
criticality: High
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
---

# Scaling Review Prompt

## Purpose
Use this prompt when evaluating system capacity, planning scaling, or analyzing load-related issues.

---

## Context

UICP must handle varying load while maintaining reliability and performance. Scaling review ensures capacity meets demand.

## Analysis Steps

### 1. Load Analysis
- Current request volume and trends?
- Peak load patterns?
- Concurrent connections?
- Request size distribution?

### 2. Capacity Assessment
- Are we approaching limits?
- What's the headroom?
- Bottleneck identification?
- Resource utilization by component?

### 3. Scaling Mechanisms
- Horizontal scaling possible?
- Auto-scaling configured?
- Database connection limits?
- Queue capacity?

### 4. Recommendations
- Scale up or out?
- Optimize expensive operations?
- Add caching?
- Optimize database queries?

---

## Output Format

```markdown
## Scaling Assessment

### Current Capacity: [adequate/stressed/overloaded]

### Projected Growth: ...

### Scaling Plan
1. ...

### Priority Actions
1. ...
```