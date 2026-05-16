---
title: Architecture Review
domain: System Architecture
owner: Platform Team
criticality: High
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
---

# Architecture Review Prompt

## Purpose
Use this prompt when reviewing UICP architecture changes or new implementations.

---

## Context

You are reviewing a proposed change to the UICP system.

## Questions to Answer

### 1. Tenant Isolation
- Does the change properly isolate tenant data?
- Is tenant ID derived from credential, not header?
- Are there any tenant-scoped queries?

### 2. Queue Safety
- Does the change involve external I/O?
- Should it use queues for reliability?
- What's the retry policy?

### 3. Security
- Are credentials properly validated?
- Is sensitive data logged?
- Is HMAC validation required?

### 4. Observability
- Are there proper metrics?
- Is tracing included?
- Are error logs structured?

---

## Output Format

```markdown
## Review Summary

### Security
- [Pass/Fail] - Details

### Reliability
- [Pass/Fail] - Details

### Performance
- [Pass/Fail] - Details

### Recommendations
1. ...
```