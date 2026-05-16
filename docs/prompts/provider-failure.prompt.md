---
title: Provider Failure Analysis
domain: External Integrations
owner: Platform Team
criticality: High
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
---

# Provider Failure Analysis Prompt

## Purpose
Use this prompt when analyzing external provider failures, timeouts, or degraded service.

---

## Context

UICP integrates with multiple external providers (KMS, Email, Queue, Cache). Provider failures can impact system availability.

## Analysis Steps

### 1. Identify Failing Provider
- Which provider is experiencing issues?
- Is it a timeout, error, or degradation?
- What's the error code and message?
- Is it affecting all requests or specific operations?

### 2. Impact Assessment
- What UICP features are affected?
- How many tenants/users impacted?
- What's the error rate?
- Any data consistency issues?

### 3. Failure Handling
- Are there retries configured?
- What's the retry strategy?
- Is there fallback logic?
- Are circuit breakers in place?

### 4. Recovery Actions
- What's the expected recovery time?
- Can we switch providers?
- Is manual intervention needed?
- What monitoring alerts are triggered?

---

## Output Format

```markdown
## Provider Failure Report

### Provider: ...
### Status: [Partial/Complete Outage/Degraded]

### Impact Analysis
- Affected Features: ...
- User Impact: ...

### Mitigation Steps
1. ...

### Prevention Recommendations
1. ...
```