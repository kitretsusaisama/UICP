---
title: Replay Analysis
domain: Security
owner: Security Team
criticality: Critical
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
---

# Replay Analysis Prompt

## Purpose
Use this prompt when analyzing potential replay attack scenarios.

---

## Context

A replay attack attempts to reuse valid authentication tokens or requests.

## Analysis Steps

### 1. Identify Vulnerability
- Is there an idempotency key mechanism?
- Are tokens short-lived?
- Is there token rotation?

### 2. Check Current Protections
- HMAC validation for API keys?
- Token blocklist on refresh?
- Session invalidation on password change?

### 3. Evaluate Impact
- What data is exposed?
- Can attacker access other tenants?
- What's the blast radius?

### 4. Recommend Fixes
- Add idempotency keys?
- Shorten token lifespan?
- Add anomaly detection?

---

## Output Format

```markdown
## Vulnerability Assessment

### Severity: [Critical/High/Medium/Low]

### Root Cause: ...

### Impact: ...

### Recommended Fix: ...
```