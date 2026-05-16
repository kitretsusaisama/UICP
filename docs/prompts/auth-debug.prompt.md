---
title: Authentication Debugging
domain: Security & Authentication
owner: Security Team
criticality: Critical
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
---

# Authentication Debugging Prompt

## Purpose
Use this prompt when debugging authentication failures, token issues, or authorization errors.

---

## Context

UICP uses multiple auth mechanisms: API keys with HMAC, session tokens, and potentially OAuth. Debugging auth issues requires understanding the credential flow.

## Analysis Steps

### 1. Authentication Flow
- What's the authentication method being used?
- Is it API key + HMAC or session-based?
- What does the credential look like?
- Is the tenant ID derived correctly?

### 2. Validation Checks
- Is the API key valid and not expired?
- Is HMAC signature correct?
- Is the key active and not revoked?
- Are there tenant permissions?

### 3. Common Failure Modes
- Clock skew causing signature failures?
- Incorrect signing algorithm?
- Missing required headers?
- Expired or rotated keys?

### 4. Debug Actions
- Check key creation timestamp?
- Verify HMAC computation?
- Review audit logs for recent key operations?
- Check for recent rotation events?

---

## Output Format

```markdown
## Auth Debug Report

### Issue: ...
### Auth Method: ...

### Root Cause: [Identified/Pending Investigation]

### Resolution Steps
1. ...

### Prevention
1. ...
```