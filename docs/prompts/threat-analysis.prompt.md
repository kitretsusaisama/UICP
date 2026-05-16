---
title: Threat Analysis
domain: Security
owner: Security Team
criticality: Critical
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
---

# Threat Analysis Prompt

## Purpose
Use this prompt when conducting security threat modeling or analyzing potential security vulnerabilities.

---

## Context

Threat analysis identifies and mitigates security risks in UICP including data exposure, unauthorized access, and injection attacks.

## Analysis Steps

### 1. Threat Identification
- What assets are at risk?
- What are potential attack vectors?
- Are there known CVEs?
- What's the attack surface?

### 2. Attack Scenario Analysis
- How would an attacker exploit this?
- What's the attack complexity?
- What privileges are needed?
- Can it be automated?

### 3. Impact Assessment
- What's the confidentiality impact?
- Integrity impact?
- Availability impact?
- Data exposure scope?

### 4. Mitigation Strategies
- Input validation?
- Access controls?
- Encryption?
- Monitoring and alerting?

---

## Output Format

```markdown
## Threat Analysis Report

### Threat: ...
### Attack Vector: ...

### Severity: [Critical/High/Medium/Low]

### Likelihood: [Likely/Possible/Unlikely]

### Mitigation
1. ...

### Detection
1. ...
```