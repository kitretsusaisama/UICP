---
title: Incident Analysis
domain: Incident Response
owner: Platform Team
criticality: High
ai-ingestable: true
review-cycle: post-incident
last-reviewed: 2026-05-16
---

# Incident Analysis Prompt

## Purpose
Use this prompt when analyzing production incidents, service disruptions, or system failures.

---

## Context

Incident analysis helps understand root causes, impact, and prevents recurrence. Proper post-mortem improves system reliability.

## Analysis Steps

### 1. Incident Timeline
- When was incident detected?
- When did it start?
- When was it resolved?
- What was the detection time?

### 2. Impact Assessment
- Who was affected?
- What functionality was impacted?
- Duration of impact?
- Data loss or corruption?

### 3. Root Cause Analysis
- What triggered the incident?
- What failed?
- Why wasn't it caught?
- What defenses failed?

### 4. Action Items
- Immediate fixes?
- Process improvements?
- Monitoring enhancements?
- Documentation updates?

---

## Output Format

```markdown
## Incident Post-Mortem

### Summary: ...

### Timeline
- Detection: ...
- Response: ...
- Resolution: ...

### Root Cause: ...

### Impact
- Users Affected: ...
- Duration: ...

### Action Items
1. ...
```