---
name: Rule Proposal
about: Propose a new AI security rule or prompt injection detection test vector
title: "[RULE] "
labels: enhancement, rule-proposal
assignees: ''
---

### Rule Overview
- **Proposed Rule ID**: [e.g. PI-007, SEC-001]
- **Rule Name**: 
- **OWASP LLM (2025) Category**: [e.g. LLM01: Prompt Injection, LLM02: Sensitive Info Disclosure]
- **Default Severity**: [CRITICAL / HIGH / MEDIUM / LOW / INFO]

### Threat Model & Attack Vector
Describe the vulnerability, how it affects LLM applications, and why standard filters fail.

### Test Payload Examples
```text
Sample prompt test vector here
```

### Expected Behavior & Evaluation Criteria
- Observable condition for `VULNERABLE`:
- Observable condition for `BLOCKED`:

### Recommended Remediation Guidance
What specific mitigation should be shown in terminal and JSON reports?
