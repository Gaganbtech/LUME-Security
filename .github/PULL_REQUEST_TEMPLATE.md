## Description
Briefly describe the changes introduced in this pull request and link to any related issues.

## Type of Change
- [ ] New security detection rule (OWASP Top 10 for LLM)
- [ ] Core scanner / executor enhancement
- [ ] Target adapter addition (HTTP / API / Local)
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] Documentation update

## Rule / Feature Checklist (For New Rules)
- [ ] Rule inherits from `BaseRule` and defines `RuleMetadata`
- [ ] Test payloads are segregated in `payloads/`
- [ ] Includes benign test cases to prevent false positives
- [ ] Returns calibrated `VULNERABLE`, `BLOCKED`, or `INCONCLUSIVE` verdicts
- [ ] Includes clear remediation guidance

## Quality & Verification
- [ ] Code formatted and passes `ruff check .`
- [ ] Tests pass via `pytest`
- [ ] Cross-platform compatibility maintained (Kali Linux, macOS, Windows)
- [ ] No hardcoded secrets, API keys, or unredacted credentials
