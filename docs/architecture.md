# LUME Security Toolkit — Architecture Specification

## Overview

The **LUME Security Toolkit** is an enterprise-grade AI security testing framework designed to evaluate Large Language Model (LLM) endpoints and AI applications against the **OWASP Top 10 for LLM (2025)**.

The system is built on **Hexagonal (Ports and Adapters) Architecture** and **Domain-Driven Design (DDD)** principles to ensure high cohesion, low coupling, and cross-platform reliability (Kali Linux, macOS, Windows, and Docker).

---

## Architectural Layers

```text
┌────────────────────────────────────────────────────────┐
│                   CLI / UI Layer                       │
│    lume/cli/main.py  |  display/banner.py              │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│                   Core Scanner Engine                  │
│    lume/core/scanner/runner.py (ScannerEngine)         │
│    lume/core/target_manager/manager.py (TargetManager) │
│    lume/core/executor/base.py (TestExecutor)           │
│    lume/core/rule_loader/base.py (RuleRegistry)        │
└───────────┬────────────────────────────────┬───────────┘
            │                                │
            ▼                                ▼
┌───────────────────────────┐    ┌───────────────────────────┐
│     Security Modules      │    │      Target Adapters      │
│  modules/prompt_injection │    │  adapters/http/client.py  │
│  • rules/ (PI-001 - 006)  │    │  adapters/local/mock.py   │
│  • payloads/bank.py       │    │  adapters/api/client.py   │
│  • detectors/matcher.py   │    └───────────────────────────┘
│  • evaluators/evaluator.py│
└───────────┬───────────────┘
            │
            ▼
┌────────────────────────────────────────────────────────┐
│               Evidence & Reporting Layer               │
│    lume/evidence/collector.py                          │
│    lume/reporting/console_reporter.py                  │
│    lume/reporting/json_reporter.py                     │
│    lume/utils/redaction.py                             │
└────────────────────────────────────────────────────────┘
```

---

## Core Contracts & Interfaces

### 1. BaseRule (`lume.core.rule_loader.base.BaseRule`)
All detection rules inherit from `BaseRule` and register themselves into `RuleRegistry`:
```python
class BaseRule(ABC):
    def __init__(self, metadata: RuleMetadata): ...
    
    @abstractmethod
    async def evaluate(self, target: BaseTargetAdapter, context: Optional[Dict[str, Any]] = None) -> Verdict: ...
```

### 2. BaseTargetAdapter (`lume.adapters.base.BaseTargetAdapter`)
Decouples the transport protocol from security rule logic:
```python
class BaseTargetAdapter(ABC):
    @abstractmethod
    async def send_prompt_async(self, prompt: str, **kwargs: Any) -> TargetResponse: ...
    
    @abstractmethod
    def health_check(self) -> bool: ...
```

### 3. Verdict & ScanReport (`lume.core.verdict.models`)
All assessments output immutable, strongly typed Pydantic models:
* `VerdictStatus`: `VULNERABLE`, `BLOCKED`, `INCONCLUSIVE`, `ERROR`
* `SeverityLevel`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
* `ScanReport`: Aggregates rule verdicts, timestamps, composite risk scores (0–100), and evidence.

---

## Three-State Verdict Determinism

To eliminate speculative findings:
1. **`VULNERABLE`**: The model executed the injected payload and produced unambiguous behavioral proof (e.g., leaked canary token, issued unauthorized tool invocation).
2. **`BLOCKED`**: The model adhered to security directives, refused the attack via guardrails, or sanitized the input.
3. **`INCONCLUSIVE`**: The target timed out, returned 5xx transport errors, or responded ambiguously without triggering either canary or refusal indicators.

When a vulnerability is detected, **the scan does not block or abort**. It continues executing all scheduled rules, logs the finding, and outputs clear step-by-step remediation guidance.
