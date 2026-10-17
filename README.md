# LUME Security Toolkit

<p align="center">
  <strong>Enterprise-Grade AI Security CLI Toolkit for LLM Vulnerability Assessment</strong><br>
  <em>Designed for Red Teams, AppSec Engineers, and DevSecOps Pipelines</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-0.1.0-blue.svg" alt="Version 0.1.0">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20macOS%20%7C%20Windows-brightgreen.svg" alt="Platforms">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED.svg" alt="Docker Ready">
  <img src="https://img.shields.io/badge/OWASP%20LLM-LLM01%3A2025%20Prompt%20Injection-orange.svg" alt="OWASP LLM01:2025">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License MIT">
</p>

---

## 🚀 Overview

**LUME Security Toolkit** is a modular, contract-driven AI security assessment framework built to test authorized Large Language Model (LLM) applications and agents against **OWASP Top 10 for LLM (2025)** vulnerabilities.

LUME dispatches controlled test vectors, collects observable behavioral evidence, evaluates deterministic verdicts (`VULNERABLE`, `BLOCKED`, `INCONCLUSIVE`), and outputs rich terminal tables and structured JSON reports with actionable remediation guidance.

### Key Capabilities
* **Primary Kali Linux Support**: Optimized for offensive security specialists, penetration testers, and red teams running on **Kali Linux**, with native cross-platform support for **macOS** and **Windows**.
* **Six Prompt-Injection Rules (V1)**: Comprehensive coverage of direct overrides, persona impersonation, indirect data injection, delimiter breakouts, tool hijacking, and obfuscated evasions.
* **Non-Blocking Finding Display**: Identified vulnerabilities **never crash or abort** your assessment run; LUME records and highlights findings with immediate step-by-step remediation advice.
* **Controlled Synthetic Test Targets**: Includes safe, deterministic in-tree fixtures (`vulnerable_ai` and `protected_ai`) for zero-cost local testing and validation.
* **Audit-Safe Evidence & Redaction**: Automatically redacts API keys, credentials, and bearer tokens before saving reports to disk.
* **Docker & CI/CD Native**: Ready for single-command containerized execution via Docker Compose and GitHub Actions.

---

## 🛡️ The Six Core Detection Rules

| Rule ID | Rule Name | Severity | Target Scope | Description |
| :---: | :--- | :---: | :---: | :--- |
| **`PI-001`** | **Direct Instruction Override** | `CRITICAL` | `LLM01:2025` | Detects attempts to force the model to disregard prior system instructions and output canary tokens. |
| **`PI-002`** | **Instruction / Privilege Impersonation** | `HIGH` | `LLM01:2025` | Tests resistance to forged administrative, maintenance, or kernel personas seeking elevated privileges. |
| **`PI-003`** | **Indirect Prompt Injection** | `HIGH` | `LLM01:2025` | Tests whether untrusted inputs (e.g. support tickets, retrieved documents) can hijack instruction flow. |
| **`PI-004`** | **Delimiter & Boundary Manipulation** | `HIGH` | `LLM01:2025` | Tests boundary escapes using synthetic XML tags, Markdown triple backticks (` ``` `), and YAML separators (`---`). |
| **`PI-005`** | **Tool & Action Hijacking Instructions** | `CRITICAL` | `LLM01:2025` | Evaluates whether inputs can induce unauthorized tool invocations (e.g. database purges, refund webhooks). |
| **`PI-006`** | **Obfuscated Prompt Injection** | `MEDIUM` | `LLM01:2025` | Tests detection evasion using Base64 encoding, leetspeak substitutions, and control characters. |

---

## 📦 Installation

### 1. Kali Linux & Debian / Ubuntu
```bash
# Clone repository
git clone https://github.com/Gaganbtech/LUME-Security.git
cd LUME-Security

# Create virtual environment and install
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2. macOS
```bash
git clone https://github.com/Gaganbtech/LUME-Security.git
cd LUME-Security
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 3. Windows (PowerShell / Command Prompt)
```powershell
git clone https://github.com/Gaganbtech/LUME-Security.git
cd LUME-Security
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```

### 4. Docker
```bash
# Build the Docker image
docker build -t lume-security -f docker/Dockerfile .

# Run LUME help
docker run --rm lume-security --help
```

---

## 💻 Quick Start & Usage

### 1. View Registered Security Rules
```bash
lume list-rules
```

### 2. Run a Security Scan
```bash
# Scan an authorized local AI endpoint
lume scan prompt-injection --target http://localhost:8000/v1/chat

# Scan with custom payload mappings
lume scan prompt-injection \
    --target http://localhost:8000/api/generate \
    --prompt-field "prompt" \
    --response-field "response" \
    --concurrency 3 \
    --timeout 15.0

# Scan an authorized client endpoint with Bearer authentication
lume scan prompt-injection \
    --target https://ai-staging.client.com/v1/chat \
    --authorized \
    -H "Authorization: Bearer <CLIENT_TOKEN>" \
    -H "X-Client-Org: ClientCorp"

# Scan an OpenAI-compatible client endpoint
lume scan prompt-injection \
    --target http://client-ai-service:8080/v1/chat/completions \
    --format openai \
    --model gpt-4o \
    -H "Authorization: Bearer <CLIENT_API_KEY>"
```

### 3. Run One-Touch Local Verification Demo
```bash
# Starts the vulnerable test target and scans it automatically
./scripts/demo_scan.sh
```

### 4. Run via Docker Compose
```bash
# Spawns LUME scanner along with the vulnerable AI test fixture in an isolated bridge network
docker compose -f docker/compose.yaml up --build
```

---

## 🧪 Testing and Verification

LUME includes a complete test suite covering unit contracts, adapters, rules, reporting, and end-to-end workflows:

```bash
# Run unit, integration, and E2E tests
pytest -v

# Run code style and lint checks
ruff check .
```

---

## 📂 Repository Structure

```text
LUME-Security/
├── .github/              # CI/CD workflows, CODEOWNERS, issue & PR templates
├── configs/              # Default scanner & adapter configuration
├── docker/               # Multi-stage Dockerfile and Docker Compose stack
├── docs/                 # Architecture, Rule Development, and CLI guides
├── lume/                 # Core LUME Python package
│   ├── adapters/         # Target communication layer (HTTP, Local mock, API)
│   ├── cli/              # Presentation layer (Typer CLI, Rich banner & tables)
│   ├── core/             # Scanner coordinator, executor, rule loader, target manager
│   ├── evidence/         # Evidence collector and redaction sanitizers
│   ├── modules/          # Security attack modules (Prompt Injection V1)
│   ├── reporting/        # JSON audit logs and formatted console reporters
│   └── utils/            # Structured logging and credential redaction
├── owasp-llm/            # OWASP Top 10 for LLM research and reference mappings
├── reports/              # Target directory for generated scan audit reports
├── scripts/              # Convenience scripts (one-touch demo)
└── tests/                # Unit, integration, and E2E tests with synthetic fixtures
```

---

## 🔒 Security & Safe Operation

* **Authorized Testing Only**: LUME is engineered exclusively for authorized security auditing, red-teaming, and defensive hardening. Active scans against external addresses require explicit confirmation (`--authorized`).
* **Zero Arbitrary Execution**: Malicious payloads are dispatched strictly as data to the target adapter; they are never executed or evaluated locally.
* **Sensitive Data Redaction**: Evidence snapshots automatically redact API keys, passwords, and bearer tokens.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
