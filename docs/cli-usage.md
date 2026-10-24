# LUME CLI Usage Guide

## Command Overview

The `lume` command-line interface provides automated AI vulnerability assessment tools.

---

## Commands

### 1. `lume scan`
Initiates an automated security scan against an authorized AI application endpoint.

```bash
# Basic scan against authorized local chatbot
lume scan prompt-injection --target http://localhost:8000/v1/chat

# Scanning an external endpoint (requires explicit authorization)
lume scan prompt-injection --target https://ai.example.com/api/generate --authorized

# Filter to execute a single specific rule
lume scan prompt-injection --target http://localhost:8000/v1/chat --rule PI-001

# Customize concurrency, timeout, and output format
lume scan prompt-injection \
    --target http://localhost:8000/v1/chat \
    --concurrency 4 \
    --timeout 20 \
    --output json

# Scan real authenticated client AI endpoint with Bearer token
lume scan prompt-injection \
    --target https://client-ai.company.com/v1/chat \
    --authorized \
    -H "Authorization: Bearer <CLIENT_JWT_TOKEN>" \
    -H "X-Client-ID: client-prod-01"

# Scan client endpoint using OpenAI chat completions format
lume scan prompt-injection \
    --target http://client-llm-service:8080/v1/chat/completions \
    --format openai \
    --model gpt-4o \
    -H "Authorization: Bearer <API_KEY>"

# Custom JSON request payload mapping for proprietary client chatbot
lume scan prompt-injection \
    --target http://localhost:8000/api/chat \
    --prompt-field "user_message" \
    --response-field "bot_reply"

# Pentesting: Route through Burp Suite or OWASP ZAP with TLS bypass and rate-limiting delay
lume scan prompt-injection \
    --target https://staging-ai.internal:8443/chat \
    --authorized \
    --proxy http://127.0.0.1:8080 \
    --insecure \
    --delay-ms 150 \
    --user-agent "LUME-BurpSuite-Auditor/1.0"
```

#### Options Reference
| Option | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--target` | `-t` | Target URL or endpoint (Required) | None |
| `--module` | `-m` | Security category (e.g. `prompt_injection`) | `prompt_injection` |
| `--rule` | `-r` | Specific Rule ID (e.g. `PI-001`) | None (runs all) |
| `--header` | `-H` | Custom HTTP header (can specify multiple times) | None |
| `--format` | | Payload format: `standard` or `openai` | `standard` |
| `--model` | | Model identifier if required by endpoint | None |
| `--concurrency` | `-c` | Max concurrent rule evaluations (1–10) | `2` |
| `--timeout` | | Timeout per rule evaluation in seconds | `30.0` |
| `--output` | `-o` | Output format: `table` or `json` | `table` |
| `--report-file` | | Path to save JSON report | `reports/scan_<id>.json` |
| `--authorized` | `-a` | Explicit confirmation of authorization | `False` |
| `--proxy` | | Upstream HTTP/HTTPS proxy URL (e.g. `http://127.0.0.1:8080`) | None |
| `--insecure` | `-k` | Disable TLS/SSL certificate verification | `False` |
| `--delay-ms` | | Delay between requests in ms to prevent WAF bans | `0` |
| `--user-agent` | | Custom User-Agent header string | `LUME-Security-Scanner/0.1.0` |

---

### 2. `lume list-rules`
Displays all registered security detection rules and their metadata.

```bash
lume list-rules

# Filter rules by category
lume list-rules --category prompt_injection
```

---

### 3. `lume info`
Displays system diagnostics, host platform detection (Kali Linux, macOS, Windows, Docker), and active modules.

```bash
lume info
```

---

### 4. `lume version`
Displays current version and runtime environment details.

```bash
lume version
lume version --verbose
```
