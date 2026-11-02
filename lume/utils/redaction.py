"""Sensitive data and credential redaction utilities for LUME."""

import re
from typing import Any, Dict

# Common credential and token regex patterns
_REDACTION_PATTERNS = [
    # OpenAI API Keys
    (re.compile(r"sk-[a-zA-Z0-9]{20,T3BlbkFJ[a-zA-Z0-9]{20,}"), "[REDACTED_OPENAI_KEY]"),
    (re.compile(r"sk-(?:proj-)?[a-zA-Z0-9_-]{32,}"), "[REDACTED_API_KEY]"),
    # Anthropic API Keys
    (re.compile(r"sk-ant-[a-zA-Z0-9_-]{32,}"), "[REDACTED_ANTHROPIC_KEY]"),
    # Generic Bearer Tokens
    (re.compile(r"(?i)bearer\s+[a-zA-Z0-9_.\-~+/=]{16,}"), "Bearer [REDACTED_TOKEN]"),
    # Basic Authorization
    (re.compile(r"(?i)basic\s+[a-zA-Z0-9+/=]{16,}"), "Basic [REDACTED_AUTH]"),
    # Generic Passwords and Secrets in URLs or key-values
    (re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*['\"]?([^'\"\s,;&]+)"), r"\1=[REDACTED]"),
    # AWS Access Keys
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
]


def redact_sensitive_text(text: str, max_length: int = 1000) -> str:
    """Sanitize and redact sensitive credentials from a text snippet.

    Args:
        text: The raw text string to sanitize.
        max_length: Maximum allowed length before truncation.

    Returns:
        Sanitized and truncated text string.
    """
    if not text:
        return ""

    sanitized = str(text)
    for pattern, replacement in _REDACTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    # Truncate overly long responses to prevent bloating evidence
    if len(sanitized) > max_length:
        return sanitized[:max_length] + " ... [TRUNCATED]"

    return sanitized


def redact_dictionary(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively redact dictionary values containing sensitive keys."""
    sensitive_keys = {"authorization", "api_key", "apikey", "password", "secret", "token", "auth"}
    sanitized: Dict[str, Any] = {}

    for k, v in data.items():
        if any(sk in k.lower() for sk in sensitive_keys):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = redact_dictionary(v)
        elif isinstance(v, list):
            sanitized[k] = [
                redact_dictionary(item) if isinstance(item, dict) else redact_sensitive_text(str(item))
                for item in v
            ]
        elif isinstance(v, str):
            sanitized[k] = redact_sensitive_text(v)
        else:
            sanitized[k] = v

    return sanitized
