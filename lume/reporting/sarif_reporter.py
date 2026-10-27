"""SARIF 2.1.0 exporter for recorded LUME scan results.

Only observed VULNERABLE verdicts are emitted as SARIF alerts. No source
code position is invented for a network-based AI target.
"""

import json
import re
from pathlib import Path
from typing import Optional, Union
from urllib.parse import urlsplit, urlunsplit

from lume.core.verdict.models import ScanReport, VerdictStatus

_SECRET_PATTERNS = (
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret|password|authorization)\b(\s*[:=]\s*)[\w./+~=-]+"), r"\1\2[REDACTED]"),
    (re.compile(r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{12,})\b"), "[REDACTED]"),
)


def sanitize(value: object, limit: int = 4000) -> str:
    """Remove common credentials and truncate untrusted captured text.

    Best-effort masking is not a guarantee: operators must review reports for
    secrets and private data before distribution.
    """
    content = str(value if value is not None else "")
    for pattern, replacement in _SECRET_PATTERNS:
        content = pattern.sub(replacement, content)
    return content[:limit] + ("… [truncated]" if len(content) > limit else "")


def safe_target(value: str) -> str:
    """Discard target URL userinfo, query, and fragment (possible credentials)."""
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc:
        return sanitize(value)
    hostname = parts.hostname or "unknown"
    if ":" in hostname:
        hostname = f"[{hostname}]"
    authority = hostname + (f":{parts.port}" if parts.port else "")
    return sanitize(urlunsplit((parts.scheme, authority, parts.path, "", "")))


class SARIFReporter:
    """Write SARIF v2.1.0 for native CI security ingestion."""

    LEVELS = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}

    def __init__(self, output_dir: Union[str, Path] = "reports"):
        self.output_dir = Path(output_dir)

    def to_dict(self, report: ScanReport) -> dict:
        rules = {}
        results = []
        target = safe_target(report.target)
        for verdict in report.verdicts:
            rid = sanitize(verdict.rule_id, 200)
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "name": sanitize(verdict.rule_name, 200),
                    "shortDescription": {"text": sanitize(verdict.rule_name, 200)},
                    "properties": {"tags": [sanitize(verdict.category, 100)], "security-severity": str({"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}.get(verdict.severity.value, 0.0))},
                    "defaultConfiguration": {"level": self.LEVELS.get(verdict.severity.value, "warning")},
                }
            if verdict.status != VerdictStatus.VULNERABLE:
                continue
            evidence = verdict.evidence
            message = f"{verdict.rule_name}: observed VULNERABLE against {target}."
            if evidence and evidence.notes:
                message += " " + sanitize(evidence.notes, 700)
            result = {
                "ruleId": rid,
                "level": self.LEVELS.get(verdict.severity.value, "warning"),
                "message": {"text": sanitize(message, 1200)},
                # Logical location is truthful for an external HTTP target.
                # A source-file location would misrepresent the observation.
                "locations": [{"logicalLocations": [{"name": target[:500], "kind": "resource"}]}],
                "properties": {"verdict": verdict.status.value, "confidence": verdict.confidence,
                               "severity": verdict.severity.value,
                               "recommendation": sanitize(verdict.recommendation, 2000)},
            }
            if evidence:
                result["properties"]["evidence"] = {
                    "response": sanitize(evidence.response_snippet, 1000),
                    "notes": sanitize(evidence.notes, 1000),
                    "status_code": evidence.status_code,
                }
            results.append(result)
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "LUME Security", "informationUri": "https://github.com/Gaganbtech/LUME-Security", "rules": list(rules.values())}},
                "automationDetails": {"id": "lume/" + sanitize(report.scan_id, 100)},
                "results": results,
                "properties": {"scan_id": sanitize(report.scan_id), "target": target,
                               "total_tests": report.total_rules,
                               "risk_score": report.overall_risk_score,
                               "inconclusive": report.inconclusive_count,
                               "errors": report.error_count},
            }],
        }

    def generate(self, report: ScanReport, file_path: Optional[Union[str, Path]] = None) -> Path:
        target = Path(file_path) if file_path else self.output_dir / f"lume_scan_{report.scan_id}.sarif"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(report), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return target
