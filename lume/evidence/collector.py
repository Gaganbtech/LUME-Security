"""Evidence collection, redaction, and audit trail management."""

from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field

from lume.core.verdict.models import Evidence
from lume.utils.redaction import redact_sensitive_text


class TestCaseEvidence(BaseModel):
    """Container for evidence gathered during an individual test case execution."""
    rule_id: str
    test_id: str
    payload_preview: str
    response_snippet: str
    matched_patterns: List[str] = Field(default_factory=list)
    status_code: Optional[int] = None
    latency_ms: Optional[float] = None
    is_vulnerable: bool = False
    is_blocked: bool = False
    notes: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvidenceCollector:
    """Thread-safe collector for test case observations and audit evidence."""

    def __init__(self, max_snippet_length: int = 500):
        self.max_snippet_length = max_snippet_length
        self._entries: List[TestCaseEvidence] = []

    def record(
        self,
        rule_id: str,
        test_id: str,
        raw_payload: str,
        raw_response: str,
        matched_patterns: Optional[List[str]] = None,
        status_code: Optional[int] = None,
        latency_ms: Optional[float] = None,
        is_vulnerable: bool = False,
        is_blocked: bool = False,
        notes: Optional[str] = None,
    ) -> TestCaseEvidence:
        """Sanitize and record an observed interaction with the target."""
        clean_payload = redact_sensitive_text(raw_payload, max_length=150)
        clean_response = redact_sensitive_text(raw_response, max_length=self.max_snippet_length)

        entry = TestCaseEvidence(
            rule_id=rule_id,
            test_id=test_id,
            payload_preview=clean_payload,
            response_snippet=clean_response,
            matched_patterns=matched_patterns or [],
            status_code=status_code,
            latency_ms=latency_ms,
            is_vulnerable=is_vulnerable,
            is_blocked=is_blocked,
            notes=notes,
        )
        self._entries.append(entry)
        return entry

    def create_verdict_evidence(
        self,
        rule_id: str,
        payload: str,
        response: str,
        matched_patterns: Optional[List[str]] = None,
        status_code: Optional[int] = None,
        latency_ms: Optional[float] = None,
        notes: Optional[str] = None,
    ) -> Evidence:
        """Create a sanitized Evidence model for a final Verdict."""
        clean_payload = redact_sensitive_text(payload, max_length=200)
        clean_response = redact_sensitive_text(response, max_length=self.max_snippet_length)

        return Evidence(
            payload=clean_payload,
            response_snippet=clean_response,
            matched_patterns=matched_patterns or [],
            status_code=status_code,
            latency_ms=latency_ms,
            notes=notes,
        )

    def get_entries_for_rule(self, rule_id: str) -> List[TestCaseEvidence]:
        """Return all recorded evidence for a specific rule ID."""
        return [e for e in self._entries if e.rule_id == rule_id]

    def clear(self) -> None:
        """Clear all collected evidence."""
        self._entries.clear()
