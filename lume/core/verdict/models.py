"""Data models for verdicts, evidence, and final security reports."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Vulnerability severity classification."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VerdictStatus(str, Enum):
    """Status result of a rule evaluation."""
    VULNERABLE = "VULNERABLE"
    BLOCKED = "BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    # Backward compatibility alias
    SECURE = "BLOCKED"


def _utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class Evidence(BaseModel):
    """Captured audit evidence verifying the verdict."""
    payload: str = Field(..., description="Prompt payload used in testing")
    response_snippet: str = Field(..., description="Observed target response snippet")
    matched_patterns: List[str] = Field(default_factory=list, description="Detector patterns triggered")
    status_code: Optional[int] = Field(default=None, description="HTTP status code received")
    latency_ms: Optional[float] = Field(default=None, description="Target roundtrip latency in ms")
    notes: Optional[str] = Field(default=None, description="Detailed analysis notes")
    timestamp: datetime = Field(default_factory=_utc_now, description="Evidence capture time")


class Verdict(BaseModel):
    """Individual security finding for a rule."""
    rule_id: str = Field(..., description="Unique rule identifier (e.g. PI-001)")
    rule_name: str = Field(..., description="Human-readable rule name")
    category: str = Field(..., description="OWASP category or module name")
    severity: SeverityLevel = Field(..., description="Severity rating if vulnerable")
    status: VerdictStatus = Field(..., description="Evaluation outcome (VULNERABLE, BLOCKED, INCONCLUSIVE)")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    evidence: Optional[Evidence] = Field(default=None, description="Supporting evidence")
    recommendation: Optional[str] = Field(default=None, description="Remediation guidance")
    execution_time_ms: float = Field(default=0.0, description="Rule evaluation duration")


class ScanReport(BaseModel):
    """Comprehensive scan report aggregating all rule verdicts."""
    scan_id: str = Field(..., description="Unique scan run identifier")
    target: str = Field(..., description="Target endpoint or descriptor")
    timestamp: datetime = Field(default_factory=_utc_now, description="Scan execution time")
    duration_seconds: float = Field(default=0.0, description="Total scan duration")
    total_rules: int = Field(default=0, description="Number of rules evaluated")
    vulnerable_count: int = Field(default=0, description="Number of vulnerable verdicts")
    blocked_count: int = Field(default=0, description="Number of blocked/secure verdicts")
    inconclusive_count: int = Field(default=0, description="Number of inconclusive verdicts")
    error_count: int = Field(default=0, description="Number of execution errors")
    verdicts: List[Verdict] = Field(default_factory=list, description="Detailed verdict list")
    overall_risk_score: float = Field(default=0.0, description="Composite risk score (0-100)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Scan environment metadata")

    @property
    def secure_count(self) -> int:
        """Alias for blocked_count."""
        return self.blocked_count
