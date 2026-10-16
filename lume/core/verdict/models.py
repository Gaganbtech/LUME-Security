"""Data models for verdicts, evidence, and final security reports."""

from datetime import datetime
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
    SECURE = "SECURE"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class Evidence(BaseModel):
    """Captured audit evidence verifying the verdict."""
    payload: str = Field(..., description="Prompt payload used in testing")
    response_snippet: str = Field(..., description="Observed target response snippet")
    matched_patterns: List[str] = Field(default_factory=list, description="Detector patterns triggered")
    notes: Optional[str] = Field(default=None, description="Detailed analysis notes")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Evidence capture time")


class Verdict(BaseModel):
    """Individual security finding for a rule."""
    rule_id: str = Field(..., description="Unique rule identifier (e.g. PI-001)")
    rule_name: str = Field(..., description="Human-readable rule name")
    category: str = Field(..., description="OWASP category or module name")
    severity: SeverityLevel = Field(..., description="Severity rating if vulnerable")
    status: VerdictStatus = Field(..., description="Evaluation outcome")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    evidence: Optional[Evidence] = Field(default=None, description="Supporting evidence")
    recommendation: Optional[str] = Field(default=None, description="Remediation guidance")
    execution_time_ms: float = Field(default=0.0, description="Rule evaluation duration")


class ScanReport(BaseModel):
    """Comprehensive scan report aggregating all rule verdicts."""
    scan_id: str = Field(..., description="Unique scan run identifier")
    target: str = Field(..., description="Target endpoint or descriptor")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Scan execution time")
    duration_seconds: float = Field(default=0.0, description="Total scan duration")
    total_rules: int = Field(default=0, description="Number of rules evaluated")
    vulnerable_count: int = Field(default=0, description="Number of vulnerable verdicts")
    secure_count: int = Field(default=0, description="Number of secure verdicts")
    error_count: int = Field(default=0, description="Number of execution errors")
    verdicts: List[Verdict] = Field(default_factory=list, description="Detailed verdict list")
    overall_risk_score: float = Field(default=0.0, description="Composite risk score (0-100)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Scan environment metadata")
