"""Base contracts and abstract interfaces for security rules and rule loaders."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from lume.adapters.base import BaseTargetAdapter
from lume.core.verdict.models import Evidence, SeverityLevel, Verdict, VerdictStatus


class RuleMetadata(BaseModel):
    """Metadata schema defining a security rule."""
    rule_id: str = Field(..., description="Unique rule ID, e.g., 'PI-001'")
    name: str = Field(..., description="Human-readable rule name")
    description: str = Field(..., description="Description of the security vulnerability tested")
    category: str = Field(default="prompt_injection", description="OWASP category or module name")
    severity: SeverityLevel = Field(default=SeverityLevel.HIGH, description="Default severity if triggered")
    version: str = Field(default="1.0.0", description="Rule version")
    author: str = Field(default="LUME Team", description="Rule author or contributor")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    remediation: Optional[str] = Field(default=None, description="Recommended remediation guidance")


class BaseRule(ABC):
    """Abstract base class that all security detection rules must implement.

    Each of the 6 prompt injection rules in Module 3 will subclass this interface.
    """

    def __init__(self, metadata: RuleMetadata):
        self.metadata = metadata

    @property
    def rule_id(self) -> str:
        return self.metadata.rule_id

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def category(self) -> str:
        return self.metadata.category

    @property
    def severity(self) -> SeverityLevel:
        return self.metadata.severity

    @abstractmethod
    async def evaluate(
        self,
        target: BaseTargetAdapter,
        context: Optional[Dict[str, Any]] = None,
    ) -> Verdict:
        """Execute the rule against the target adapter and return a Verdict.

        Args:
            target: The active target adapter communicating with the AI system.
            context: Optional runtime scan context or parameters.

        Returns:
            A structured Verdict model with evidence and status.
        """
        pass

    def create_verdict(
        self,
        status: VerdictStatus,
        evidence: Optional[Evidence] = None,
        confidence: float = 1.0,
        notes: Optional[str] = None,
        execution_time_ms: float = 0.0,
    ) -> Verdict:
        """Helper to create a standard Verdict from this rule's metadata."""
        return Verdict(
            rule_id=self.metadata.rule_id,
            rule_name=self.metadata.name,
            category=self.metadata.category,
            severity=self.metadata.severity,
            status=status,
            confidence=confidence,
            evidence=evidence,
            recommendation=self.metadata.remediation,
            execution_time_ms=execution_time_ms,
        )


class BaseRuleLoader(ABC):
    """Abstract interface for loading rules from disk, modules, or configurations."""

    @abstractmethod
    def load_rules(self, category: Optional[str] = None) -> List[BaseRule]:
        """Load and return all matching rules."""
        pass

    @abstractmethod
    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        """Retrieve a specific rule by its ID."""
        pass


class RuleRegistry:
    """In-memory registry enabling decoupled registration of rules by modular teams."""

    _registry: Dict[str, BaseRule] = {}

    @classmethod
    def register(cls, rule: BaseRule) -> None:
        """Register a new rule instance."""
        cls._registry[rule.rule_id] = rule

    @classmethod
    def get(cls, rule_id: str) -> Optional[BaseRule]:
        """Retrieve a registered rule by ID."""
        return cls._registry.get(rule_id)

    @classmethod
    def get_all(cls) -> List[BaseRule]:
        """Return all registered rules."""
        return list(cls._registry.values())

    @classmethod
    def filter_by_category(cls, category: str) -> List[BaseRule]:
        """Filter registered rules by category (e.g. prompt_injection)."""
        return [r for r in cls._registry.values() if r.category.lower() == category.lower()]

    @classmethod
    def clear(cls) -> None:
        """Clear the registry (useful for testing)."""
        cls._registry.clear()
