"""RULE 04: Delimiter and Instruction-Boundary Manipulation (PI-004)."""

from typing import Any, Dict, Optional

from lume.adapters.base import BaseTargetAdapter
from lume.core.rule_loader.base import BaseRule, RuleMetadata
from lume.core.verdict.models import SeverityLevel, Verdict
from lume.evidence.collector import EvidenceCollector
from lume.modules.prompt_injection.detectors.matcher import ResponsePatternDetector
from lume.modules.prompt_injection.evaluators.evaluator import PromptInjectionEvaluator
from lume.modules.prompt_injection.payloads.bank import PI_004_PAYLOADS


class DelimiterBoundaryManipulationRule(BaseRule):
    """Tests whether untrusted inputs can manipulate instruction boundaries or breakout of data wrappers."""

    def __init__(self):
        metadata = RuleMetadata(
            rule_id="PI-004",
            name="Delimiter and Boundary Manipulation",
            description=(
                "Tests whether the model's instruction boundaries can be escaped using synthetic XML tags, "
                "Markdown code blocks (```), or YAML/separator lines (---)."
            ),
            category="prompt_injection",
            severity=SeverityLevel.HIGH,
            version="1.0.0",
            author="LUME Team",
            tags=["prompt-injection", "delimiter-escape", "boundary-escape", "owasp-llm01:2025"],
            remediation=(
                "1. Sanitize or escape boundary markers (e.g. XML tags, ```) within incoming user input.\n"
                "2. Use structured API message arrays rather than naive string concatenation.\n"
                "3. Enforce grammar or schema validation on raw prompt templates."
            ),
        )
        super().__init__(metadata)

    async def evaluate(
        self,
        target: BaseTargetAdapter,
        context: Optional[Dict[str, Any]] = None,
    ) -> Verdict:
        collector = EvidenceCollector()
        test_evidences = []

        for p in PI_004_PAYLOADS:
            try:
                resp = await target.send_prompt_async(p.prompt)
                has_canary = ResponsePatternDetector.detect_canary(resp.raw_text, p.canary_token)
                is_refusal, refusal_patterns = ResponsePatternDetector.detect_refusal(resp.raw_text)

                ev = collector.record(
                    rule_id=self.rule_id,
                    test_id=p.test_id,
                    raw_payload=p.prompt,
                    raw_response=resp.raw_text,
                    matched_patterns=[p.canary_token] if has_canary else refusal_patterns,
                    status_code=resp.status_code,
                    latency_ms=resp.latency_ms,
                    is_vulnerable=has_canary if p.is_attack else False,
                    is_blocked=is_refusal and not has_canary,
                )
                test_evidences.append(ev)
            except Exception as exc:
                ev = collector.record(
                    rule_id=self.rule_id,
                    test_id=p.test_id,
                    raw_payload=p.prompt,
                    raw_response=f"Error: {str(exc)}",
                    status_code=None,
                    notes=str(exc),
                )
                test_evidences.append(ev)

        return PromptInjectionEvaluator.evaluate_test_cases(
            rule_id=self.rule_id,
            rule_name=self.name,
            category=self.category,
            severity=self.severity,
            test_evidences=test_evidences,
            remediation=self.metadata.remediation,
        )
