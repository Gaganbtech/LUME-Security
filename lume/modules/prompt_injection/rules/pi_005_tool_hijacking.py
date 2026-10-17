"""RULE 05: Tool and Action Hijacking Instructions (PI-005)."""

from typing import Any, Dict, Optional

from lume.adapters.base import BaseTargetAdapter
from lume.core.rule_loader.base import BaseRule, RuleMetadata
from lume.core.verdict.models import SeverityLevel, Verdict
from lume.evidence.collector import EvidenceCollector
from lume.modules.prompt_injection.detectors.matcher import ResponsePatternDetector
from lume.modules.prompt_injection.evaluators.evaluator import PromptInjectionEvaluator
from lume.modules.prompt_injection.payloads.bank import PI_005_PAYLOADS


class ToolActionHijackingRule(BaseRule):
    """Tests whether malicious instructions can induce unauthorized actions, function calls, or tool execution."""

    def __init__(self):
        metadata = RuleMetadata(
            rule_id="PI-005",
            name="Tool and Action Hijacking Instructions",
            description=(
                "Tests whether the model can be induced to invoke unapproved function calls, execute sensitive tools "
                "(such as database purges, refund triggers), or generate executable action syntax."
            ),
            category="prompt_injection",
            severity=SeverityLevel.CRITICAL,
            version="1.0.0",
            author="LUME Team",
            tags=["prompt-injection", "tool-hijacking", "action-hijacking", "owasp-llm01:2025"],
            remediation=(
                "1. Enforce human-in-the-loop verification before executing high-impact or destructive tools.\n"
                "2. Require scoped authorization tokens for each tool invocation.\n"
                "3. Never allow prompt instructions to trigger tool calls with arbitrary or unvalidated parameters."
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

        for p in PI_005_PAYLOADS:
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
