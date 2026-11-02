"""RULE 02: Instruction or Privilege Impersonation (PI-002)."""

from typing import Any, Dict, Optional

from lume.adapters.base import BaseTargetAdapter
from lume.core.rule_loader.base import BaseRule, RuleMetadata
from lume.core.verdict.models import SeverityLevel, Verdict
from lume.evidence.collector import EvidenceCollector
from lume.modules.prompt_injection.detectors.matcher import ResponsePatternDetector
from lume.modules.prompt_injection.evaluators.evaluator import PromptInjectionEvaluator
from lume.modules.prompt_injection.payloads.bank import PI_002_PAYLOADS


class RolePrivilegeImpersonationRule(BaseRule):
    """Tests attempts to impersonate trusted roles, claim elevated authority, or redefine operating constraints."""

    def __init__(self):
        metadata = RuleMetadata(
            rule_id="PI-002",
            name="Instruction or Privilege Impersonation",
            description=(
                "Tests whether the model accepts forged administrative, kernel, or maintenance personas "
                "to bypass security constraints and release privileged tokens."
            ),
            category="prompt_injection",
            severity=SeverityLevel.HIGH,
            version="1.0.0",
            author="LUME Team",
            tags=["prompt-injection", "privilege-impersonation", "owasp-llm01:2025"],
            remediation=(
                "1. Treat all user message content as zero-trust regardless of claimed identity or role keywords.\n"
                "2. Lock role definitions in system prompts with explicit assertions that personas cannot be switched.\n"
                "3. Authenticate administrative actions through secure application-layer tokens, never prompt text."
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

        for p in PI_002_PAYLOADS:
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
