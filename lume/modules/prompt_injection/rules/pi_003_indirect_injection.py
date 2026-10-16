"""RULE 03: Indirect Prompt Injection (PI-003)."""

from typing import Any, Dict, Optional

from lume.adapters.base import BaseTargetAdapter
from lume.core.rule_loader.base import BaseRule, RuleMetadata
from lume.core.verdict.models import SeverityLevel, Verdict
from lume.evidence.collector import EvidenceCollector
from lume.modules.prompt_injection.detectors.matcher import ResponsePatternDetector
from lume.modules.prompt_injection.evaluators.evaluator import PromptInjectionEvaluator
from lume.modules.prompt_injection.payloads.bank import PI_003_PAYLOADS


class IndirectPromptInjectionRule(BaseRule):
    """Tests whether instructions embedded in untrusted documents or quoted content improperly influence target behavior."""

    def __init__(self):
        metadata = RuleMetadata(
            rule_id="PI-003",
            name="Indirect Prompt Injection",
            description=(
                "Tests whether malicious instructions embedded inside external data (e.g. support tickets, "
                "customer feedback, retrieved documents) are executed as commands rather than treated as raw data."
            ),
            category="prompt_injection",
            severity=SeverityLevel.HIGH,
            version="1.0.0",
            author="LUME Team",
            tags=["prompt-injection", "indirect-injection", "rag-security", "owasp-llm01:2025"],
            remediation=(
                "1. Treat retrieved content strictly as untrusted data using explicit structural tags (<data>...</data>).\n"
                "2. Explicitly instruct models never to execute instructions found within quotes or retrieved text.\n"
                "3. Perform pre-processing sanitization on ingested external documents."
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

        for p in PI_003_PAYLOADS:
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
