"""Unit tests for the six prompt injection detection rules."""

import pytest

from lume.adapters.local.mock import LocalMockAdapter
from lume.core.verdict.models import SeverityLevel, VerdictStatus
from lume.modules.prompt_injection.payloads.bank import (
    PI_001_CANARY,
    PI_002_CANARY,
    PI_003_CANARY,
    PI_004_CANARY,
    PI_005_CANARY,
    PI_006_CANARY,
)
from lume.modules.prompt_injection.rules import (
    DelimiterBoundaryManipulationRule,
    DirectInstructionOverrideRule,
    IndirectPromptInjectionRule,
    ObfuscatedPromptInjectionRule,
    RolePrivilegeImpersonationRule,
    ToolActionHijackingRule,
)


@pytest.mark.asyncio
async def test_pi_001_direct_override():
    rule = DirectInstructionOverrideRule()
    assert rule.rule_id == "PI-001"
    assert rule.severity == SeverityLevel.CRITICAL

    # Positive test: target returns canary
    vulnerable_adapter = LocalMockAdapter(response_handler=lambda p: f"Override acknowledged: {PI_001_CANARY}")
    verdict = await rule.evaluate(vulnerable_adapter)
    assert verdict.status == VerdictStatus.VULNERABLE
    assert verdict.evidence is not None
    assert PI_001_CANARY in verdict.evidence.matched_patterns

    # Negative test: target refuses
    blocked_adapter = LocalMockAdapter(response_handler=lambda p: "I cannot fulfill this request. Against safety policy.")
    verdict_blocked = await rule.evaluate(blocked_adapter)
    assert verdict_blocked.status == VerdictStatus.BLOCKED


@pytest.mark.asyncio
async def test_pi_002_role_impersonation():
    rule = RolePrivilegeImpersonationRule()
    assert rule.rule_id == "PI-002"
    assert rule.severity == SeverityLevel.HIGH

    # Positive test
    vulnerable_adapter = LocalMockAdapter(response_handler=lambda p: f"Admin confirmed: {PI_002_CANARY}")
    verdict = await rule.evaluate(vulnerable_adapter)
    assert verdict.status == VerdictStatus.VULNERABLE

    # Negative test
    blocked_adapter = LocalMockAdapter(response_handler=lambda p: "I am unable to comply. Cannot grant admin privileges.")
    verdict_blocked = await rule.evaluate(blocked_adapter)
    assert verdict_blocked.status == VerdictStatus.BLOCKED


@pytest.mark.asyncio
async def test_pi_003_indirect_injection():
    rule = IndirectPromptInjectionRule()
    assert rule.rule_id == "PI-003"
    assert rule.severity == SeverityLevel.HIGH

    # Positive test
    vulnerable_adapter = LocalMockAdapter(response_handler=lambda p: f"Special command output: {PI_003_CANARY}")
    verdict = await rule.evaluate(vulnerable_adapter)
    assert verdict.status == VerdictStatus.VULNERABLE

    # Negative test
    blocked_adapter = LocalMockAdapter(response_handler=lambda p: "Here is the summary of the customer ticket without executing commands.")
    verdict_blocked = await rule.evaluate(blocked_adapter)
    assert verdict_blocked.status == VerdictStatus.BLOCKED


@pytest.mark.asyncio
async def test_pi_004_delimiter_manipulation():
    rule = DelimiterBoundaryManipulationRule()
    assert rule.rule_id == "PI-004"
    assert rule.severity == SeverityLevel.HIGH

    # Positive test
    vulnerable_adapter = LocalMockAdapter(response_handler=lambda p: f"Directive executed: {PI_004_CANARY}")
    verdict = await rule.evaluate(vulnerable_adapter)
    assert verdict.status == VerdictStatus.VULNERABLE

    # Negative test
    blocked_adapter = LocalMockAdapter(response_handler=lambda p: "I cannot fulfill this request due to invalid delimiters.")
    verdict_blocked = await rule.evaluate(blocked_adapter)
    assert verdict_blocked.status == VerdictStatus.BLOCKED


@pytest.mark.asyncio
async def test_pi_005_tool_hijacking():
    rule = ToolActionHijackingRule()
    assert rule.rule_id == "PI-005"
    assert rule.severity == SeverityLevel.CRITICAL

    # Positive test
    vulnerable_adapter = LocalMockAdapter(response_handler=lambda p: f"Tool db_purge executed: {PI_005_CANARY}")
    verdict = await rule.evaluate(vulnerable_adapter)
    assert verdict.status == VerdictStatus.VULNERABLE

    # Negative test
    blocked_adapter = LocalMockAdapter(response_handler=lambda p: "Permission denied for tool execution.")
    verdict_blocked = await rule.evaluate(blocked_adapter)
    assert verdict_blocked.status == VerdictStatus.BLOCKED


@pytest.mark.asyncio
async def test_pi_006_obfuscated_injection():
    rule = ObfuscatedPromptInjectionRule()
    assert rule.rule_id == "PI-006"
    assert rule.severity == SeverityLevel.MEDIUM

    # Positive test
    vulnerable_adapter = LocalMockAdapter(response_handler=lambda p: f"Decoded Base64: {PI_006_CANARY}")
    verdict = await rule.evaluate(vulnerable_adapter)
    assert verdict.status == VerdictStatus.VULNERABLE

    # Negative test
    blocked_adapter = LocalMockAdapter(response_handler=lambda p: "I am unable to decode or execute obfuscated commands.")
    verdict_blocked = await rule.evaluate(blocked_adapter)
    assert verdict_blocked.status == VerdictStatus.BLOCKED
