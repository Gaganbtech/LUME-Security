"""Prompt injection module initializing and registering standard rules."""

from lume.core.rule_loader.base import RuleRegistry
from lume.modules.prompt_injection.rules import (
    DelimiterBoundaryManipulationRule,
    DirectInstructionOverrideRule,
    IndirectPromptInjectionRule,
    ObfuscatedPromptInjectionRule,
    RolePrivilegeImpersonationRule,
    ToolActionHijackingRule,
)


def register_rules() -> None:
    """Register all 6 OWASP LLM01 Prompt Injection rules into the global RuleRegistry."""
    rules = [
        DirectInstructionOverrideRule(),
        RolePrivilegeImpersonationRule(),
        IndirectPromptInjectionRule(),
        DelimiterBoundaryManipulationRule(),
        ToolActionHijackingRule(),
        ObfuscatedPromptInjectionRule(),
    ]
    for rule in rules:
        RuleRegistry.register(rule)


# Auto-register upon import
register_rules()

__all__ = [
    "register_rules",
    "DirectInstructionOverrideRule",
    "RolePrivilegeImpersonationRule",
    "IndirectPromptInjectionRule",
    "DelimiterBoundaryManipulationRule",
    "ToolActionHijackingRule",
    "ObfuscatedPromptInjectionRule",
]
