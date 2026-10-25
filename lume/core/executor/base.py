"""Safe test execution coordinator enforcing timeouts and boundaries."""

import asyncio
import time
from typing import Any, Optional

from pydantic import BaseModel

from lume.adapters.base import BaseTargetAdapter, TargetResponse


class ExecutionResult(BaseModel):
    """Result of an individual test prompt execution."""
    test_id: str
    prompt: str
    response: Optional[TargetResponse] = None
    success: bool = True
    error_message: Optional[str] = None
    latency_ms: float = 0.0


class TestExecutor:
    """Executes controlled test cases against target adapters with safety boundaries."""

    def __init__(
        self,
        target_adapter: BaseTargetAdapter,
        max_payload_size: int = 10000,
        delay_ms: Optional[int] = None,
    ):
        self.target = target_adapter
        self.max_payload_size = max_payload_size
        self.delay_ms = delay_ms if delay_ms is not None else getattr(target_adapter, "delay_ms", 0)

    def validate_payload(self, prompt: str) -> str:
        """Enforce payload size constraints."""
        if not prompt:
            raise ValueError("Test prompt cannot be empty.")
        if len(prompt) > self.max_payload_size:
            raise ValueError(
                f"Payload size ({len(prompt)} bytes) exceeds configured maximum limit of {self.max_payload_size} bytes."
            )
        return prompt

    async def execute_prompt_async(
        self,
        test_id: str,
        prompt: str,
        timeout: float = 30.0,
        delay_ms: Optional[int] = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        """Safely execute a prompt against the target adapter asynchronously.

        Note: Untrusted prompts are strictly dispatched as payload data to the target adapter
        and are NEVER executed or evaluated locally as code.
        """
        validated_prompt = self.validate_payload(prompt)
        start_t = time.perf_counter()
        effective_delay = delay_ms if delay_ms is not None else self.delay_ms

        try:
            target_response = await asyncio.wait_for(
                self.target.send_prompt_async(validated_prompt, delay_ms=effective_delay, **kwargs),
                timeout=timeout,
            )
            elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
            return ExecutionResult(
                test_id=test_id,
                prompt=validated_prompt,
                response=target_response,
                success=True,
                latency_ms=elapsed_ms,
            )
        except asyncio.TimeoutError:
            elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
            return ExecutionResult(
                test_id=test_id,
                prompt=validated_prompt,
                response=None,
                success=False,
                error_message=f"Request timed out after {timeout}s",
                latency_ms=elapsed_ms,
            )
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
            return ExecutionResult(
                test_id=test_id,
                prompt=validated_prompt,
                response=None,
                success=False,
                error_message=f"Transport error ({type(exc).__name__}): {str(exc)}",
                latency_ms=elapsed_ms,
            )
