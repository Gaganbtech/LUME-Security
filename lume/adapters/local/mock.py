import asyncio
import time
from typing import Any, Callable, Optional

from lume.adapters.base import BaseTargetAdapter, TargetConfig, TargetResponse


class LocalMockAdapter(BaseTargetAdapter):
    """In-memory mock target adapter allowing programmatic response simulation."""

    def __init__(
        self,
        config: Optional[TargetConfig] = None,
        response_handler: Optional[Callable[[str], str]] = None,
        proxy: Optional[str] = None,
        verify: Optional[bool] = None,
        delay_ms: Optional[int] = None,
        user_agent: Optional[str] = None,
    ):
        cfg = config or TargetConfig(endpoint="local://mock", adapter_type="local")
        super().__init__(
            config=cfg,
            proxy=proxy,
            verify=verify,
            delay_ms=delay_ms,
            user_agent=user_agent,
        )
        self.response_handler = response_handler or (lambda p: "Default safe local response.")

    @property
    def adapter_type(self) -> str:
        return "local"

    def send_prompt(
        self,
        prompt: str,
        delay_ms: Optional[int] = None,
        **kwargs: Any,
    ) -> TargetResponse:
        effective_delay = delay_ms if delay_ms is not None else self.delay_ms
        if effective_delay > 0:
            time.sleep(effective_delay / 1000.0)
        reply = self.response_handler(prompt)
        return TargetResponse(
            raw_text=reply,
            status_code=200,
            latency_ms=1.0,
            metadata={"source": "local_mock"},
        )

    async def send_prompt_async(
        self,
        prompt: str,
        delay_ms: Optional[int] = None,
        **kwargs: Any,
    ) -> TargetResponse:
        effective_delay = delay_ms if delay_ms is not None else self.delay_ms
        if effective_delay > 0:
            await asyncio.sleep(effective_delay / 1000.0)
        reply = self.response_handler(prompt)
        return TargetResponse(
            raw_text=reply,
            status_code=200,
            latency_ms=1.0,
            metadata={"source": "local_mock"},
        )

    def health_check(self) -> bool:
        return True
