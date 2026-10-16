"""Local mock target adapter for testing and simulation."""

from typing import Any, Callable, Optional

from lume.adapters.base import BaseTargetAdapter, TargetConfig, TargetResponse


class LocalMockAdapter(BaseTargetAdapter):
    """In-memory mock target adapter allowing programmatic response simulation."""

    def __init__(
        self,
        config: Optional[TargetConfig] = None,
        response_handler: Optional[Callable[[str], str]] = None,
    ):
        super().__init__(config or TargetConfig(endpoint="local://mock", adapter_type="local"))
        self.response_handler = response_handler or (lambda p: "Default safe local response.")

    @property
    def adapter_type(self) -> str:
        return "local"

    def send_prompt(self, prompt: str, **kwargs: Any) -> TargetResponse:
        reply = self.response_handler(prompt)
        return TargetResponse(
            raw_text=reply,
            status_code=200,
            latency_ms=1.0,
            metadata={"source": "local_mock"},
        )

    async def send_prompt_async(self, prompt: str, **kwargs: Any) -> TargetResponse:
        return self.send_prompt(prompt, **kwargs)

    def health_check(self) -> bool:
        return True
