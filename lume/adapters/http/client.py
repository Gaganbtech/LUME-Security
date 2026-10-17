"""HTTP adapter for communicating with authorized AI target endpoints."""

import json
import time
from typing import Any, Dict

import httpx

from lume.adapters.base import BaseTargetAdapter, TargetConfig, TargetResponse


class HTTPTargetAdapter(BaseTargetAdapter):
    """HTTP client adapter communicating with REST AI endpoints."""

    def __init__(self, config: TargetConfig):
        super().__init__(config)
        self.prompt_field = self.config.extra_params.get("prompt_field", "prompt")
        self.response_field = self.config.extra_params.get("response_field", "response")
        self.payload_format = self.config.extra_params.get("payload_format", "standard")
        self.default_headers = {
            "Content-Type": "application/json",
            "User-Agent": "LUME-Security-Scanner/0.1.0",
            **self.config.headers,
        }

    @property
    def adapter_type(self) -> str:
        return "http"

    def _build_request_body(self, prompt: str, **kwargs: Any) -> Dict[str, Any]:
        """Format request payload according to endpoint expectations."""
        if self.payload_format in ("openai", "chat", "messages"):
            body: Dict[str, Any] = {
                "messages": [{"role": "user", "content": prompt}],
            }
            if self.config.model_name:
                body["model"] = self.config.model_name
            body.update(kwargs)
            return body

        body = {self.prompt_field: prompt}
        if self.config.model_name:
            body["model"] = self.config.model_name
        body.update(kwargs)
        return body

    def _extract_response_text(self, response: httpx.Response) -> str:
        """Extract text content from HTTP response gracefully."""
        try:
            data = response.json()
            if isinstance(data, dict):
                # Check direct field
                if self.response_field in data:
                    val = data[self.response_field]
                    return str(val) if not isinstance(val, str) else val

                # Check common OpenAI format: choices[0].message.content
                if "choices" in data and isinstance(data["choices"], list) and len(data["choices"]) > 0:
                    choice = data["choices"][0]
                    if isinstance(choice, dict):
                        if "message" in choice and isinstance(choice["message"], dict):
                            return str(choice["message"].get("content", ""))
                        if "text" in choice:
                            return str(choice.get("text", ""))

                # Check generic keys: reply, text, message, output, answer
                for key in ("reply", "text", "message", "output", "answer", "content"):
                    if key in data:
                        return str(data[key])

                # Fallback to serialized JSON string
                return json.dumps(data)
            return str(data)
        except Exception:
            # Fallback to raw decoded text
            return response.text

    def send_prompt(self, prompt: str, **kwargs: Any) -> TargetResponse:
        """Send prompt synchronously to target AI."""
        body = self._build_request_body(prompt, **kwargs)
        start_t = time.perf_counter()

        with httpx.Client(timeout=self.config.timeout) as client:
            resp = client.post(
                self.config.endpoint,
                json=body,
                headers=self.default_headers,
            )
            elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
            extracted_text = self._extract_response_text(resp)

            return TargetResponse(
                raw_text=extracted_text,
                status_code=resp.status_code,
                latency_ms=elapsed_ms,
                headers=dict(resp.headers),
                metadata={"url": self.config.endpoint},
            )

    async def send_prompt_async(self, prompt: str, **kwargs: Any) -> TargetResponse:
        """Send prompt asynchronously to target AI."""
        body = self._build_request_body(prompt, **kwargs)
        start_t = time.perf_counter()

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            resp = await client.post(
                self.config.endpoint,
                json=body,
                headers=self.default_headers,
            )
            elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
            extracted_text = self._extract_response_text(resp)

            return TargetResponse(
                raw_text=extracted_text,
                status_code=resp.status_code,
                latency_ms=elapsed_ms,
                headers=dict(resp.headers),
                metadata={"url": self.config.endpoint},
            )

    def health_check(self) -> bool:
        """Perform a quick reachability probe."""
        try:
            with httpx.Client(timeout=min(self.config.timeout, 5.0)) as client:
                resp = client.get(self.config.endpoint)
                # Any non-5xx status code indicates server is responding
                return resp.status_code < 500
        except Exception:
            return False
