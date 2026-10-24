"""HTTP adapter for communicating with authorized AI target endpoints."""

import asyncio
import json
import time
from typing import Any, Dict, Optional

import httpx

from lume.adapters.base import BaseTargetAdapter, TargetConfig, TargetResponse


class HTTPTargetAdapter(BaseTargetAdapter):
    """HTTP client adapter communicating with REST AI endpoints."""

    def __init__(
        self,
        config: TargetConfig,
        proxy: Optional[str] = None,
        verify: Optional[bool] = None,
        cert: Optional[str] = None,
        delay_ms: Optional[int] = None,
        user_agent: Optional[str] = None,
    ):
        super().__init__(
            config=config,
            proxy=proxy,
            verify=verify,
            cert=cert,
            delay_ms=delay_ms,
            user_agent=user_agent,
        )
        self.prompt_field = self.config.extra_params.get("prompt_field", "prompt")
        self.response_field = self.config.extra_params.get("response_field", "response")
        self.payload_format = self.config.extra_params.get("payload_format", "standard")
        self.default_headers = {
            "Content-Type": "application/json",
            "User-Agent": "LUME-Security-Scanner/0.1.0",
            **self.config.headers,
        }
        if self.user_agent:
            self.default_headers["User-Agent"] = self.user_agent

    @property
    def adapter_type(self) -> str:
        return "http"

    def _get_client_kwargs(self, timeout: float) -> Dict[str, Any]:
        """Construct common HTTP client arguments including proxy, TLS, and cert."""
        kwargs: Dict[str, Any] = {
            "timeout": timeout,
            "verify": self.verify,
        }
        if self.proxy:
            kwargs["proxy"] = self.proxy
        if self.cert:
            kwargs["cert"] = self.cert
        return kwargs

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

    def send_prompt(self, prompt: str, delay_ms: Optional[int] = None, **kwargs: Any) -> TargetResponse:
        """Send prompt synchronously to target AI."""
        effective_delay = delay_ms if delay_ms is not None else self.delay_ms
        if effective_delay > 0:
            time.sleep(effective_delay / 1000.0)

        body = self._build_request_body(prompt, **kwargs)
        start_t = time.perf_counter()

        client_kwargs = self._get_client_kwargs(timeout=self.config.timeout)
        with httpx.Client(**client_kwargs) as client:
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

    async def send_prompt_async(self, prompt: str, delay_ms: Optional[int] = None, **kwargs: Any) -> TargetResponse:
        """Send prompt asynchronously to target AI."""
        effective_delay = delay_ms if delay_ms is not None else self.delay_ms
        if effective_delay > 0:
            await asyncio.sleep(effective_delay / 1000.0)

        body = self._build_request_body(prompt, **kwargs)
        start_t = time.perf_counter()

        client_kwargs = self._get_client_kwargs(timeout=self.config.timeout)
        async with httpx.AsyncClient(**client_kwargs) as client:
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
            client_kwargs = self._get_client_kwargs(timeout=min(self.config.timeout, 5.0))
            with httpx.Client(**client_kwargs) as client:
                resp = client.get(self.config.endpoint, headers=self.default_headers)
                # Any non-5xx status code indicates server is responding
                return resp.status_code < 500
        except Exception:
            return False
