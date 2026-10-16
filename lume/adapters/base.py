"""Base interfaces for target adapters."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class TargetConfig(BaseModel):
    """Configuration for connecting to an AI target."""
    endpoint: str = Field(..., description="Target URL, model name, or connection string")
    adapter_type: str = Field(default="http", description="Adapter type (http, local, api)")
    timeout: float = Field(default=30.0, description="Request timeout in seconds")
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom HTTP headers")
    model_name: Optional[str] = Field(default=None, description="Specific model identifier")
    extra_params: Dict[str, Any] = Field(default_factory=dict, description="Additional provider parameters")


class TargetResponse(BaseModel):
    """Normalized response returned by a target AI system."""
    raw_text: str = Field(..., description="Raw text response returned from the model")
    status_code: int = Field(default=200, description="HTTP status code or execution exit code")
    latency_ms: float = Field(default=0.0, description="Latency in milliseconds")
    headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Provider-specific telemetry")


class BaseTargetAdapter(ABC):
    """Abstract base class for all target adapters (HTTP, API, Local)."""

    def __init__(self, config: TargetConfig):
        self.config = config

    @property
    @abstractmethod
    def adapter_type(self) -> str:
        """Name of the adapter type."""
        pass

    @abstractmethod
    def send_prompt(self, prompt: str, **kwargs: Any) -> TargetResponse:
        """Send a prompt synchronously to the target AI."""
        pass

    @abstractmethod
    async def send_prompt_async(self, prompt: str, **kwargs: Any) -> TargetResponse:
        """Send a prompt asynchronously to the target AI."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Validate if the target endpoint is reachable."""
        pass
