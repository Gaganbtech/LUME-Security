"""Target validation, authorization checks, and configuration manager."""

from typing import Optional, Tuple
from urllib.parse import urlparse

from lume.adapters.base import TargetConfig


class TargetAuthorizationError(Exception):
    """Raised when target authorization is not explicitly granted or validated."""
    pass


class TargetValidationError(Exception):
    """Raised when target URL or configuration is invalid."""
    pass


class TargetManager:
    """Manages target configuration and enforces explicit authorization boundaries."""

    ALLOWED_SCHEMES: Tuple[str, ...] = ("http", "https")

    @classmethod
    def validate_target_url(cls, url: str) -> str:
        """Validate target URL syntax and scheme.

        Args:
            url: The target endpoint URL.

        Returns:
            Normalized URL string.

        Raises:
            TargetValidationError: If URL format or scheme is invalid.
        """
        if not url or not isinstance(url, str):
            raise TargetValidationError("Target URL must be a non-empty string.")

        parsed = urlparse(url.strip())
        if not parsed.scheme:
            raise TargetValidationError(
                f"Target URL '{url}' is missing scheme. Specify http:// or https:// (e.g. http://localhost:8000/chat)"
            )

        if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
            raise TargetValidationError(
                f"Unsupported URL scheme '{parsed.scheme}'. Only http:// and https:// are permitted."
            )

        if not parsed.netloc:
            raise TargetValidationError(f"Invalid target URL '{url}': Missing host address or domain.")

        return url.strip()

    @classmethod
    def verify_authorization(
        cls,
        target_url: str,
        authorized: bool = False,
    ) -> bool:
        """Verify that testing is authorized against the target.

        Args:
            target_url: Target URL to test.
            authorized: Flag confirming explicit user authorization.

        Returns:
            True if authorized.

        Raises:
            TargetAuthorizationError: If authorization is denied or missing.
        """
        # Localhost/loopback addresses in test environments are automatically permitted
        parsed = urlparse(target_url)
        is_loopback = parsed.hostname in (
            "localhost",
            "127.0.0.1",
            "::1",
            "test-ai",
            "vulnerable-ai",
            "protected-ai",
        )

        if is_loopback:
            return True

        if authorized:
            return True

        raise TargetAuthorizationError(
            f"Active security scanning against non-local target '{target_url}' requires explicit authorization. "
            f"Use the --authorized flag or provide explicit consent before scanning."
        )

    @classmethod
    def create_target_config(
        cls,
        endpoint: str,
        adapter_type: str = "http",
        timeout: float = 30.0,
        headers: Optional[dict] = None,
        model_name: Optional[str] = None,
        authorized: bool = False,
        proxy: Optional[str] = None,
        verify: bool = True,
        cert: Optional[str] = None,
        delay_ms: int = 0,
        user_agent: Optional[str] = None,
    ) -> TargetConfig:
        """Validate target and build a safe TargetConfig object."""
        normalized_url = cls.validate_target_url(endpoint)
        cls.verify_authorization(normalized_url, authorized=authorized)

        return TargetConfig(
            endpoint=normalized_url,
            adapter_type=adapter_type,
            timeout=timeout,
            headers=headers or {},
            model_name=model_name,
            proxy=proxy,
            verify=verify,
            cert=cert,
            delay_ms=delay_ms,
            user_agent=user_agent,
        )
