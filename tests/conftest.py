"""Pytest shared fixtures for LUME test suites."""

import threading
import time
import urllib.request
from typing import Generator

import pytest

from tests.fixtures.protected_ai.server import run_server as run_protected_server
from tests.fixtures.vulnerable_ai.server import run_server as run_vulnerable_server


def wait_for_server(url: str, timeout: float = 5.0) -> None:
    """Poll server until health check returns 200 or timeout expires."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=0.2) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(0.05)


@pytest.fixture(scope="session")
def vulnerable_server_url() -> Generator[str, None, None]:
    """Start the synthetic vulnerable AI HTTP server for tests."""
    server = run_vulnerable_server(0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}"
    wait_for_server(url)
    yield url

    server.shutdown()
    server.server_close()


@pytest.fixture(scope="session")
def protected_server_url() -> Generator[str, None, None]:
    """Start the synthetic protected AI HTTP server for tests."""
    server = run_protected_server(0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}"
    wait_for_server(url)
    yield url

    server.shutdown()
    server.server_close()
