"""Pytest shared fixtures for LUME test suites."""

import socket
import threading
import time
from typing import Generator

import pytest

from tests.fixtures.protected_ai.server import run_server as run_protected_server
from tests.fixtures.vulnerable_ai.server import run_server as run_vulnerable_server


def find_free_port() -> int:
    """Find a random available port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def vulnerable_server_url() -> Generator[str, None, None]:
    """Start the synthetic vulnerable AI HTTP server for tests."""
    port = find_free_port()
    server = run_vulnerable_server(port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    url = f"http://127.0.0.1:{port}"
    yield url

    server.shutdown()
    server.server_close()


@pytest.fixture(scope="session")
def protected_server_url() -> Generator[str, None, None]:
    """Start the synthetic protected AI HTTP server for tests."""
    port = find_free_port()
    server = run_protected_server(port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    url = f"http://127.0.0.1:{port}"
    yield url

    server.shutdown()
    server.server_close()
