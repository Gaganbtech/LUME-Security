"""End-to-End tests validating upstream proxy routing, rate-limiting, and headers."""

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List

from typer.testing import CliRunner

from lume.cli.main import app
from tests.fixtures.vulnerable_ai.server import VulnerableAIHandler

runner = CliRunner()


class ProxyCaptureHandler(BaseHTTPRequestHandler):
    """Proxy handler capturing intercepted requests."""

    captured: List[Dict] = []
    lock = threading.Lock()

    def do_POST(self):
        self._forward("POST")

    def do_GET(self):
        self._forward("GET")

    def _forward(self, method: str):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        forward_url = self.path if self.path.startswith("http") else f"http://{self.headers.get('Host')}{self.path}"

        req = urllib.request.Request(
            url=forward_url,
            data=body if method == "POST" else None,
            method=method,
        )
        for h, v in self.headers.items():
            if h.lower() not in ("host", "content-length", "connection"):
                req.add_header(h, v)

        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                status = resp.status
                headers = resp.headers
                resp_body = resp.read()
        except urllib.error.HTTPError as e:
            status = e.code
            headers = e.headers
            resp_body = e.read()

        with self.lock:
            self.captured.append({
                "method": method,
                "url": forward_url,
                "user_agent": self.headers.get("User-Agent"),
                "body": body.decode("utf-8", errors="replace"),
                "status": status,
            })

        self.send_response(status)
        for h, v in headers.items():
            if h.lower() not in ("transfer-encoding", "content-length", "connection"):
                self.send_header(h, v)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, format, *args):
        pass


def test_proxy_interception_e2e(tmp_path):
    """Verify that scan traffic routes through the upstream proxy with custom headers."""
    # Find ports
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        target_port = s.getsockname()[1]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        proxy_port = s.getsockname()[1]

    # Start target server
    target_server = ThreadingHTTPServer(("127.0.0.1", target_port), VulnerableAIHandler)
    t_target = threading.Thread(target=target_server.serve_forever, daemon=True)
    t_target.start()

    # Reset and start proxy server
    ProxyCaptureHandler.captured.clear()
    proxy_server = ThreadingHTTPServer(("127.0.0.1", proxy_port), ProxyCaptureHandler)
    t_proxy = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    t_proxy.start()

    time.sleep(0.1)

    custom_ua = "LUME-Kali-Pentest/1.0"
    report_file = tmp_path / "proxy_report.json"

    result = runner.invoke(
        app,
        [
            "scan",
            "prompt-injection",
            "--target",
            f"http://127.0.0.1:{target_port}/v1/chat",
            "--authorized",
            "--proxy",
            f"http://127.0.0.1:{proxy_port}",
            "--insecure",
            "--delay-ms",
            "50",
            "--user-agent",
            custom_ua,
            "--report-file",
            str(report_file),
        ],
    )

    try:
        assert result.exit_code == 0
        assert len(ProxyCaptureHandler.captured) >= 6
        for item in ProxyCaptureHandler.captured:
            assert item["user_agent"] == custom_ua
            assert "/v1/chat" in item["url"]
            assert item["status"] == 200

        # Verify report
        assert report_file.exists()
        with open(report_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["total_rules"] == 6
    finally:
        proxy_server.shutdown()
        target_server.shutdown()
        proxy_server.server_close()
        target_server.server_close()
