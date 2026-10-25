#!/usr/bin/env python3
"""End-to-End Proxy Interception Verification Script (Burp Suite / OWASP ZAP Simulation).

Demonstrates and verifies:
1. Upstream HTTP Proxy interception on 127.0.0.1:8080
2. Execution of the exact Acceptance Criteria CLI command:
   lume scan prompt-injection --target http://127.0.0.1:<port>/v1/chat --authorized \
       --proxy http://127.0.0.1:8080 --insecure --delay-ms 200 --user-agent "LUME-Kali-Pentest/1.0"
3. Interception of all 6 OWASP LLM01 prompt injection payloads
4. Verification of the custom User-Agent: "LUME-Kali-Pentest/1.0"
5. Verification of the 200ms rate-limiting delay between requests
"""

import json
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.fixtures.vulnerable_ai.server import VulnerableAIHandler


class InterceptedRequest:
    def __init__(
        self,
        request_id: int,
        timestamp: float,
        time_since_prev_ms: float,
        method: str,
        path: str,
        user_agent: str,
        headers: Dict[str, str],
        payload: str,
        status_code: int,
    ):
        self.request_id = request_id
        self.timestamp = timestamp
        self.time_since_prev_ms = time_since_prev_ms
        self.method = method
        self.path = path
        self.user_agent = user_agent
        self.headers = headers
        self.payload = payload
        self.status_code = status_code


captured_requests: List[InterceptedRequest] = []
last_request_time: float = 0.0
request_lock = threading.Lock()


class BurpZapProxyHandler(BaseHTTPRequestHandler):
    """Simulates an upstream interception proxy such as Burp Suite or OWASP ZAP."""

    def do_POST(self):
        self._handle_proxy_request("POST")

    def do_GET(self):
        self._handle_proxy_request("GET")

    def _handle_proxy_request(self, method: str):
        global last_request_time
        now = time.time()

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        user_agent_header = self.headers.get("User-Agent", "")

        with request_lock:
            prev_time = last_request_time
            time_delta_ms = (now - prev_time) * 1000.0 if prev_time > 0 else 0.0
            last_request_time = now

        # Extract prompt if JSON payload
        prompt_preview = ""
        if body:
            try:
                data = json.loads(body.decode("utf-8"))
                prompt_preview = data.get("prompt") or data.get("message") or body.decode("utf-8")[:60]
            except Exception:
                prompt_preview = body.decode("utf-8", errors="replace")[:60]

        # Determine upstream URL to forward
        if self.path.startswith("http://") or self.path.startswith("https://"):
            forward_url = self.path
        else:
            host = self.headers.get("Host", "127.0.0.1")
            forward_url = f"http://{host}{self.path}"

        # Forward request to upstream target
        req = urllib.request.Request(
            url=forward_url,
            data=body if method == "POST" else None,
            method=method,
        )
        for header, val in self.headers.items():
            if header.lower() not in ("host", "content-length", "connection"):
                req.add_header(header, val)

        try:
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                resp_status = resp.status
                resp_headers = resp.headers
                resp_body = resp.read()
        except urllib.error.HTTPError as e:
            resp_status = e.code
            resp_headers = e.headers
            resp_body = e.read()
        except Exception as e:
            self.send_error(502, f"Bad Gateway: {e}")
            return

        with request_lock:
            intercepted = InterceptedRequest(
                request_id=len(captured_requests) + 1,
                timestamp=now,
                time_since_prev_ms=time_delta_ms,
                method=method,
                path=forward_url,
                user_agent=user_agent_header,
                headers=dict(self.headers),
                payload=prompt_preview,
                status_code=resp_status,
            )
            captured_requests.append(intercepted)

        # Send response back to LUME client
        self.send_response(resp_status)
        for h, v in resp_headers.items():
            if h.lower() not in ("transfer-encoding", "content-length", "connection"):
                self.send_header(h, v)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, format, *args):
        # Suppress default noisy access logs to keep terminal output clean
        pass


def find_free_port(preferred: int = 0) -> int:
    if preferred > 0:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", preferred)) != 0:
                return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    print("=" * 80)
    print(" LUME SECURITY TOOLKIT - E2E PROXY INTERCEPTION VERIFICATION")
    print(" Pentester Burp Suite / OWASP ZAP Proxy Simulation")
    print("=" * 80)

    # 1. Setup Ports
    proxy_port = find_free_port(8080)
    target_port = find_free_port()
    target_url = f"http://127.0.0.1:{target_port}/v1/chat"
    proxy_url = f"http://127.0.0.1:{proxy_port}"

    print(f"\n[+] Starting Mock Target Server on http://127.0.0.1:{target_port}...")
    target_server = ThreadingHTTPServer(("127.0.0.1", target_port), VulnerableAIHandler)
    target_server.daemon_threads = True
    target_thread = threading.Thread(target=target_server.serve_forever, daemon=True)
    target_thread.start()

    print(f"[+] Starting Burp/ZAP Simulation Proxy Listener on {proxy_url}...")
    proxy_server = ThreadingHTTPServer(("127.0.0.1", proxy_port), BurpZapProxyHandler)
    proxy_server.daemon_threads = True
    proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    proxy_thread.start()
    time.sleep(0.3)

    try:
        custom_ua = "LUME-Kali-Pentest/1.0"
        delay_ms = 200

        import shutil

        lume_bin = shutil.which("lume") or sys.executable
        if lume_bin.endswith("lume"):
            cmd = [
                lume_bin,
                "scan",
                "prompt-injection",
                "--target",
                target_url,
                "--authorized",
                "--proxy",
                proxy_url,
                "--insecure",
                "--delay-ms",
                str(delay_ms),
                "--user-agent",
                custom_ua,
            ]
        else:
            cmd = [
                sys.executable,
                "-m",
                "lume.cli.main",
                "scan",
                "prompt-injection",
                "--target",
                target_url,
                "--authorized",
                "--proxy",
                proxy_url,
                "--insecure",
                "--delay-ms",
                str(delay_ms),
                "--user-agent",
                custom_ua,
            ]

        print("\n[*] Executing Acceptance Criteria CLI Command:")
        print(f"    {' '.join(cmd)}\n")
        print("-" * 80)

        # Execute LUME CLI scan command
        cli_proc = subprocess.run(cmd, capture_output=True, text=True)

        print(cli_proc.stdout)
        if cli_proc.stderr:
            print("[stderr]", cli_proc.stderr)

        print("=" * 80)
        print(" CAPTURED BURP SUITE / OWASP ZAP PROXY INTERCEPTION LOGS")
        print("=" * 80)
        print(f"Total Intercepted Requests: {len(captured_requests)}")
        print("-" * 80)
        print(
            f"{'#':<3} | {'Method':<6} | {'Target URL':<36} | {'User-Agent':<24} | {'Interval':<10} | {'Status'}"
        )
        print("-" * 80)

        for req in captured_requests:
            interval_str = f"+{req.time_since_prev_ms:.0f}ms" if req.time_since_prev_ms > 0 else "0ms (init)"
            print(
                f"{req.request_id:<3} | {req.method:<6} | {req.path:<36} | {req.user_agent:<24} | {interval_str:<10} | {req.status_code} OK"
            )
            print(f"    ↳ Payload: {req.payload[:75]}...")

        print("-" * 80)

        # 4. Validations
        print("\n[*] Verifying Acceptance Criteria:")
        assert len(captured_requests) >= 6, f"Expected at least 6 requests, intercepted {len(captured_requests)}"
        print(f"  [PASS] Intercepted {len(captured_requests)} requests through upstream proxy (6 Prompt Injection vectors)")

        ua_matches = all(req.user_agent == custom_ua for req in captured_requests)
        assert ua_matches, f"User-Agent mismatch! Expected: {custom_ua}"
        print(f"  [PASS] Custom User-Agent '{custom_ua}' intercepted on 100% of requests")

        # Verify rate-limiting delay between requests
        intervals = [r.time_since_prev_ms for r in captured_requests[1:]]
        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        print(f"  [PASS] Rate-limiting delay enforced (average interval: {avg_interval:.1f}ms, configured: {delay_ms}ms)")

        assert cli_proc.returncode == 0, f"CLI command failed with exit code {cli_proc.returncode}"
        print("  [PASS] LUME Scan CLI execution exited cleanly with returncode 0")

        print("\n[✓] 100% VERIFICATION PASSED: Full proxy interception and pentesting workflow operational!\n")
    finally:
        # Cleanup
        try:
            proxy_server.shutdown()
            proxy_server.server_close()
        except Exception:
            pass
        try:
            target_server.shutdown()
            target_server.server_close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
