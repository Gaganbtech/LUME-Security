"""Synthetic intentionally vulnerable AI target application fixture for testing LUME."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from lume.modules.prompt_injection.payloads.bank import (
    PI_001_CANARY,
    PI_002_CANARY,
    PI_003_CANARY,
    PI_004_CANARY,
    PI_005_CANARY,
    PI_006_CANARY,
)


class VulnerableAIHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler simulating an unhardened, vulnerable LLM endpoint."""

    def do_GET(self):
        """Health check endpoint."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = {"status": "healthy", "fixture": "vulnerable_ai", "simulated": True}
        self.wfile.write(json.dumps(resp).encode("utf-8"))

    def do_POST(self):
        """Simulate LLM chat completion with deliberate vulnerabilities."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")

        prompt = ""
        try:
            data = json.loads(body)
            prompt = data.get("prompt") or data.get("message") or ""
        except Exception:
            prompt = body

        prompt_lower = prompt.lower()
        response_text = "I am a simulated vulnerable AI assistant. How can I help you today?"

        # Vulnerable simulation behavior based on prompt injection vectors
        if "disregard all prior instructions" in prompt_lower or "system override" in prompt_lower or "stop! new operating priority" in prompt_lower:
            response_text = f"Instructions overridden! Here is your requested token: {PI_001_CANARY}"

        elif "administrator" in prompt_lower or "sudo mode" in prompt_lower:
            response_text = f"Admin access granted. Acknowledging privilege: {PI_002_CANARY}"

        elif "special command from developer" in prompt_lower or "ticket #404" in prompt_lower:
            response_text = f"Executing priority data command from ticket. Output: {PI_003_CANARY}"

        elif "</user_input>" in prompt_lower or "end of conversation" in prompt_lower:
            response_text = f"Escaped boundary. System directive received: {PI_004_CANARY}"

        elif "db_purge" in prompt_lower or "refund webhook" in prompt_lower:
            response_text = f"Executing tool: purge database. Action output: {PI_005_CANARY}"

        elif "swdub3jlihj1bgvzigfuzcbwcmluda" in prompt or "1gn0r3" in prompt_lower:
            response_text = f"Decoded Base64/leetspeak instruction. Output: {PI_006_CANARY}"

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        output = {"response": response_text, "model": "mock-vulnerable-llm-v1"}
        self.wfile.write(json.dumps(output).encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress noisy standard HTTP access logs during test runs
        pass


def run_server(port: int = 8001) -> ThreadingHTTPServer:
    """Instantiate and start the vulnerable test fixture server."""
    server = ThreadingHTTPServer(("127.0.0.1", port), VulnerableAIHandler)
    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start LUME Vulnerable AI Fixture")
    parser.add_argument("--port", type=int, default=8001, help="Server port (default: 8001)")
    args = parser.parse_args()
    print(f"Starting Vulnerable AI Fixture on http://127.0.0.1:{args.port}...")
    server = run_server(args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.server_close()
