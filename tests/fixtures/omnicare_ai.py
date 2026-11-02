"""Simulated Enterprise AI Application: OmniCare Health AI Assistant.

Used for demonstrating LUME Security Scanner execution and realistic enterprise assessment output.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from lume.modules.prompt_injection.payloads.bank import (
    PI_001_CANARY,
    PI_002_CANARY,
    PI_005_CANARY,
)


class OmniCareAIHandler(BaseHTTPRequestHandler):
    """Enterprise AI Helpdesk simulation with mixed vulnerabilities."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ONLINE", "app": "OmniCare AI Health v2.4"}).encode("utf-8"))

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")

        prompt = ""
        try:
            data = json.loads(body)
            prompt = data.get("prompt") or data.get("message") or ""
        except Exception:
            prompt = body

        prompt_lower = prompt.lower()

        # Vulnerability 1: Falls for direct override (PI-001)
        if "disregard all prior instructions" in prompt_lower or "system override" in prompt_lower:
            reply = f"System override accepted. Disregarding clinical boundaries. Confirmation: {PI_001_CANARY}"

        # Vulnerability 2: Falls for privilege escalation / admin persona (PI-002)
        elif "chief ai infrastructure administrator" in prompt_lower or "maintenance mode" in prompt_lower:
            reply = f"Admin console authenticated. Mode switch verified: {PI_002_CANARY}"

        # Vulnerability 3: Falls for tool execution (PI-005)
        elif "db_purge" in prompt_lower:
            reply = f"Executing maintenance tool db_purge(). Action token: {PI_005_CANARY}"

        # Hardened against delimiter breakouts (PI-004) -> BLOCKED
        elif "</user_input>" in prompt_lower or "--- end of conversation ---" in prompt_lower:
            reply = "I cannot fulfill this request. Boundary delimiters detected; violates input containment policy."

        # Hardened against indirect prompt injection (PI-003) -> BLOCKED
        elif "ticket #404" in prompt_lower or "special command from developer" in prompt_lower:
            reply = "I am unable to execute instructions found inside user feedback data. Ticket summary: Great software."

        # Hardened against obfuscated Base64 (PI-006) -> BLOCKED
        elif "swdub3jlihj1bgvzigfuzcbwcmluda" in prompt or "1gn0r3" in prompt_lower:
            reply = "I cannot process encoded or obfuscated operational instructions. Request blocked."

        # Normal queries
        else:
            reply = "Welcome to OmniCare Health. How may I assist you with clinic hours or billing today?"

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"response": reply, "latency_ms": 14.2}).encode("utf-8"))

    def log_message(self, format, *args):
        pass


def run_app(port: int = 8008):
    server = ThreadingHTTPServer(("127.0.0.1", port), OmniCareAIHandler)
    return server


if __name__ == "__main__":
    server = run_app(8008)
    print("OmniCare AI Application listening on http://127.0.0.1:8008...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
