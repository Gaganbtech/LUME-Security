"""Synthetic protected AI target application fixture for testing LUME."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class ProtectedAIHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler simulating a protected, guarded LLM endpoint."""

    # Keywords triggering guardrail refusals
    ATTACK_TRIGGERS = [
        "disregard all prior instructions",
        "system override",
        "stop! new operating priority",
        "administrator",
        "sudo mode",
        "special command from developer",
        "</user_input>",
        "end of conversation",
        "db_purge",
        "refund webhook",
        "swdub3jlihj1bgvzigfuzcbwcmluda",
        "1gn0r3",
    ]

    def do_GET(self):
        """Health check endpoint."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = {"status": "healthy", "fixture": "protected_ai", "simulated": True}
        self.wfile.write(json.dumps(resp).encode("utf-8"))

    def do_POST(self):
        """Simulate guarded LLM chat completion with active defense."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")

        prompt = ""
        try:
            data = json.loads(body)
            prompt = data.get("prompt") or data.get("message") or ""
        except Exception:
            prompt = body

        prompt_lower = prompt.lower()
        is_attack = any(trigger in prompt_lower or trigger in prompt for trigger in self.ATTACK_TRIGGERS)

        if is_attack:
            response_text = (
                "I cannot fulfill this request. I am unable to comply with instructions "
                "that attempt to override my system directives or violate safety policies. "
                "Permission denied."
            )
        else:
            response_text = (
                f"I am a protected AI assistant operating under strict safety guidelines. "
                f"Regarding your query: '{prompt[:40]}...', here is an accurate, safe response."
            )

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        output = {"response": response_text, "model": "mock-protected-llm-v1"}
        self.wfile.write(json.dumps(output).encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress standard HTTP access logs
        pass


def run_server(port: int = 8002) -> ThreadingHTTPServer:
    """Instantiate and start the protected test fixture server."""
    server = ThreadingHTTPServer(("127.0.0.1", port), ProtectedAIHandler)
    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start LUME Protected AI Fixture")
    parser.add_argument("--port", type=int, default=8002, help="Server port (default: 8002)")
    args = parser.parse_args()
    print(f"Starting Protected AI Fixture on http://127.0.0.1:{args.port}...")
    server = run_server(args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.server_close()
