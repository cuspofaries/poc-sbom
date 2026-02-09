"""Minimal web app for supply chain POC testing."""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os

# These imports exist to generate a richer dependency tree for SBOM
import flask  # noqa: F401
import requests  # noqa: F401
import pyyaml  # noqa: F401 — imported as yaml but pkg is pyyaml
import cryptography  # noqa: F401


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Supply Chain POC App")

    def log_message(self, format, *args):
        pass  # Silence logs


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    server = HTTPServer(("0.0.0.0", port), HealthHandler)
    print(f"Server running on port {port}")
    server.serve_forever()
