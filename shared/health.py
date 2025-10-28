# shared/health.py
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import requests
import io

AGENT_HTTP_LOCAL = "http://127.0.0.1:8001"  # internal agent server (where agent endpoints live)

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Respond 200 OK for ANY path so /intake/health, /analyzer/health, etc. all work
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        """
        Proxy POST requests to the local agent server at AGENT_HTTP_LOCAL.
        Keeps headers and body; returns proxied status/body/headers.
        Useful when ALB sends /intake/analyze -> this forwards to agent at /intake/analyze.
        """
        # Read incoming body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""

        # Construct upstream URL using the same path
        upstream_url = f"{AGENT_HTTP_LOCAL}{self.path}"

        # Copy relevant headers (omit Host to let requests set it)
        headers = {}
        for k, v in self.headers.items():
            if k.lower() in ("host", "content-length", "connection"):
                continue
            headers[k] = v

        try:
            resp = requests.post(upstream_url, data=body, headers=headers, timeout=10)
        except requests.RequestException as e:
            # Upstream unavailable -> 502 Bad Gateway
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            msg = f"Upstream proxy error: {e}".encode("utf-8")
            self.wfile.write(msg)
            return

        # Relay upstream response
        self.send_response(resp.status_code)
        # Copy headers (skip hop-by-hop)
        hop_by_hop = {
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailers", "transfer-encoding", "upgrade"
        }
        for k, v in resp.headers.items():
            if k.lower() in hop_by_hop:
                continue
            self.send_header(k, v)
        # Ensure content-type exists
        if "Content-Type" not in resp.headers:
            self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        # Write body
        if resp.content:
            self.wfile.write(resp.content)

    def log_message(self, fmt, *args):
        # reduce noise in container logs
        pass

def start_health_server(port: int = 8080):
    def run():
        server = HTTPServer(("0.0.0.0", port), HealthHandler)
        server.serve_forever()
    t = threading.Thread(target=run, daemon=True)
    t.start()
