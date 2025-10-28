# shared/http_proxy.py
import os
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

SERVICE_BASE = os.environ.get("SERVICE_BASE", "/intake").rstrip("/")
UAGENTS_HOST = os.environ.get("UAGENTS_HOST", "127.0.0.1")
UAGENTS_PORT = int(os.environ.get("UAGENTS_PORT", "8001"))

class _ProxyHandler(BaseHTTPRequestHandler):
    server_version = "HealthProxy/1.0"

    def _write(self, code=200, body="ok", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.wfile.write(body)

    def do_GET(self):
        if self.path == f"{SERVICE_BASE}/health":
            return self._write(200, "ok")
        return self._write(404, "not found")

    def _proxy(self):
        if not self.path.startswith(f"{SERVICE_BASE}/submit"):
            return self._write(404, "not found")

        # strip the service prefix so uAgents sees /submit...
        internal_path = self.path[len(SERVICE_BASE):]
        target = f"http://{UAGENTS_HOST}:{UAGENTS_PORT}{internal_path}"

        length = int(self.headers.get("Content-Length", "0") or 0)
        data = self.rfile.read(length) if length else None
        headers = {"Content-Type": self.headers.get("Content-Type", "application/octet-stream")}

        try:
            resp = requests.request(self.command, target, headers=headers, data=data, timeout=10)
            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                if k.lower() in ("transfer-encoding", "connection", "content-encoding"):
                    continue
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp.content)
        except Exception as e:
            self._write(502, f"proxy error: {e}")

    def do_POST(self): self._proxy()
    def do_PUT(self): self._proxy()
    def do_PATCH(self): self._proxy()
    def do_DELETE(self): self._proxy()

def start_health_proxy(port: int):
    """Run the proxy/health server on 0.0.0.0:<port> in a background thread."""
    server = HTTPServer(("0.0.0.0", port), _ProxyHandler)
    t = threading.Thread(target=server.serve_forever, name="health-proxy", daemon=True)
    t.start()
