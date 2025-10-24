# shared/health.py
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

def start_health_server(port: int = 8080):
    def run():
        server = HTTPServer(("0.0.0.0", port), HealthHandler)
        server.serve_forever()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
