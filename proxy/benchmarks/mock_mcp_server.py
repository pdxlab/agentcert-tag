"""Minimal MCP upstream for benchmarking — answers JSON-RPC with near-zero work,
so the measured delta between direct and through-proxy is the proxy's own overhead."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = [{"name": "echo", "description": "echo", "inputSchema": {"type": "object"}}]


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}") if n else {}
        method, rid = req.get("method"), req.get("id")
        if method == "tools/list":
            result = {"tools": TOOLS}
        else:
            result = {"content": [{"type": "text", "text": "ok"}]}
        body = json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    port = int(os.environ.get("MOCK_PORT", "9090"))
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()


if __name__ == "__main__":
    main()
