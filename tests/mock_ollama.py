"""A tiny fake Ollama server for tests (no GPU, no model needed).

It answers ``/api/chat`` like Ollama does (streamed NDJSON) with an identification: a page
titled "Kitchen Owl" is KitchenOwl on the port it was seen on, anything else is unknown.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "qwen2.5:14b"


class _Handler(BaseHTTPRequestHandler):
    calls: list = []

    def log_message(self, *args):  # silence
        pass

    def _send(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/api/version":
            self._send(200, {"version": "0.12.0-mock"})
        elif self.path == "/api/tags":
            self._send(200, {"models": [{"name": MODEL}, {"name": "llama3.2:3b"}]})
        elif self.path == "/api/ps":
            self._send(200, {"models": []})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(length) or b"{}")
        if self.path != "/api/chat":
            return self._send(404, {"error": "not found"})
        if req.get("model") not in (MODEL, "llama3.2:3b"):
            return self._send(404, {"error": f"model '{req.get('model')}' not found"})
        _Handler.calls.append(req)
        prompt = req["messages"][-1]["content"]
        m = re.search(r'"port":\s*(\d+)[^{}]*"title":\s*"Kitchen Owl"', prompt)
        if m:
            answer = {"app": "kitchenowl", "display_name": "KitchenOwl", "category": "home",
                      "version": "", "confidence": 0.82, "web_port": int(m.group(1)),
                      "scheme": "http", "health_path": "/api/health", "metrics_port": 0,
                      "description": "Grocery list and recipe manager",
                      "reasons": ["page title is Kitchen Owl"]}
        else:
            answer = {"app": "unknown", "category": "other", "confidence": 0.2, "web_port": 0,
                      "health_path": "/", "description": "", "reasons": ["nothing distinctive"]}
        line = {"model": req["model"], "message": {"role": "assistant", "content": json.dumps(answer)},
                "done": True, "done_reason": "stop", "prompt_eval_count": len(prompt) // 4,
                "eval_count": 40}
        data = (json.dumps(line) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def start() -> tuple[ThreadingHTTPServer, str]:
    _Handler.calls = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def calls() -> list:
    return _Handler.calls


if __name__ == "__main__":
    s, url = start()
    print(url, flush=True)
    threading.Event().wait()
