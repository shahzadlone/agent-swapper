"""Serve the README proposals on loopback and record a visual selection."""

import argparse
import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / ".preview"
CHOICES = {"graphite", "paper", "forest"}


class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def do_POST(self):
        if self.path != "/selection":
            self.send_error(404)
            return
        origin = self.headers.get("Origin")
        if origin and origin != "http://" + self.headers.get("Host", ""):
            self.send_error(403)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 256:
                raise ValueError("Invalid payload size")
            choice = json.loads(self.rfile.read(length)).get("choice")
            available = set(CHOICES)
            manifest = ROOT / "themes.json"
            if manifest.exists():
                available.update(theme["id"] for theme in json.loads(manifest.read_text()))
            if choice not in available:
                raise ValueError("Unknown design")
        except (ValueError, AttributeError):
            self.send_error(400)
            return
        (ROOT / "selection.json").write_text(json.dumps({"choice": choice}) + "\n")
        body = json.dumps({"choice": choice, "saved": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=4317)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), partial(Handler, directory=str(ROOT)))
    print(f"README previews: http://localhost:{args.port}", flush=True)
    server.serve_forever()
