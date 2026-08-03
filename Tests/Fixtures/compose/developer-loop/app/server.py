from __future__ import annotations

import hashlib
import json
import os
import pathlib
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SOURCE = pathlib.Path("/workspace/message.txt")
IMAGE_VERSION = pathlib.Path("/image-version.txt").read_text().strip()
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL_SECONDS", "0.15"))
state_lock = threading.Lock()
state = {"generation": 0, "message": "", "sha256": ""}
ready = threading.Event()


def poll_source() -> None:
    previous = None
    candidate = None
    while True:
        try:
            payload = SOURCE.read_bytes()
        except FileNotFoundError:
            payload = b""
        if not payload.endswith(b"\n"):
            candidate = None
            time.sleep(POLL_INTERVAL)
            continue
        digest = hashlib.sha256(payload).hexdigest()
        if digest == candidate and digest != previous:
            with state_lock:
                state["generation"] += 1
                state["message"] = payload.decode(errors="replace").strip()
                state["sha256"] = digest
            previous = digest
            ready.set()
        candidate = digest
        time.sleep(POLL_INTERVAL)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path not in ("/", "/health"):
            self.send_error(404)
            return
        if self.path == "/health" and not ready.is_set():
            self.send_error(503)
            return
        with state_lock:
            body = json.dumps({
                **state,
                "imageVersion": IMAGE_VERSION,
                "pid": os.getpid(),
            }, sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


threading.Thread(target=poll_source, daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
