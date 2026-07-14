#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from serverware.http_client import HttpClientError, request_bytes


class Handler(BaseHTTPRequestHandler):
    redirected_requests = 0
    redirected_secret: str | None = None

    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/target")
            self.end_headers()
            return
        if self.path == "/target":
            type(self).redirected_requests += 1
            type(self).redirected_secret = self.headers.get("X-Test-Secret")
            body = b"redirected"
        elif self.path == "/oversized":
            body = b"x" * 33
        else:
            body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        response = request_bytes(f"{base}/ok", timeout=2, max_bytes=32)
        if response.status != 200 or response.body != b'{"ok":true}':
            raise AssertionError(f"bounded request returned the wrong response: {response}")

        redirect = urllib.request.Request(f"{base}/redirect", headers={"X-Test-Secret": "do-not-forward"})
        try:
            request_bytes(redirect, timeout=2, max_bytes=32)
        except urllib.error.HTTPError as exc:
            if exc.code != 302:
                raise AssertionError(f"redirect failed with the wrong status: {exc.code}") from exc
        else:
            raise AssertionError("HTTP redirect was followed")
        if Handler.redirected_requests or Handler.redirected_secret:
            raise AssertionError("redirect target received a credential-bearing request")

        try:
            request_bytes(f"{base}/oversized", timeout=2, max_bytes=32)
        except HttpClientError as exc:
            if "exceeds 32 bytes" not in str(exc):
                raise AssertionError(f"oversized response failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("oversized HTTP response was accepted")

        for invalid in ("file:///etc/passwd", "http://user:password@localhost/", f"{base}/ok#fragment"):
            try:
                request_bytes(invalid, timeout=2, max_bytes=32)
            except HttpClientError:
                pass
            else:
                raise AssertionError(f"unsafe HTTP URL was accepted: {invalid}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    print(json.dumps({"http_client": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
