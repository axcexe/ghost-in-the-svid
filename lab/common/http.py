"""Minimal JSON-over-HTTP(S) server/client helpers built on the standard library."""
from __future__ import annotations

import http.client
import json
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class JsonHandler(BaseHTTPRequestHandler):
    routes: dict = {}

    def log_message(self, fmt, *args):  # quieter logs, prefixed by service
        sys.stderr.write(f"[{self.server.server_name_tag}] " + (fmt % args) + "\n")

    def _dispatch(self, method: str):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {}
        for (m, prefix), fn in self.routes.items():
            if m == method and self.path.startswith(prefix):
                try:
                    status, payload = fn(self, body)
                except Exception as e:  # noqa: BLE001
                    status, payload = 500, {"error": f"{type(e).__name__}: {e}"}
                return self._send(status, payload)
        self._send(404, {"error": "not found"})

    def _send(self, status: int, payload: dict):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def peer_der(self) -> bytes | None:
        conn = self.connection
        if isinstance(conn, ssl.SSLSocket):
            return conn.getpeercert(binary_form=True)
        return None


def serve(port: int, routes: dict, tag: str, ssl_ctx: ssl.SSLContext | None = None):
    handler = type(f"H_{tag}", (JsonHandler,), {"routes": routes})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.server_name_tag = tag
    if ssl_ctx is not None:
        httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


def request(method: str, host: str, port: int, path: str, body=None, headers=None,
            ssl_ctx: ssl.SSLContext | None = None, timeout: float = 15, expect_peer: str | None = None):
    """Return (status, json_body, peer_der_or_None).

    expect_peer: required SPIFFE ID of the server, checked after the handshake and
    BEFORE any credential is sent.
    """
    if ssl_ctx is not None:
        conn = http.client.HTTPSConnection(host, port, context=ssl_ctx, timeout=timeout)
        if expect_peer:
            from common.spiffe_util import spiffe_id_from_der
            conn.connect()
            got = spiffe_id_from_der(conn.sock.getpeercert(binary_form=True))
            if got != expect_peer:
                conn.close()
                raise ssl.SSLError(f"server is {got}, expected {expect_peer}")
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    conn.request(method, path, body=data, headers=hdrs)
    resp = conn.getresponse()
    peer = None
    if ssl_ctx is not None and conn.sock is not None:
        peer = conn.sock.getpeercert(binary_form=True)
    raw = resp.read()
    conn.close()
    try:
        payload = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        payload = {"raw": raw.decode(errors="replace")}
    return resp.status, payload, peer
