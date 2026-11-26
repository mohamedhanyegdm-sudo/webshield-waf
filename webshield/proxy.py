"""Reverse proxy mode: put the WAF in front of any HTTP app you run yourself."""

import http.client
import http.server
import logging
import socketserver
import urllib.parse
from typing import Optional

from .engine import WAF, RequestView
from .middleware import block_response
from .engine import Decision

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade"}


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def make_proxy_server(listen_host: str, listen_port: int, upstream: str, waf: WAF,
                      timeout: float = 10.0) -> http.server.HTTPServer:
    target = urllib.parse.urlparse(upstream)
    if target.scheme != "http" or not target.hostname:
        raise ValueError("upstream must look like http://host:port")
    up_host, up_port = target.hostname, target.port or 80

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "webshield"

        def log_message(self, fmt, *args):  # the WAF logger handles logging
            pass

        def _send_decision(self, decision: Decision, view: Optional[RequestView] = None):
            if view is not None:
                waf.log(view, decision)
            status, headers, body = block_response(decision, waf.config.reveal_rule_id)
            self.send_response_only(int(status.split()[0]), status.split(" ", 1)[1])
            for key, value in headers:
                self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            self.close_connection = True

        def _handle(self):
            parts = urllib.parse.urlsplit(self.path)
            headers = {k: v for k, v in self.headers.items()}
            view = RequestView(
                method=self.command, path=parts.path, query_string=parts.query,
                headers=headers, content_type=self.headers.get("Content-Type", ""),
                client_ip=self.client_address[0])
            if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
                return self._send_decision(Decision(False, 411, "LIMIT-CHUNKED", "limits",
                                                    "Chunked request bodies are not supported"), view)
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if length < 0:
                    raise ValueError
            except ValueError:
                return self._send_decision(Decision(False, 400, "LIMIT-LENGTH", "limits",
                                                    "Bad Content-Length"), view)
            too_big = waf.check_declared_size(length)
            if too_big:
                return self._send_decision(too_big, view)
            view.body = self.rfile.read(length) if length else b""

            decision = waf.inspect(view)
            if not decision.allowed:
                return self._send_decision(decision)

            fwd = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
            fwd["X-Forwarded-For"] = self.client_address[0]
            fwd["X-Request-Id"] = decision.request_id
            try:
                conn = http.client.HTTPConnection(up_host, up_port, timeout=timeout)
                conn.request(self.command, self.path, body=view.body or None, headers=fwd)
                resp = conn.getresponse()
                data = resp.read()
            except (OSError, http.client.HTTPException) as exc:
                logging.getLogger("webshield").error("upstream error: %s", exc)
                return self._send_decision(Decision(False, 502, "UPSTREAM", "proxy",
                                                    "Bad gateway"))
            self.send_response_only(resp.status, resp.reason)
            for key, value in resp.getheaders():
                if key.lower() not in HOP_BY_HOP and key.lower() != "content-length":
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            conn.close()

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _handle
        do_TRACE = do_CONNECT = _handle

    return _Server((listen_host, listen_port), Handler)
