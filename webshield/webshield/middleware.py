"""WSGI middleware: wrap any WSGI app (Flask, Django, plain WSGI) with the WAF."""

import io
import json
from typing import Optional

from .engine import WAF, Decision, RequestView, load_config


def block_response(decision: Decision, reveal_rule_id: bool = False):
    """Build (status_line, headers, body_bytes) for a blocked request."""
    payload = {
        "error": "request blocked by web application firewall",
        "status": decision.status,
        "request_id": decision.request_id,
    }
    if reveal_rule_id:
        payload["rule_id"] = decision.rule_id
    body = json.dumps(payload).encode("utf-8")
    reasons = {403: "Forbidden", 405: "Method Not Allowed", 413: "Payload Too Large",
               414: "URI Too Long", 429: "Too Many Requests", 411: "Length Required"}
    headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body))),
               ("Cache-Control", "no-store")]
    headers.extend(decision.headers.items())
    return "%d %s" % (decision.status, reasons.get(decision.status, "Blocked")), headers, body


class WAFMiddleware:
    def __init__(self, app, waf: Optional[WAF] = None, **overrides):
        """Wrap `app`. Pass a ready WAF, or keyword overrides for load_config()."""
        self.app = app
        self.waf = waf or WAF(load_config(overrides=overrides or None))

    def __call__(self, environ, start_response):
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = -1
        if length < 0:
            return self._deny(Decision(False, 400, "LIMIT-LENGTH", "limits", "Bad Content-Length"),
                              start_response)
        headers = {k[5:].replace("_", "-").title(): v
                   for k, v in environ.items() if k.startswith("HTTP_")}
        view = RequestView(
            method=environ.get("REQUEST_METHOD", "GET"),
            path=environ.get("SCRIPT_NAME", "") + environ.get("PATH_INFO", ""),
            query_string=environ.get("QUERY_STRING", ""),
            headers=headers,
            content_type=environ.get("CONTENT_TYPE", ""),
            client_ip=environ.get("REMOTE_ADDR", "unknown"),
        )
        too_big = self.waf.check_declared_size(length)
        if too_big:
            self.waf.log(view, too_big)
            return self._deny(too_big, start_response)

        body = environ["wsgi.input"].read(length) if length else b""
        environ["wsgi.input"] = io.BytesIO(body)
        view.body = body
        decision = self.waf.inspect(view)
        if not decision.allowed:
            return self._deny(decision, start_response)
        environ["webshield.request_id"] = decision.request_id
        return self.app(environ, start_response)

    def _deny(self, decision: Decision, start_response):
        status, headers, body = block_response(decision, self.waf.config.reveal_rule_id)
        start_response(status, headers)
        return [body]
