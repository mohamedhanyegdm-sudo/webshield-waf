"""Localhost-only demo: sends benign and malicious requests through the WAF.

Run from the repository root:  python demo/run_demo.py
Everything runs on 127.0.0.1 against demo/demo_app.py. Nothing leaves your machine.
"""

import http.client
import json
import os
import sys
import threading
from wsgiref.simple_server import WSGIRequestHandler, make_server

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging

import demo_app
from webshield import WAF, WAFMiddleware, load_config

HOST = "127.0.0.1"


class QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):
        pass


CASES = [
    # label, method, path, body, content type
    ("normal page", "GET", "/", None, None),
    ("normal search", "GET", "/search?q=network+security", None, None),
    ("normal comment (JSON)", "POST", "/comment", {"text": "Nice article, thanks"}, "json"),
    ("SQLi: tautology", "GET", "/search?q=%27%20OR%201%3D1%20--%20", None, None),
    ("SQLi: UNION SELECT", "GET", "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users", None, None),
    ("SQLi: comment-obfuscated", "GET", "/search?q=1%20UNION/**/SELECT/**/1,2", None, None),
    ("XSS: script tag", "GET", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", None, None),
    ("XSS: double-encoded", "GET", "/search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E", None, None),
    ("XSS: event handler", "GET", "/search?q=%22%20onerror%3Dalert(1)%20x%3D%22", None, None),
    ("Path traversal", "GET", "/files?name=..%2F..%2Fetc%2Fpasswd", None, None),
    ("Command injection", "GET", "/files?name=report.txt%3B%20whoami", None, None),
    ("XSS in JSON body", "POST", "/comment", {"text": "<script>steal()</script>"}, "json"),
    ("Disallowed method (TRACE)", "TRACE", "/", None, None),
    ("Oversized body (2 KB, limit 1 KB)", "POST", "/comment", {"text": "a" * 2048}, "json"),
]


def send(port, method, path, body, kind):
    conn = http.client.HTTPConnection(HOST, port, timeout=5)
    headers = {}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8", "replace")
    conn.close()
    return resp.status, raw


def main():
    logging.basicConfig(level=logging.WARNING, format="  log: %(message)s", stream=sys.stdout)
    config = load_config(overrides={"max_body_bytes": 1024, "rate_limit_requests": 1000})
    waf = WAF(config)
    server = make_server(HOST, 0, WAFMiddleware(demo_app.app, waf), handler_class=QuietHandler)
    port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print("WAF in front of demo app on http://%s:%d (%d rules)\n" % (HOST, port, len(waf.rules)))
    print("%-36s %-7s %s" % ("request", "status", "outcome"))
    print("-" * 78)
    for label, method, path, body, kind in CASES:
        before = len(demo_app.REACHED)
        status, raw = send(port, method, path, body, kind)
        reached = len(demo_app.REACHED) > before
        outcome = "reached app" if reached else "blocked before app"
        print("%-36s %-7d %s" % (label, status, outcome))
    print("\nSample blocked response body:")
    print(" ", send(port, "GET", "/search?q=%3Cscript%3E", None, None)[1])
    server.shutdown()

    # Rate limiting, on its own instance with a small limit so the result is easy to read.
    limited = WAFMiddleware(demo_app.app, WAF(load_config(overrides={"rate_limit_requests": 5,
                                                                    "rate_limit_window_seconds": 60})))
    server = make_server(HOST, 0, limited, handler_class=QuietHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print("\nRate limit demo (limit: 5 requests per 60 s), sending 8 requests")
    codes = [send(server.server_port, "GET", "/", None, None)[0] for _ in range(8)]
    print("  statuses:", codes)
    server.shutdown()


if __name__ == "__main__":
    main()
