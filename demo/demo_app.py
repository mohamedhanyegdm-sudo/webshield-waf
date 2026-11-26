"""A tiny demo WSGI app for trying the WAF on localhost.

WARNING: this app is deliberately naive. It echoes input back without
escaping and does no validation. It never touches a database, the file system
or a shell, but do not deploy it anywhere. It exists only so the WAF has
something to protect in the demo.
"""

import json
from urllib.parse import parse_qs

REACHED = []  # paths of requests that got past the WAF, used by the demo output


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    REACHED.append(path)
    query = parse_qs(environ.get("QUERY_STRING", ""))
    if path == "/":
        body = b"demo app is up"
        ctype = "text/plain"
    elif path == "/search":
        term = query.get("q", [""])[0]
        body = ("<h1>Results for %s</h1>" % term).encode()  # unescaped on purpose
        ctype = "text/html"
    elif path == "/files":
        name = query.get("name", [""])[0]
        body = json.dumps({"would_read": name}).encode()
        ctype = "application/json"
    elif path == "/comment" and environ["REQUEST_METHOD"] == "POST":
        size = int(environ.get("CONTENT_LENGTH") or 0)
        data = environ["wsgi.input"].read(size)
        body = json.dumps({"stored": data.decode("utf-8", "replace")[:200]}).encode()
        ctype = "application/json"
    else:
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"not found"]
    start_response("200 OK", [("Content-Type", ctype), ("Content-Length", str(len(body)))])
    return [body]
