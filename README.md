# webshield

A small web application firewall (WAF) written in pure Python, with no third-party dependencies. It inspects HTTP requests and blocks common attacks before they reach your application: SQL injection, cross-site scripting (XSS), path traversal and command injection, plus oversized bodies, disallowed methods and request floods.

It runs in two ways:

- **WSGI middleware** that wraps any WSGI app (Flask, Django, or plain WSGI).
- **Reverse proxy** that sits in front of any HTTP app on your machine.

> **Scope.** Use webshield only to protect applications you own or run. It is a defensive learning project and a useful extra layer, not a replacement for secure coding. Read the [Limitations](#limitations) section before relying on it.

## Features

- 15 default rules in readable JSON, across four attack categories, each with a stable ID.
- Inspects the URL path, query string, headers and request body (form, JSON including nested keys and values, and raw text).
- Decodes input before matching: repeated URL decoding, HTML entities, and SQL block comments (`UNION/**/SELECT`), so simple encoding tricks do not slip through.
- Limits: allowed HTTP methods, maximum body size (checked from `Content-Length` before the body is read), maximum URL length.
- Per-client sliding-window rate limiting that returns `429` with `Retry-After`.
- Structured JSON request logging (method, path, client, action, rule ID, where it matched). Request bodies are never logged.
- Monitor mode: log what would be blocked without blocking, to tune rules against real traffic first.
- Clear JSON block response with a request ID you can find in the log.
- Proxy mode listens on loopback only unless you pass `--allow-non-loopback`, and rejects chunked request bodies to avoid request smuggling problems.

## Requirements

Python 3.9 or newer (tested on 3.10). Nothing to install.

## Quick start

### 1. As WSGI middleware

```python
from webshield import WAFMiddleware

app = WAFMiddleware(my_wsgi_app)                       # default rules
app = WAFMiddleware(my_wsgi_app, rate_limit_requests=60, mode="monitor")  # with overrides
```

With Flask: `app.wsgi_app = WAFMiddleware(app.wsgi_app)`.

For custom settings or rules from a file:

```python
from webshield import WAF, WAFMiddleware, load_config

waf = WAF(load_config("my_rules.json"))
app = WAFMiddleware(my_wsgi_app, waf)
```

### 2. As a reverse proxy

Run your app on one port (for example 5000), then put webshield in front of it:

```bash
python -m webshield --upstream http://127.0.0.1:5000 --listen 127.0.0.1:8080
```

Options: `--rules FILE`, `--mode block|monitor`, `--log-file FILE`, `--allow-non-loopback`.

### 3. Try the demo

```bash
python demo/run_demo.py
```

This starts a deliberately naive demo app and the WAF on `127.0.0.1` only, sends benign and malicious requests, and prints what happened. Nothing leaves your machine.

## Sample output

Real output from `python demo/run_demo.py` (log lines omitted, port and request IDs vary per run; the full run including log lines is in [demo/sample_output.txt](demo/sample_output.txt)):

```
WAF in front of demo app on http://127.0.0.1:PORT (15 rules)

request                              status  outcome
------------------------------------------------------------------------------
normal page                          200     reached app
normal search                        200     reached app
normal comment (JSON)                200     reached app
SQLi: tautology                      403     blocked before app
SQLi: UNION SELECT                   403     blocked before app
SQLi: comment-obfuscated             403     blocked before app
XSS: script tag                      403     blocked before app
XSS: double-encoded                  403     blocked before app
XSS: event handler                   403     blocked before app
Path traversal                       403     blocked before app
Command injection                    403     blocked before app
XSS in JSON body                     403     blocked before app
Disallowed method (TRACE)            405     blocked before app
Oversized body (2 KB, limit 1 KB)    413     blocked before app

Sample blocked response body:
  {"error": "request blocked by web application firewall", "status": 403, "request_id": "84dce034dfe8"}

Rate limit demo (limit: 5 requests per 60 s), sending 8 requests
  statuses: [200, 200, 200, 200, 200, 429, 429, 429]
```

One log line, as written for a blocked request:

```json
log: {"ts": "2026-11-26T09:50:00+0200", "request_id": "9f88a6406efb", "client": "127.0.0.1", "method": "GET", "path": "/search", "action": "block", "status": 403, "rule_id": "SQLI-002", "category": "sql_injection", "location": "query"}
```

## Block responses

| Status | Meaning | Rule ID |
| --- | --- | --- |
| 403 | A rule matched | the rule's ID, for example `XSS-001` |
| 405 | Method not allowed (an `Allow` header is sent) | `LIMIT-METHOD` |
| 411 | Chunked request body (not supported in proxy mode) | `LIMIT-CHUNKED` |
| 413 | Body larger than `max_body_bytes` | `LIMIT-BODY` |
| 414 | URL longer than `max_url_length` | `LIMIT-URL` |
| 429 | Rate limit exceeded (a `Retry-After` header is sent) | `LIMIT-RATE` |

The response body is JSON and contains only a request ID. The rule ID is written to the log, not sent to the client, so an attacker learns less about what triggered. Set `reveal_rule_id` to `true` while developing if you want it in the response.

## Rule format

Rules and settings live in one JSON file. The bundled file is [`webshield/default_rules.json`](webshield/default_rules.json). Copy it and edit.

```json
{
  "settings": {
    "allowed_methods": ["GET", "POST"],
    "max_body_bytes": 1048576,
    "max_url_length": 2048,
    "rate_limit_requests": 120,
    "rate_limit_window_seconds": 60,
    "mode": "block",
    "reveal_rule_id": false,
    "disabled_rules": ["XSS-002"]
  },
  "rules": [
    {
      "id": "CUSTOM-001",
      "category": "custom",
      "message": "Block an internal admin path from outside",
      "pattern": "^/internal-admin",
      "targets": ["path"]
    }
  ]
}
```

| Rule field | Required | Description |
| --- | --- | --- |
| `id` | yes | Unique ID, used in logs and `disabled_rules`. |
| `category` | yes | Free-form label, for example `sql_injection`. |
| `pattern` | yes | Python regular expression. Matching is case-insensitive and dot matches newlines. |
| `targets` | no | Any of `path`, `query`, `body`, `header`. Defaults to all four. |
| `message` | no | Human-readable description. |

Notes:

- A file replaces the bundled rules. To keep the defaults and add to them, copy the default file and add your rules.
- Settings keys can also be passed as keyword arguments to `WAFMiddleware(...)` or `load_config(overrides={...})`.
- Invalid regular expressions, unknown targets, unknown settings and duplicate IDs raise an error at load time, not at request time.
- Rate limiting is disabled with `"rate_limit_requests": 0`.
- Avoid nested quantifiers such as `(a+)+` in your own patterns. They can make a regular expression very slow on crafted input.

### Default rules

| ID | Category | Detects |
| --- | --- | --- |
| SQLI-001 to SQLI-005 | sql_injection | UNION SELECT, boolean tautologies, stacked destructive statements, blind-injection and schema functions, quote plus comment |
| XSS-001 to XSS-004 | xss | script tags, inline event handlers, `javascript:` URLs, iframe/object/embed/svg tags |
| TRAV-001 to TRAV-003 | path_traversal | `../` sequences, sensitive system files, null bytes |
| CMDI-001 to CMDI-003 | command_injection | shell operator plus common command, `$()` and backtick substitution, Shellshock-style headers |

## How a request is processed

1. Method check, then rate limit, then URL length and body size.
2. Path, each query parameter (and the raw query string), headers and body values are extracted. JSON bodies are parsed so escaped payloads such as `\u003cscript` are seen after decoding.
3. Each value is decoded up to three rounds and tested against every rule that targets that location.
4. The first match blocks the request (or is only logged in monitor mode).

## Running the tests

```bash
python -m unittest discover -s tests
```

The suite (36 tests) covers benign traffic, every attack category, encoding evasion, limits, the rate limiter with a fake clock, monitor mode, rule file loading and validation, the middleware, and the reverse proxy end to end on loopback.

## Limitations

This is a pattern-matching WAF, and pattern matching has well-known limits. Please read these honestly.

- **It is not a substitute for secure code.** Use parameterised queries, output escaping, path allow-lists and no shell calls with user input. A WAF only lowers the chance that a mistake gets exploited.
- **Bypasses exist.** Signature rules can be evaded with payloads the patterns do not cover, unusual encodings, or application-specific syntax. Treat the rules as a baseline to tune, not a guarantee.
- **False positives happen.** Text that looks like an attack, for example a blog comment that discusses `<script>` tags, will be blocked. Use monitor mode and your own traffic to tune or disable rules.
- **No response inspection.** Only requests are checked. It does not stop data leaving the application.
- **Rate limiting is per process and in memory.** It resets on restart and is not shared between workers or machines. The client is identified by the connection address, so behind another proxy every user can look like one client.
- **Multipart uploads are scanned as raw text** and file contents are not analysed. Binary uploads may produce odd matches.
- **Proxy mode is basic.** HTTP/1.1 only, upstream over plain HTTP, no TLS termination, no WebSockets, no chunked request bodies, one upstream. For production traffic use a mature WAF such as ModSecurity with the OWASP Core Rule Set.
- **Not tested against real attack tooling.** The tests and demo use hand-written payloads against a local demo app only.

## Project layout

```
webshield/
  engine.py           rules, decoding, limits, rate limiter
  middleware.py       WSGI middleware and block response
  proxy.py            reverse proxy server
  __main__.py         command line entry point
  default_rules.json  bundled rules and settings
demo/
  demo_app.py         deliberately naive demo app (never deploy)
  run_demo.py         localhost-only demo
  sample_output.txt   captured demo output
tests/
  test_waf.py
```

## License

MIT. See [LICENSE](LICENSE).
