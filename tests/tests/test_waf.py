import http.client
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from wsgiref.simple_server import WSGIRequestHandler, make_server

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import logging
logging.disable(logging.CRITICAL)

from webshield import RateLimiter, RequestView, WAF, WAFMiddleware, load_config
from webshield.engine import Rule, normalize
from webshield.proxy import make_proxy_server


def make_waf(**overrides):
    overrides.setdefault("rate_limit_requests", 0)
    return WAF(load_config(overrides=overrides))


def get(waf, path="/", query="", **kw):
    return waf.inspect(RequestView(method="GET", path=path, query_string=query, **kw))


def post_json(waf, obj, path="/"):
    return waf.inspect(RequestView(method="POST", path=path, body=json.dumps(obj).encode(),
                                   content_type="application/json"))


class BenignTraffic(unittest.TestCase):
    def setUp(self):
        self.waf = make_waf()

    def test_normal_requests_pass(self):
        for query in ["q=network+security", "page=2&sort=name", "name=O%27Brien", "tag=rock+%26+roll",
                      "q=cats+and+dogs", "city=Zagazig", "note=I+will+be+on+time"]:
            self.assertTrue(get(self.waf, "/search", query).allowed, query)

    def test_normal_json_body_passes(self):
        self.assertTrue(post_json(self.waf, {"user": "mo", "text": "Great post, thanks!"}).allowed)

    def test_normal_headers_pass(self):
        d = get(self.waf, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                   "Accept": "text/html,application/xhtml+xml"})
        self.assertTrue(d.allowed)


class Attacks(unittest.TestCase):
    def setUp(self):
        self.waf = make_waf()

    def assert_blocked(self, decision, category):
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status, 403)
        self.assertEqual(decision.category, category)

    def test_sql_injection(self):
        for q in ["q=' OR 1=1 --", "q=1 UNION SELECT user,pass FROM users", "q=x'; DROP TABLE users",
                  "q=1 UNION/**/SELECT/**/1,2", "id=1 AND SLEEP(5)", "q=admin'--",
                  "q=%27%20or%20%27a%27%3D%27a", "q=1 union all select null"]:
            self.assert_blocked(get(self.waf, "/", q), "sql_injection")

    def test_xss(self):
        for q in ["q=<script>alert(1)</script>", "q=%3Cscript%3Ealert(1)%3C/script%3E",
                  "q=%253Cscript%253E", 'q=" onerror=alert(1) x="', "q=javascript:alert(1)",
                  "q=<iframe src=//evil>", "q=<svg onload=alert(1)>", "q=&lt;script&gt;alert(1)"]:
            self.assert_blocked(get(self.waf, "/", q), "xss")

    def test_path_traversal(self):
        self.assert_blocked(get(self.waf, "/files", "name=../../etc/passwd"), "path_traversal")
        self.assert_blocked(get(self.waf, "/files", "name=..%2f..%2fsecret"), "path_traversal")
        self.assert_blocked(get(self.waf, "/static/..%5c..%5cwin.ini"), "path_traversal")
        self.assert_blocked(get(self.waf, "/files", "name=a%00.png"), "path_traversal")

    def test_command_injection(self):
        for q in ["host=example.com; cat /x", "host=a | whoami", "host=$(id)", "host=`id`",
                  "host=a && curl http://x"]:
            self.assert_blocked(get(self.waf, "/ping", q), "command_injection")

    def test_shellshock_header(self):
        d = get(self.waf, headers={"User-Agent": "() { :; }; /bin/true"})
        self.assert_blocked(d, "command_injection")

    def test_attack_in_json_body_and_keys(self):
        self.assert_blocked(post_json(self.waf, {"text": "<script>x()</script>"}), "xss")
        self.assert_blocked(post_json(self.waf, {"a": [{"b": "1 UNION SELECT 1"}]}), "sql_injection")
        escaped = self.waf.inspect(RequestView(method="POST", body=b'{"text": "\\u003cscript\\u003e"}',
                                               content_type="application/json"))
        self.assert_blocked(escaped, "xss")

    def test_attack_in_form_body(self):
        d = self.waf.inspect(RequestView(method="POST", body=b"user=a&pw=%27+OR+1%3D1+--",
                                         content_type="application/x-www-form-urlencoded"))
        self.assert_blocked(d, "sql_injection")

    def test_attack_in_header(self):
        d = get(self.waf, headers={"Referer": "http://x/?q=<script>alert(1)</script>"})
        self.assert_blocked(d, "xss")


class Limits(unittest.TestCase):
    def test_bad_method(self):
        d = make_waf().inspect(RequestView(method="TRACE", path="/"))
        self.assertEqual((d.allowed, d.status), (False, 405))
        self.assertIn("Allow", d.headers)

    def test_body_too_large(self):
        waf = make_waf(max_body_bytes=100)
        d = waf.inspect(RequestView(method="POST", path="/", body=b"a" * 101))
        self.assertEqual(d.status, 413)
        self.assertEqual(waf.check_declared_size(101).status, 413)
        self.assertIsNone(waf.check_declared_size(100))

    def test_url_too_long(self):
        d = get(make_waf(max_url_length=50), "/", "q=" + "a" * 100)
        self.assertEqual(d.status, 414)

    def test_rate_limit_sliding_window(self):
        now = [0.0]
        limiter = RateLimiter(3, 10, clock=lambda: now[0])
        self.assertEqual([limiter.check("a")[0] for _ in range(4)], [True, True, True, False])
        self.assertTrue(limiter.check("b")[0])  # other clients are unaffected
        now[0] = 11
        self.assertTrue(limiter.check("a")[0])  # window slid

    def test_rate_limit_in_waf(self):
        waf = WAF(load_config(overrides={"rate_limit_requests": 2}))
        results = [get(waf, client_ip="1.2.3.4") for _ in range(3)]
        self.assertEqual([r.status for r in results], [200, 200, 429])
        self.assertIn("Retry-After", results[2].headers)


class Modes(unittest.TestCase):
    def test_monitor_mode_allows_but_flags(self):
        d = get(make_waf(mode="monitor"), "/", "q=<script>")
        self.assertTrue(d.allowed)
        self.assertTrue(d.would_block)
        self.assertEqual(d.rule_id, "XSS-001")

    def test_monitor_mode_still_enforces_limits(self):
        d = make_waf(mode="monitor").inspect(RequestView(method="TRACE", path="/"))
        self.assertFalse(d.allowed)

    def test_disabled_rule(self):
        waf = make_waf(disabled_rules=["XSS-001"])
        self.assertTrue(get(waf, "/", "q=<script>").allowed)
        self.assertFalse(get(waf, "/", "q=<iframe src=x>").allowed)


class RuleFiles(unittest.TestCase):
    def write(self, data):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(data, handle)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_custom_rules_and_settings(self):
        path = self.write({"settings": {"max_body_bytes": 10, "rate_limit_requests": 0},
                           "rules": [{"id": "CUSTOM-1", "category": "custom",
                                      "pattern": "forbidden-word", "targets": ["query"]}]})
        waf = WAF(load_config(path))
        d = get(waf, "/", "q=FORBIDDEN-WORD")
        self.assertEqual((d.allowed, d.rule_id), (False, "CUSTOM-1"))
        self.assertTrue(get(waf, "/", "q=<script>").allowed)  # default rules are not loaded
        self.assertEqual(waf.config.max_body_bytes, 10)

    def test_invalid_rules_are_rejected(self):
        bad = [{"id": "X", "category": "c", "pattern": "("},
               {"id": "X", "category": "c", "pattern": "a", "targets": ["cookie"]},
               {"category": "c", "pattern": "a"}]
        for rule in bad:
            with self.assertRaises(ValueError):
                load_config(self.write({"rules": [rule]}))

    def test_unknown_setting_and_duplicate_ids(self):
        with self.assertRaises(ValueError):
            load_config(self.write({"settings": {"nope": 1}, "rules": []}))
        dup = {"id": "A", "category": "c", "pattern": "a"}
        with self.assertRaises(ValueError):
            load_config(self.write({"rules": [dup, dup]}))

    def test_bundled_rules_load(self):
        cfg = load_config()
        self.assertGreaterEqual(len(cfg.rules), 15)
        self.assertTrue(all(isinstance(r, Rule) for r in cfg.rules))


class Normalize(unittest.TestCase):
    def test_double_decoding_and_comments(self):
        self.assertIn("<script>", normalize("%253Cscript%253E"))
        self.assertIn("union select", normalize("union/**/select").pop().replace("  ", " "))


def call_wsgi(app, method="GET", path="/", query="", body=b"", ctype="", extra=None):
    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": query,
               "REMOTE_ADDR": "127.0.0.1", "CONTENT_LENGTH": str(len(body)),
               "CONTENT_TYPE": ctype, "wsgi.input": io.BytesIO(body)}
    environ.update(extra or {})
    captured = {}

    def start_response(status, headers):
        captured["status"], captured["headers"] = status, dict(headers)

    out = b"".join(app(environ, start_response))
    return captured["status"], captured["headers"], out


def echo_app(environ, start_response):
    data = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0))
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok:" + data]


class Middleware(unittest.TestCase):
    def setUp(self):
        self.app = WAFMiddleware(echo_app, rate_limit_requests=0, max_body_bytes=50)

    def test_allows_and_passes_body_through(self):
        status, _, out = call_wsgi(self.app, "POST", "/x", body=b"hello", ctype="text/plain")
        self.assertEqual((status, out), ("200 OK", b"ok:hello"))

    def test_blocks_with_json_response(self):
        status, headers, out = call_wsgi(self.app, query="q=%3Cscript%3E")
        payload = json.loads(out)
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertIn("request_id", payload)
        self.assertNotIn("rule_id", payload)

    def test_reveal_rule_id_option(self):
        app = WAFMiddleware(echo_app, rate_limit_requests=0, reveal_rule_id=True)
        _, _, out = call_wsgi(app, query="q=%3Cscript%3E")
        self.assertEqual(json.loads(out)["rule_id"], "XSS-001")

    def test_oversized_declared_body_rejected_before_read(self):
        status, _, _ = call_wsgi(self.app, "POST", body=b"a" * 60, ctype="text/plain")
        self.assertTrue(status.startswith("413"))

    def test_bad_content_length(self):
        status, _, _ = call_wsgi(self.app, "POST", extra={"CONTENT_LENGTH": "abc"})
        self.assertTrue(status.startswith("400"))

    def test_headers_are_inspected(self):
        status, _, _ = call_wsgi(self.app, extra={"HTTP_USER_AGENT": "() { :; }; echo"})
        self.assertTrue(status.startswith("403"))


class QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):
        pass


class ProxyIntegration(unittest.TestCase):
    def setUp(self):
        self.upstream = make_server("127.0.0.1", 0, echo_app, handler_class=QuietHandler)
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        waf = make_waf(max_body_bytes=200)
        self.proxy = make_proxy_server("127.0.0.1", 0, "http://127.0.0.1:%d" % self.upstream.server_port, waf)
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        self.port = self.proxy.server_address[1]

    def tearDown(self):
        self.proxy.shutdown()
        self.proxy.server_close()
        if self.upstream is not None:
            self.upstream.shutdown()
            self.upstream.server_close()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def test_forwards_clean_request(self):
        self.assertEqual(self.request("POST", "/a", b"payload", {"Content-Type": "text/plain"}),
                         (200, b"ok:payload"))

    def test_blocks_attack_in_query(self):
        status, data = self.request("GET", "/a?q=%27%20OR%201%3D1%20--")
        self.assertEqual(status, 403)
        self.assertIn(b"request_id", data)

    def test_blocks_attack_in_body(self):
        status, _ = self.request("POST", "/a", b"<script>x</script>", {"Content-Type": "text/plain"})
        self.assertEqual(status, 403)

    def test_blocks_oversized_body(self):
        status, _ = self.request("POST", "/a", b"a" * 300, {"Content-Type": "text/plain"})
        self.assertEqual(status, 413)

    def test_rejects_chunked_requests(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", "/a", body=iter([b"abc"]), headers={"Transfer-Encoding": "chunked"},
                     encode_chunked=True)
        self.assertEqual(conn.getresponse().status, 411)
        conn.close()

    def test_bad_gateway_when_upstream_down(self):
        self.upstream.shutdown()
        self.upstream.server_close()
        self.upstream = None
        self.assertEqual(self.request("GET", "/")[0], 502)


if __name__ == "__main__":
    unittest.main()
