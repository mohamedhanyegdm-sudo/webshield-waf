"""Core inspection engine: rules, request normalisation and rate limiting.

The engine knows nothing about WSGI or sockets. It takes a RequestView and
returns a Decision, so the same logic serves the WSGI middleware and the
reverse proxy.
"""

import collections
import html
import json
import logging
import os
import re
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

LOGGER = logging.getLogger("webshield")

DEFAULT_RULES_PATH = os.path.join(os.path.dirname(__file__), "default_rules.json")
VALID_TARGETS = ("path", "query", "body", "header")
VALID_MODES = ("block", "monitor")
_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    message: str
    pattern: "re.Pattern[str]"
    targets: Tuple[str, ...] = VALID_TARGETS

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        for key in ("id", "category", "pattern"):
            if not data.get(key):
                raise ValueError("rule is missing required field %r: %r" % (key, data))
        targets = tuple(data.get("targets") or VALID_TARGETS)
        bad = [t for t in targets if t not in VALID_TARGETS]
        if bad:
            raise ValueError("rule %s has unknown targets %s" % (data["id"], bad))
        try:
            compiled = re.compile(data["pattern"], re.I | re.S)
        except re.error as exc:
            raise ValueError("rule %s has an invalid pattern: %s" % (data["id"], exc))
        return cls(
            id=str(data["id"]),
            category=str(data["category"]),
            message=str(data.get("message", data["id"])),
            pattern=compiled,
            targets=targets,
        )


@dataclass
class Config:
    allowed_methods: Tuple[str, ...] = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
    max_body_bytes: int = 1048576
    max_url_length: int = 2048
    rate_limit_requests: int = 120  # 0 disables rate limiting
    rate_limit_window_seconds: float = 60.0
    mode: str = "block"  # "block" or "monitor" (log only)
    reveal_rule_id: bool = False  # include the rule id in the response body
    disabled_rules: Tuple[str, ...] = ()
    rules: List[Rule] = field(default_factory=list)

    def __post_init__(self):
        if self.mode not in VALID_MODES:
            raise ValueError("mode must be one of %s" % (VALID_MODES,))
        self.allowed_methods = tuple(m.upper() for m in self.allowed_methods)


def load_config(path: Optional[str] = None, overrides: Optional[dict] = None) -> Config:
    """Load settings and rules from a JSON file (default: the bundled rules).

    File format: {"settings": {...}, "rules": [...]}. Settings keys match the
    Config fields. Keys in `overrides` win over the file.
    """
    with open(path or DEFAULT_RULES_PATH, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    settings = dict(data.get("settings", {}))
    settings.update(overrides or {})
    known = {"allowed_methods", "max_body_bytes", "max_url_length", "rate_limit_requests",
             "rate_limit_window_seconds", "mode", "reveal_rule_id", "disabled_rules"}
    unknown = set(settings) - known
    if unknown:
        raise ValueError("unknown settings: %s" % ", ".join(sorted(unknown)))
    rules = [Rule.from_dict(r) for r in data.get("rules", [])]
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule ids in %s" % (path or DEFAULT_RULES_PATH))
    settings["rules"] = rules
    for key in ("allowed_methods", "disabled_rules"):
        if key in settings:
            settings[key] = tuple(settings[key])
    return Config(**settings)


@dataclass
class RequestView:
    method: str
    path: str = "/"
    query_string: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    content_type: str = ""
    client_ip: str = "unknown"


@dataclass
class Decision:
    allowed: bool
    status: int = 200
    rule_id: str = ""
    category: str = ""
    message: str = ""
    location: str = ""
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    would_block: bool = False  # set in monitor mode when a rule matched
    headers: Dict[str, str] = field(default_factory=dict)


class RateLimiter:
    """Sliding-window limiter keyed by client address. Thread-safe."""

    def __init__(self, max_requests: int, window_seconds: float,
                 clock: Callable[[], float] = time.monotonic):
        self.max_requests = max_requests
        self.window = window_seconds
        self.clock = clock
        self._hits: Dict[str, collections.deque] = {}
        self._lock = threading.Lock()
        self._calls = 0

    def check(self, key: str) -> Tuple[bool, int]:
        """Record a hit. Returns (allowed, retry_after_seconds)."""
        if self.max_requests <= 0:
            return True, 0
        now = self.clock()
        with self._lock:
            hits = self._hits.setdefault(key, collections.deque())
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            self._calls += 1
            if self._calls % 1000 == 0:
                self._purge(now)
            if len(hits) >= self.max_requests:
                retry = max(1, int(self.window - (now - hits[0])) + 1)
                return False, retry
            hits.append(now)
            return True, 0

    def _purge(self, now: float) -> None:
        for key in [k for k, h in self._hits.items() if not h or now - h[-1] >= self.window]:
            del self._hits[key]


def normalize(value: str) -> List[str]:
    """Return the forms of a value that the rules should be tested against.

    The value is URL-decoded and HTML-unescaped repeatedly (up to 3 rounds) to
    defeat double encoding. A second form with SQL block comments replaced by
    spaces is added, so UNION/**/SELECT is seen as UNION SELECT.
    """
    current = value
    for _ in range(3):
        decoded = html.unescape(urllib.parse.unquote(current))
        if decoded == current:
            break
        current = decoded
    forms = [current]
    stripped = _COMMENT_RE.sub(" ", current)
    if stripped != current:
        forms.append(stripped)
    return forms


class WAF:
    def __init__(self, config: Optional[Config] = None, clock: Callable[[], float] = time.monotonic):
        self.config = config or load_config()
        disabled = set(self.config.disabled_rules)
        self.rules = [r for r in self.config.rules if r.id not in disabled]
        self.limiter = RateLimiter(self.config.rate_limit_requests,
                                   self.config.rate_limit_window_seconds, clock)

    # -- public API -------------------------------------------------------

    def inspect(self, req: RequestView) -> Decision:
        decision = self._evaluate(req)
        if not decision.allowed and self.config.mode == "monitor" and decision.status == 403:
            decision.would_block = True
            decision.allowed = True
        self.log(req, decision)
        return decision

    def check_declared_size(self, content_length: int) -> Optional[Decision]:
        """Cheap pre-check on a declared Content-Length, before reading the body."""
        if content_length > self.config.max_body_bytes:
            return Decision(False, 413, "LIMIT-BODY", "limits", "Request body too large")
        return None

    # -- internals --------------------------------------------------------

    def _evaluate(self, req: RequestView) -> Decision:
        cfg = self.config
        method = req.method.upper()
        if method not in cfg.allowed_methods:
            return Decision(False, 405, "LIMIT-METHOD", "limits", "Method not allowed",
                            headers={"Allow": ", ".join(cfg.allowed_methods)})
        allowed, retry = self.limiter.check(req.client_ip)
        if not allowed:
            return Decision(False, 429, "LIMIT-RATE", "limits", "Rate limit exceeded",
                            headers={"Retry-After": str(retry)})
        url_len = len(req.path) + (len(req.query_string) + 1 if req.query_string else 0)
        if url_len > cfg.max_url_length:
            return Decision(False, 414, "LIMIT-URL", "limits", "URL too long")
        if len(req.body) > cfg.max_body_bytes:
            return Decision(False, 413, "LIMIT-BODY", "limits", "Request body too large")
        for target, value in self._collect(req):
            for form in normalize(value):
                for rule in self.rules:
                    if target in rule.targets and rule.pattern.search(form):
                        return Decision(False, 403, rule.id, rule.category, rule.message, target)
        return Decision(True)

    def _collect(self, req: RequestView) -> List[Tuple[str, str]]:
        items: List[Tuple[str, str]] = [("path", req.path)]
        if req.query_string:
            # The whole raw string too, so payloads that rely on '&' or ';' splitting are seen.
            items.append(("query", req.query_string))
        for name, value in urllib.parse.parse_qsl(req.query_string, keep_blank_values=True):
            items.append(("query", name))
            items.append(("query", value))
        for name, value in req.headers.items():
            if name.lower() in ("host", "content-length", "content-type"):
                continue
            items.append(("header", value))
        items.extend(("body", v) for v in self._body_strings(req))
        return items

    @staticmethod
    def _body_strings(req: RequestView) -> List[str]:
        if not req.body:
            return []
        text = req.body.decode("utf-8", errors="replace")
        ctype = req.content_type.split(";")[0].strip().lower()
        if ctype == "application/x-www-form-urlencoded":
            out: List[str] = []
            for name, value in urllib.parse.parse_qsl(text, keep_blank_values=True):
                out.extend((name, value))
            return out
        if ctype == "application/json" or ctype.endswith("+json"):
            try:
                parsed = json.loads(text)
            except ValueError:
                return [text]
            strings: List[str] = []
            _flatten(parsed, strings)
            return strings
        return [text]

    def log(self, req: RequestView, d: Decision) -> None:
        if d.would_block:
            action = "monitor"
        elif d.allowed:
            action = "allow"
        else:
            action = "block"
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "request_id": d.request_id,
            "client": req.client_ip,
            "method": req.method,
            "path": req.path[:200],
            "action": action,
            "status": d.status,
            "rule_id": d.rule_id,
            "category": d.category,
            "location": d.location,
        }
        level = logging.INFO if action == "allow" else logging.WARNING
        LOGGER.log(level, json.dumps(record))


def _flatten(node, out: List[str]) -> None:
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for key, value in node.items():
            out.append(str(key))
            _flatten(value, out)
    elif isinstance(node, (list, tuple)):
        for value in node:
            _flatten(value, out)
