"""webshield: a small, local-first web application firewall for Python apps."""

from .engine import (
    Config,
    Decision,
    RateLimiter,
    RequestView,
    Rule,
    WAF,
    load_config,
)
from .middleware import WAFMiddleware

__all__ = [
    "Config",
    "Decision",
    "RateLimiter",
    "RequestView",
    "Rule",
    "WAF",
    "WAFMiddleware",
    "load_config",
]
__version__ = "1.0.0"
