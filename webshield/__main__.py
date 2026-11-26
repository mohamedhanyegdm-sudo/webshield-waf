"""Command line entry point: python -m webshield --upstream http://127.0.0.1:5000"""

import argparse
import logging
import sys

from .engine import WAF, load_config
from .proxy import make_proxy_server

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="webshield",
        description="Reverse-proxy web application firewall. Protect only apps you own or run.")
    parser.add_argument("--upstream", required=True, help="app to protect, e.g. http://127.0.0.1:5000")
    parser.add_argument("--listen", default="127.0.0.1:8080", help="host:port to listen on")
    parser.add_argument("--rules", help="path to a JSON rules file (default: bundled rules)")
    parser.add_argument("--mode", choices=("block", "monitor"), help="override the file's mode")
    parser.add_argument("--log-file", help="also append JSON log lines to this file")
    parser.add_argument("--allow-non-loopback", action="store_true",
                        help="permit listening on a non-loopback address")
    args = parser.parse_args(argv)

    host, _, port = args.listen.rpartition(":")
    host = host or "127.0.0.1"
    if host not in LOOPBACK and not args.allow_non_loopback:
        print("Refusing to listen on %s. Use --allow-non-loopback if you really mean it." % host,
              file=sys.stderr)
        return 2

    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=handlers)

    overrides = {"mode": args.mode} if args.mode else None
    waf = WAF(load_config(args.rules, overrides))
    server = make_proxy_server(host, int(port), args.upstream, waf)
    print("webshield listening on http://%s:%s -> %s (mode: %s, %d rules)"
          % (host, port, args.upstream, waf.config.mode, len(waf.rules)), file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
