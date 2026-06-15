#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="HTTPS endpoint to POST findings to.")
    ap.add_argument("--header", action="append", default=[], help="Key: Value")
    args = ap.parse_args()

    if not args.url.startswith(("http://", "https://")):
        print(
            f"webhook: invalid URL (must start with http:// or https://): {args.url}",
            file=sys.stderr,
        )
        return 2

    payload = sys.stdin.buffer.read()
    if not payload:
        print("webhook: no input on stdin — nothing to send.", file=sys.stderr)
        return 2

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        if not k.strip():
            print(f"webhook: malformed --header value (no key): {h!r}", file=sys.stderr)
            return 2
        req.add_header(k.strip(), v.strip())
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except Exception as e:
        print(f"webhook error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
