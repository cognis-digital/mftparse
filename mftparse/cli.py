"""Command-line interface for MFTPARSE."""
from __future__ import annotations

import argparse
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    analyze,
    parse_mft_csv,
    render_html,
    render_json,
    render_table,
)


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        return fh.read()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Analyze an NTFS $MFT CSV export for timestomping and "
                    "suspicious file activity (defensive forensics).",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command")

    p_an = sub.add_parser(
        "analyze", help="Analyze an $MFT CSV and report findings."
    )
    p_an.add_argument("input", help="Path to $MFT CSV export, or '-' for stdin.")
    p_an.add_argument(
        "--format", choices=["table", "json", "html"], default="table",
        help="Output format (default: table). 'html' writes a shareable report.",
    )
    p_an.add_argument(
        "-o", "--output", default="-",
        help="Write report to a file instead of stdout.",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help(sys.stderr)
        return 2

    if args.command == "analyze":
        try:
            text = _read_input(args.input)
        except OSError as exc:
            print(f"{TOOL_NAME}: error reading input: {exc}", file=sys.stderr)
            return 2
        try:
            records = parse_mft_csv(text)
        except Exception as exc:
            print(f"{TOOL_NAME}: failed to parse CSV: {exc}", file=sys.stderr)
            return 2
        try:
            result = analyze(records)
        except Exception as exc:
            print(f"{TOOL_NAME}: analysis error: {exc}", file=sys.stderr)
            return 2

        if args.format == "json":
            report = render_json(result)
        elif args.format == "html":
            report = render_html(result)
        else:
            report = render_table(result)

        if args.output and args.output != "-":
            try:
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(report)
            except OSError as exc:
                print(f"{TOOL_NAME}: error writing output: {exc}", file=sys.stderr)
                return 2
            print(f"{TOOL_NAME}: wrote {args.format} report to {args.output} "
                  f"({len(result.findings)} findings)", file=sys.stderr)
        else:
            print(report)

        # Non-zero exit when findings exist (pipeline-friendly).
        return 1 if result.has_findings else 0

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
