"""Command line entry point for Polarizer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import ConfigError, load_config
from .guard import HostNotAllowed
from .report import render_json, render_markdown
from .scan import exit_code, run_scan
from .spec import SpecError

SAFETY_NOTE = "Only scan systems you own or are authorized to test."


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="polarizer",
        description="Replays API requests across user identities to find broken authorization. "
        + SAFETY_NOTE,
    )
    parser.add_argument("--version", action="version", version=f"polarizer {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a target for authorization flaws.")
    scan.add_argument("--config", required=True, help="Path to the Polarizer config file.")
    scan.add_argument("--base-url", help="Override target.base_url from the config.")
    scan.add_argument("--spec", help="Override target.spec from the config.")
    scan.add_argument(
        "--allow-host",
        action="append",
        default=[],
        metavar="HOST",
        help="Permit a non-localhost host. Repeatable. You are asserting you may test it.",
    )
    scan.add_argument("--rate", type=float, default=5.0, help="Max requests per second (default 5).")
    scan.add_argument(
        "--allow-writes",
        action="store_true",
        help="Permit the mass-assignment check to send writes (it restores the value after).",
    )
    scan.add_argument(
        "--format",
        choices=["md", "json", "both"],
        default="md",
        help="Report format written to --out-dir (default md).",
    )
    scan.add_argument("--out-dir", help="Directory to write report files into.")
    scan.add_argument("--quiet", action="store_true", help="Do not print the report to stdout.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "scan":  # pragma: no cover - argparse enforces this
        return 2

    try:
        config = load_config(args.config, base_url=args.base_url, spec=args.spec)
        results = run_scan(
            config,
            allowed_hosts=args.allow_host,
            rate=args.rate,
            allow_writes=args.allow_writes,
        )
    except (ConfigError, SpecError, HostNotAllowed, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    markdown = render_markdown(results, config)
    if args.out_dir:
        _write_reports(Path(args.out_dir), results, config, args.format)
    if not args.quiet:
        print(markdown)

    code = exit_code(results)
    summary = (
        f"{len(results.findings)} finding(s), {len(results.inconclusive)} inconclusive, "
        f"{len(results.skipped)} skipped. Exit {code}."
    )
    print(summary, file=sys.stderr)
    return code


def _write_reports(out_dir: Path, results, config, fmt: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    if fmt in ("md", "both"):
        (out_dir / "polarizer-report.md").write_text(render_markdown(results, config), encoding="utf-8")
    if fmt in ("json", "both"):
        (out_dir / "polarizer-report.json").write_text(render_json(results, config), encoding="utf-8")
