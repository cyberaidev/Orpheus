"""Command-line interface for Orpheus.

Subcommands:
    scan <path> [--no-llm] [--config CFG]   scan a file or directory (recursive *.md)
    watch [--config CFG]                    watch configured dirs and scan on change
    config [--config CFG]                   print the effective merged config
    test-llm [--config CFG]                 ping the LLM backend; exit code reflects result

Runnable as: ``python -m orpheus.cli <cmd>``.

Warnings go to stderr, results to stdout, so output can be piped cleanly. A down
or misconfigured LLM degrades scans to regex+mip rather than crashing.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .analyzer import analyze
from .config import load_config
from .llm import LLMBackend, LLMError, make_backend
from .masker import is_orpheus_output, write_outputs

# NOTE: ``watcher`` (and thus ``watchdog``) is imported lazily inside
# ``_cmd_watch`` so that the scan/config/test-llm subcommands keep working even
# when watchdog is not installed. Only ``watch`` needs the dependency.

try:
    import yaml
except ImportError:  # pragma: no cover - fall back to JSON pretty-print
    yaml = None


def _warn(msg: str) -> None:
    """Emit a warning/error on stderr (keeps stdout clean for results)."""
    print(msg, file=sys.stderr)


def _try_make_backend(cfg: Dict[str, Any]) -> Optional[LLMBackend]:
    """Build a backend, degrading to None (regex-only) on any config error."""
    try:
        return make_backend(cfg)
    except LLMError as exc:
        _warn(f"[orpheus] warning: could not build LLM backend: {exc}")
        return None


# --------------------------------------------------------------------------- #
# Subcommand handlers (each returns a process exit code)
# --------------------------------------------------------------------------- #
def _cmd_scan(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    use_llm = (not args.no_llm) and cfg.get("llm_scan", True)

    backend = _try_make_backend(cfg) if use_llm else None
    if use_llm and backend is None:
        _warn("[orpheus] proceeding regex-only (no usable LLM backend).")

    target = Path(args.path).expanduser()
    if not target.exists():
        _warn(f"[orpheus] error: path does not exist: {target}")
        return 2

    # Build the file list.
    if target.is_file():
        if is_orpheus_output(target.name):
            _warn(f"[orpheus] refusing to scan an Orpheus output file: {target}")
            return 0
        files: List[Path] = [target]
    else:
        # Recursive *.md, excluding our own outputs.
        files = sorted(
            p for p in target.rglob("*.md") if not is_orpheus_output(p.name)
        )
        if not files:
            print(f"No .md files found under {target}.")
            return 0

    n_files = 0
    total_findings = 0
    for f in files:
        try:
            doc = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            _warn(f"[orpheus] skip {f}: cannot read ({exc})")
            continue

        try:
            findings = analyze(doc, cfg, backend=backend, use_llm=use_llm)
        except LLMError as exc:
            _warn(f"[orpheus] LLM error on {f}: {exc}; scanning regex-only")
            findings = analyze(doc, cfg, backend=None, use_llm=False)

        written = write_outputs(str(f), doc, findings, cfg)
        print(f"{f}: {len(findings)} finding(s) -> {', '.join(written.values())}")
        n_files += 1
        total_findings += len(findings)

    print(f"Scanned {n_files} file(s), {total_findings} finding(s).")
    # Findings are not an error; only fail if we scanned nothing due to I/O.
    return 0 if n_files > 0 else 1


def _cmd_watch(args: argparse.Namespace) -> int:
    # Lazy import: watchdog is only required for the watch subcommand, so we
    # import it here rather than at module load. This keeps scan/config/test-llm
    # usable even when watchdog isn't installed.
    try:
        from .watcher import watch
    except ImportError as exc:
        _warn(
            f"[orpheus] watch requires watchdog, which is not installed "
            f"({exc}); run: pip install -r requirements.txt"
        )
        return 3

    cfg = load_config(args.config)
    use_llm = cfg.get("llm_scan", True)  # watch has no --no-llm; honour config
    backend = _try_make_backend(cfg) if use_llm else None
    if use_llm and backend is None:
        _warn("[orpheus] proceeding regex-only (no usable LLM backend).")
    watch(cfg, backend, use_llm=use_llm)  # blocks until Ctrl-C
    return 0


def _cmd_config(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if yaml is not None:
        print(yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False))
    else:
        # pyyaml missing — JSON is still perfectly readable.
        print(json.dumps(cfg, indent=2))
    return 0


def _cmd_test_llm(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    try:
        backend = make_backend(cfg)
    except LLMError as exc:
        _warn(f"[orpheus] {exc}")
        return 1
    ok, msg = backend.ping()
    print(msg)
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# Argparse wiring
# --------------------------------------------------------------------------- #
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="orpheus",
        description="Fully-local PII / sensitive-data scanner for Markdown files.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a file or directory (recursive *.md)")
    p_scan.add_argument("path", help="file or directory to scan")
    p_scan.add_argument("--no-llm", action="store_true", help="skip the LLM pass")
    p_scan.add_argument("--config", default=None, help="path to config.yaml")

    p_watch = sub.add_parser("watch", help="watch configured dirs and scan on change")
    p_watch.add_argument("--config", default=None, help="path to config.yaml")

    p_config = sub.add_parser("config", help="print the effective merged config")
    p_config.add_argument("--config", default=None, help="path to config.yaml")

    p_test = sub.add_parser("test-llm", help="ping the LLM backend")
    p_test.add_argument("--config", default=None, help="path to config.yaml")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Parse args and dispatch. Returns the process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "watch":
        return _cmd_watch(args)
    if args.command == "config":
        return _cmd_config(args)
    if args.command == "test-llm":
        return _cmd_test_llm(args)
    # argparse's required=True prevents reaching here, but be explicit.
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
