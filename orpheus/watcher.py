"""Filesystem watcher — scans Markdown files as they change.

Watches ``cfg["watch_paths"]`` recursively; on a ``.md`` create/modify/move it
debounces ~1.5s (editors emit a burst of events per save) then runs the full
analyzer and writes outputs via the masker.

Critical correctness property: Orpheus writes its own ``.masked.md`` /
``.orpheus-report.md`` files into the very tree it is watching. Those writes
fire modify events too — ``is_orpheus_output`` filters them so we never loop.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from threading import Lock, Timer
from typing import Any, Dict, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .analyzer import analyze
from .llm import LLMBackend, LLMError
from .masker import is_orpheus_output, write_outputs

# Editors save in a flurry of writes; coalesce them into one scan per file.
_DEBOUNCE_SECONDS = 1.5


def _is_output_file(path: str) -> bool:
    """True for non-markdown paths and for Orpheus's own output files.

    Anything this returns True for is skipped by the watcher — either it's not
    a Markdown file we care about, or it's an artefact we ourselves produced.
    """
    if not path.endswith(".md"):
        return True
    return is_orpheus_output(path)


class _MarkdownScanHandler(FileSystemEventHandler):
    """Debounced watchdog handler that scans one Markdown file per event burst."""

    def __init__(self, cfg: Dict[str, Any], backend: Optional[LLMBackend], use_llm: bool):
        self._cfg = cfg
        self._backend = backend  # single reused instance across all events
        self._use_llm = use_llm
        self._timers: Dict[str, Timer] = {}
        self._lock = Lock()

    # watchdog event hooks --------------------------------------------------- #
    def on_created(self, event) -> None:
        self._maybe_schedule(event)

    def on_modified(self, event) -> None:
        self._maybe_schedule(event)

    def on_moved(self, event) -> None:
        # A rename/move: treat the destination as a fresh modify if it's a .md.
        self._maybe_schedule(event)

    # scheduling ------------------------------------------------------------- #
    def _maybe_schedule(self, event) -> None:
        if event.is_directory:
            return
        # For moves, the interesting path is where the file landed.
        path = getattr(event, "dest_path", None) or event.src_path
        if _is_output_file(path):
            return

        # Debounce per-path: replace any pending timer for this file so a burst
        # of modify events collapses into a single scan after quiet settles.
        with self._lock:
            existing = self._timers.pop(path, None)
            if existing is not None:
                existing.cancel()
            timer = Timer(_DEBOUNCE_SECONDS, self._scan, args=[path])
            self._timers[path] = timer
            timer.start()

    def _scan(self, path: str) -> None:
        # The whole body is guarded: a raised exception inside a watchdog
        # callback thread can wedge the Observer, so we never let one escape.
        try:
            with self._lock:
                self._timers.pop(path, None)

            # The file may have been deleted/renamed during the debounce window.
            if not os.path.exists(path):
                return
            if _is_output_file(path):  # defensive re-check
                return

            try:
                doc = Path(path).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                print(f"[orpheus] skip {path}: cannot read ({exc})")
                return

            try:
                findings = analyze(
                    doc, self._cfg, backend=self._backend, use_llm=self._use_llm
                )
            except LLMError as exc:
                # Mirror the CLI's graceful degradation: fall back to regex+mip.
                print(f"[orpheus] LLM error on {path}: {exc}; scanning regex-only")
                findings = analyze(doc, self._cfg, backend=None, use_llm=False)

            written = write_outputs(path, doc, findings, self._cfg)
            print(
                f"[orpheus] {path} -> {len(findings)} finding(s); "
                f"wrote {', '.join(written.values())}"
            )
        except Exception as exc:  # noqa: BLE001 - keep the observer thread alive
            print(f"[orpheus] scan failed for {path}: {exc}")

    def cancel_pending(self) -> None:
        """Cancel and clear any outstanding debounce timers (for clean exit)."""
        with self._lock:
            for timer in self._timers.values():
                timer.cancel()
            self._timers.clear()


def watch(cfg: Dict[str, Any], backend: Optional[LLMBackend], use_llm: bool = True) -> None:
    """Watch ``cfg["watch_paths"]`` until Ctrl-C, scanning Markdown on change."""
    raw_paths = cfg.get("watch_paths", [])

    # Only directories are watchable here; warn+skip files (watch_paths are dirs
    # by design, and recursive dir-watch is what we need for a notes folder).
    watch_dirs = []
    for p in raw_paths:
        if os.path.isdir(p):
            watch_dirs.append(p)
        elif os.path.exists(p):
            print(f"[orpheus] warning: not a directory, skipping: {p}")
        else:
            print(f"[orpheus] warning: watch path does not exist: {p}")

    if not watch_dirs:
        print("[orpheus] error: no existing watch directories; nothing to do.")
        return

    # One handler instance -> one reused backend across every event.
    handler = _MarkdownScanHandler(cfg, backend, use_llm)
    observer = Observer()
    for d in watch_dirs:
        observer.schedule(handler, d, recursive=True)

    llm_on = use_llm and cfg.get("llm_scan", True) and backend is not None
    print("[orpheus] watching:")
    for d in watch_dirs:
        print(f"  - {d}")
    print(f"[orpheus] LLM pass: {'on' if llm_on else 'off'}  (Ctrl-C to stop)")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[orpheus] stopping…")
    finally:
        # Stop delivering events, then cancel any outstanding debounce timers
        # *before* joining so a timer can't fire a fresh scan mid-shutdown. A
        # timer that already fired is a no-op (its file still scans safely).
        observer.stop()
        handler.cancel_pending()
        observer.join()
