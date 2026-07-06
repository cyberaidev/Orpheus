"""Configuration loading and the shared Finding data model.

Precedence (lowest -> highest): built-in DEFAULTS  <  config.yaml  <  env vars.
"""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import yaml
except ImportError:  # pragma: no cover - dependency check surfaced in CLI
    yaml = None


# --------------------------------------------------------------------------- #
# Built-in defaults (mirror config.yaml so the tool works even with no file)
# --------------------------------------------------------------------------- #
DEFAULTS: Dict[str, Any] = {
    "backend": "ollama",
    "model": "llama3.1:8b",
    "endpoint": "http://localhost:11434",
    "api_key": "",
    "temperature": 0.0,
    "timeout_seconds": 120,
    "llm_scan": True,
    "watch_paths": ["~/Downloads/Orpheus/notes"],
    "output_dir": "",
    "masking": {"mode": "copy", "style": "label"},
    "categories": {
        "classic_pii": True,
        "financial_secrets": True,
        "mip_labels": True,
        "corporate_sensitive": True,
    },
}

# Where we look for config.yaml if none is passed explicitly.
_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"

# env var name -> (dotted config key, coercer)
_ENV_MAP = {
    "ORPHEUS_BACKEND": ("backend", str),
    "ORPHEUS_MODEL": ("model", str),
    "ORPHEUS_ENDPOINT": ("endpoint", str),
    "ORPHEUS_API_KEY": ("api_key", str),
    "ORPHEUS_LLM_SCAN": ("llm_scan", lambda v: str(v).lower() in ("1", "true", "yes", "on")),
}


# --------------------------------------------------------------------------- #
# Finding model — the single currency passed between detectors, analyzer, masker
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """One detected sensitive span within a document.

    Offsets are absolute character positions into the *full* document text.
    """

    category: str          # classic_pii | financial_secrets | mip_labels | corporate_sensitive
    type: str              # e.g. EMAIL, CREDIT_CARD, MIP_LABEL, PROJECT_CODENAME
    start: int
    end: int
    text: str              # the exact matched substring
    confidence: float = 1.0
    source: str = "regex"  # regex | mip | llm
    note: str = ""         # optional explanation (mostly from the LLM)

    def line_number(self, doc: str) -> int:
        """1-indexed line the finding starts on."""
        return doc.count("\n", 0, self.start) + 1


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``override`` into a copy of ``base``."""
    out = copy.deepcopy(base)
    for key, val in (override or {}).items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = val
    return out


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Return the effective config dict (defaults + yaml + env)."""
    cfg = copy.deepcopy(DEFAULTS)

    path = config_path or os.environ.get("ORPHEUS_CONFIG") or _DEFAULT_CONFIG_PATH
    path = Path(path).expanduser()
    if path.exists():
        if yaml is None:
            raise RuntimeError(
                "pyyaml is not installed but a config.yaml exists. "
                "Run: pip install -r requirements.txt"
            )
        with open(path, "r", encoding="utf-8") as fh:
            file_cfg = yaml.safe_load(fh) or {}
        cfg = _deep_merge(cfg, file_cfg)

    # Environment overrides (highest precedence).
    for env_name, (key, coerce) in _ENV_MAP.items():
        if env_name in os.environ:
            cfg[key] = coerce(os.environ[env_name])

    # Normalise paths.
    cfg["watch_paths"] = [str(Path(p).expanduser()) for p in cfg.get("watch_paths", [])]
    if cfg.get("output_dir"):
        cfg["output_dir"] = str(Path(cfg["output_dir"]).expanduser())

    return cfg
