<div align="center">

# 🛡️ Orpheus

### Local, offline PII &amp; sensitive-data scanner for Markdown

*Find secrets, PII, and confidential content in your `.md` files — mask them — without a single byte leaving your laptop.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Runs 100% locally](https://img.shields.io/badge/inference-100%25%20local-brightgreen.svg)](#privacy--offline-guarantee)
[![Backend: Ollama](https://img.shields.io/badge/backend-Ollama%20%7C%20OpenAI--compatible-orange.svg)](#using-a-different-local-backend)

</div>

---

Orpheus watches your Markdown files (or scans them on demand), finds **PII**, **secrets**,
**Microsoft Information Protection (MIP) markings**, and **contextually-sensitive corporate
content**, highlights every finding in a report, and writes a **masked copy** — all
**100% locally**. The LLM runs on *your* machine via a backend of your choice. Nothing is
ever sent to the cloud.

## Why Orpheus?

- 🔒 **Truly offline** — deterministic regex + a **local** small LLM. No API calls, no telemetry.
- 🧠 **Hybrid detection** — regex nails structured secrets; a local LLM catches the contextual stuff regex can't.
- 🧩 **Bring your own model** — Ollama by default, or any OpenAI-compatible server (LM Studio, llama.cpp, vLLM, LocalAI).
- ♻️ **Non-destructive** — your originals are *never* modified. You get a report + a separate masked copy.
- 👀 **Watch or scan** — a background daemon that auto-scans on save, or a one-shot CLI.
- ⚙️ **Fully configurable** — every knob lives in [`config.yaml`](config.yaml) or an env var.

---

## How it works

Orpheus runs a three-layer hybrid pipeline and merges the results into one de-duplicated set of findings:

| Layer | What it catches | How |
|---|---|---|
| **1 · Regex** | emails, phones, credit cards (Luhn-validated), IBANs, SSNs, AWS/GCP/Slack/GitHub keys, private keys, JWTs, DB connection strings, IPs | fast, deterministic, offline |
| **2 · MIP markings** | textual sensitivity banners — `Sensitivity: Highly Confidential`, `Trend Micro - Confidential`, `[Internal Use Only]`, `CONFIDENTIAL` | anchored patterns (no prose false-positives) |
| **3 · Local LLM** | personal names, postal addresses, internal project codenames, unreleased financials, confidential customer references | your local model, conservative JSON-only prompt |

Findings from all three are merged, de-duplicated, written to a **report**, and applied to a
**masked copy**. Originals are never touched.

---

## Quick start

```bash
git clone https://github.com/cyberaidev/Orpheus.git
cd Orpheus
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Pull the default local model (recommended for sensitivity judgement)
ollama pull llama3.1:8b

# Verify the local LLM backend is reachable
python -m orpheus.cli test-llm

# Scan the bundled sample (contains only fake, planted test data)
python -m orpheus.cli scan tests/sample.md
```

## Usage

```bash
# Scan a file or a whole directory (recursive over *.md)
python -m orpheus.cli scan tests/sample.md
python -m orpheus.cli scan ~/Documents/notes

# Regex-only — fastest, fully deterministic, no model needed
python -m orpheus.cli scan tests/sample.md --no-llm

# Watch configured directories and auto-scan on every save/create
python -m orpheus.cli watch

# Inspect the effective, merged configuration
python -m orpheus.cli config

# Confirm the local backend + model are reachable
python -m orpheus.cli test-llm
```

For each scanned `foo.md`, Orpheus writes (next to it, or into `output_dir`):

- **`foo.orpheus-report.md`** — every finding: line, category, type, snippet, confidence, source
- **`foo.masked.md`** — a redacted copy (unless `masking.mode: report_only`)

### Example

Given input:

```markdown
Owner: Jane Doe, reachable at jane.doe@example.com or on +1 415-555-0142.
We are tracking Project Nightingale toward a projected Q4 revenue of $47.3M (not yet public).
aws_key  = AKIAIOSFODNN7EXAMPLE
```

Orpheus produces a masked copy:

```markdown
Owner: [REDACTED:PN], reachable at [REDACTED:EMAIL] or on [REDACTED:PHONE].
We are tracking [REDACTED:PCN] toward a projected Q4 revenue of [REDACTED:FIG] (not yet public).
aws_key  = [REDACTED:AWS_ACCESS_KEY]
```

…plus a report table listing every finding with its line, confidence, and which layer caught it.

---

## Configuration

Everything is customizable via [`config.yaml`](config.yaml). Key knobs:

| Setting | Purpose |
|---|---|
| `backend` | `ollama` or `openai_compat` |
| `model` | any local model tag you have loaded |
| `endpoint` | URL of your local inference server |
| `llm_scan` | master switch for the contextual LLM pass |
| `masking.mode` | `copy` (masked copy) or `report_only` |
| `masking.style` | `label` (`[REDACTED:EMAIL]`) or `block` (`████`) |
| `categories.*` | toggle each detection category on/off |
| `watch_paths` | directories the `watch` daemon monitors |

### Using a different local backend

Point Orpheus at any OpenAI-compatible local server — LM Studio, `llama.cpp --server`,
vLLM, LocalAI, text-generation-webui:

```yaml
backend: openai_compat
model: your-loaded-model-name
endpoint: http://localhost:1234/v1   # e.g. LM Studio
api_key: ""                          # usually blank for local servers
```

### Environment overrides

Any setting can be overridden without editing the file:

```bash
ORPHEUS_MODEL=qwen2.5:7b-instruct ORPHEUS_BACKEND=ollama python -m orpheus.cli scan notes/
```

Supported: `ORPHEUS_BACKEND`, `ORPHEUS_MODEL`, `ORPHEUS_ENDPOINT`, `ORPHEUS_API_KEY`,
`ORPHEUS_LLM_SCAN`, `ORPHEUS_CONFIG`.

---

## Privacy &amp; offline guarantee

Orpheus makes **no network calls** other than to the local inference `endpoint` you configure
(default `http://localhost:11434`, i.e. Ollama on your own machine). There is no telemetry,
no analytics, and no cloud fallback. Run it on an air-gapped box and it works exactly the same.

The committed [`config.yaml`](config.yaml) ships with `api_key: ""` and only local defaults —
**no secrets are included in this repository.**

---

## Project layout

```
Orpheus/
├── config.yaml                # user-editable settings
├── requirements.txt
├── orpheus/
│   ├── config.py              # config loading + the shared Finding model
│   ├── detectors/
│   │   ├── regex_rules.py     # deterministic structured-data patterns
│   │   └── mip.py             # MIP sensitivity-marking detection
│   ├── llm.py                 # pluggable Ollama / OpenAI-compatible backends
│   ├── analyzer.py            # orchestrates + de-duplicates all findings
│   ├── masker.py              # writes the report + masked copy
│   ├── watcher.py             # watchdog daemon
│   └── cli.py                 # scan / watch / config / test-llm
└── tests/
    └── sample.md              # demo note with planted FAKE data
```

---

## Limitations

- **MIP labels:** genuine MIP sensitivity labels live in Office/OLE file *metadata*, not in
  plain Markdown. Orpheus detects the **textual markings** that appear inside `.md` content.
- **Detection quality** is bounded by the local model you choose. Defaults favour precision:
  deterministic regex for structured data plus a conservative LLM prompt. Orpheus is a helper,
  **not a compliance-grade DLP guarantee** — review the report before relying on it.
- The LLM pass adds latency proportional to document size and model speed. Use `--no-llm` for a
  fast structured-only scan.

---

## License

[MIT](LICENSE) © 2026 cyberaidev
