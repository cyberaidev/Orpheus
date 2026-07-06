"""Pluggable local-LLM backends.

Two backends ship in the box:
  * OllamaBackend        -> POST {endpoint}/api/generate
  * OpenAICompatBackend  -> POST {endpoint}/v1/chat/completions

Both expose the same interface: .complete(prompt) -> str and .ping() -> (ok, msg).
Add your own by subclassing LLMBackend and wiring it into make_backend().
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Tuple

import requests


class LLMError(RuntimeError):
    pass


class LLMBackend(ABC):
    def __init__(self, cfg: Dict[str, Any]):
        self.model = cfg["model"]
        self.endpoint = cfg["endpoint"].rstrip("/")
        self.api_key = cfg.get("api_key", "")
        self.temperature = float(cfg.get("temperature", 0.0))
        self.timeout = int(cfg.get("timeout_seconds", 120))

    @abstractmethod
    def complete(self, prompt: str) -> str:
        """Return the model's text completion for ``prompt``."""

    @abstractmethod
    def ping(self) -> Tuple[bool, str]:
        """Cheap connectivity check. Returns (ok, human-readable message)."""


class OllamaBackend(LLMBackend):
    def complete(self, prompt: str) -> str:
        url = f"{self.endpoint}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        try:
            resp = requests.post(url, json=payload, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise LLMError(f"Ollama request failed: {exc}") from exc
        return resp.json().get("response", "")

    def ping(self) -> Tuple[bool, str]:
        try:
            resp = requests.get(f"{self.endpoint}/api/tags", timeout=10)
            resp.raise_for_status()
        except requests.RequestException as exc:
            return False, f"Cannot reach Ollama at {self.endpoint}: {exc}"
        tags = [m.get("name") for m in resp.json().get("models", [])]
        if self.model not in tags:
            return (
                False,
                f"Ollama is up but model '{self.model}' is not pulled. "
                f"Available: {', '.join(tags) or '(none)'}. "
                f"Run: ollama pull {self.model}",
            )
        return True, f"Ollama OK at {self.endpoint}, model '{self.model}' available."


class OpenAICompatBackend(LLMBackend):
    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def complete(self, prompt: str) -> str:
        url = f"{self.endpoint}/chat/completions" if self.endpoint.endswith("/v1") \
            else f"{self.endpoint}/v1/chat/completions"
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.temperature,
            "stream": False,
        }
        try:
            resp = requests.post(url, json=payload, headers=self._headers(), timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise LLMError(f"OpenAI-compat request failed: {exc}") from exc
        data = resp.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise LLMError(f"Unexpected response shape: {data}") from exc

    def ping(self) -> Tuple[bool, str]:
        base = self.endpoint if self.endpoint.endswith("/v1") else f"{self.endpoint}/v1"
        try:
            resp = requests.get(f"{base}/models", headers=self._headers(), timeout=10)
            resp.raise_for_status()
        except requests.RequestException as exc:
            return False, f"Cannot reach OpenAI-compat server at {base}: {exc}"
        return True, f"OpenAI-compat server OK at {base}, configured model '{self.model}'."


def make_backend(cfg: Dict[str, Any]) -> LLMBackend:
    backend = cfg.get("backend", "ollama").lower()
    if backend == "ollama":
        return OllamaBackend(cfg)
    if backend in ("openai_compat", "openai", "openai-compatible"):
        return OpenAICompatBackend(cfg)
    raise LLMError(
        f"Unknown backend '{backend}'. Use 'ollama' or 'openai_compat'."
    )
