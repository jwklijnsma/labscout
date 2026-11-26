"""Minimal Ollama client (local or remote server).

Requests are streamed so a slow-but-working generation is never killed by a fixed read
timeout: `timeout` is the maximum silence between two chunks (or before the first one),
`deadline` caps the whole request, and `num_predict` stops runaway generations.
A timeout is NOT retried with the same prompt (it would just time out again); it raises
OllamaTimeout so the caller can split the work instead.
"""

from __future__ import annotations

import json
import re
import time

import requests


class OllamaError(RuntimeError):
    pass


class OllamaTimeout(OllamaError):
    """The model was too slow for this prompt; retrying the same prompt will not help."""


class OllamaClient:
    def __init__(self, host: str, model: str, *, api_key: str = "", timeout: int = 600,
                 retries: int = 2, temperature: float = 0.1, num_ctx: int = 16384,
                 num_predict: int = 4096, deadline: int = 0, keep_alive: str = "30m"):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout            # max seconds of silence (queue wait + generation)
        self.deadline = deadline or timeout * 2   # max seconds for one whole request
        self.retries = retries
        self.temperature = temperature
        self.num_ctx = num_ctx
        self.num_predict = num_predict
        self.keep_alive = keep_alive
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "labscout"
        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"
        self._schema_supported = True
        self.tokens_in = 0
        self.tokens_out = 0
        self.last_stats: dict = {}

    # -- health ----------------------------------------------------------------
    def version(self) -> str:
        r = self.session.get(f"{self.host}/api/version", timeout=15)
        r.raise_for_status()
        return r.json().get("version", "?")

    def models(self) -> list[str]:
        r = self.session.get(f"{self.host}/api/tags", timeout=15)
        r.raise_for_status()
        return [m.get("name", "") for m in r.json().get("models", [])]

    def has_model(self) -> bool:
        names = self.models()
        want = self.model if ":" in self.model else self.model + ":latest"
        return want in names or self.model in names

    def running(self) -> list[dict]:
        """Models loaded on the server right now (/api/ps)."""
        r = self.session.get(f"{self.host}/api/ps", timeout=15)
        r.raise_for_status()
        return r.json().get("models", [])

    # -- chat ------------------------------------------------------------------
    def _stream(self, payload: dict) -> str:
        start = time.monotonic()
        parts: list[str] = []
        with self.session.post(f"{self.host}/api/chat", json=payload, stream=True,
                               timeout=(15, self.timeout)) as r:
            if r.status_code == 400 and self._schema_supported and "format" in r.text:
                raise _SchemaUnsupported()
            if r.status_code == 404:
                raise OllamaError(f"model '{self.model}' not found on {self.host} "
                                  f"(run: ollama pull {self.model})")
            r.raise_for_status()
            for line in r.iter_lines():
                if not line:
                    continue
                data = json.loads(line)
                if data.get("error"):
                    raise OllamaError(f"Ollama: {data['error']}")
                parts.append((data.get("message") or {}).get("content", ""))
                if data.get("done"):
                    self.last_stats = {k: data.get(k) for k in (
                        "prompt_eval_count", "prompt_eval_duration", "eval_count",
                        "eval_duration", "load_duration", "total_duration")}
                    self.tokens_in += data.get("prompt_eval_count", 0) or 0
                    self.tokens_out += data.get("eval_count", 0) or 0
                    if data.get("done_reason") == "length":
                        raise OllamaTimeout(
                            f"output hit num_predict={self.num_predict} (model looping or "
                            "too much work in one request)")
                    break
                if time.monotonic() - start > self.deadline:
                    raise OllamaTimeout(f"request exceeded {self.deadline}s")
        return "".join(parts)

    def chat_json(self, system: str, user: str, schema: dict) -> dict:
        payload = {
            "model": self.model,
            "stream": True,
            "keep_alive": self.keep_alive,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "format": schema if self._schema_supported else "json",
            "options": {"temperature": self.temperature, "num_ctx": self.num_ctx,
                        "num_predict": self.num_predict},
        }
        last_exc: Exception | None = None
        attempt = 0
        while attempt <= self.retries:
            try:
                return parse_json_lenient(self._stream(payload))
            except _SchemaUnsupported:
                # Older Ollama (< 0.5) only knows format: "json"
                self._schema_supported = False
                payload["format"] = "json"
                continue
            except OllamaError:
                raise
            except (requests.Timeout, requests.exceptions.ChunkedEncodingError) as exc:
                raise OllamaTimeout(f"no output for {self.timeout}s ({exc.__class__.__name__})")
            except (requests.RequestException, ValueError) as exc:
                if "timed out" in str(exc).lower():   # read timeout mid-stream
                    raise OllamaTimeout(f"no output for {self.timeout}s")
                last_exc = exc
                attempt += 1
                if attempt <= self.retries:
                    time.sleep(2 * attempt)
        raise OllamaError(f"Ollama request failed after {self.retries + 1} attempts: {last_exc}")


class _SchemaUnsupported(Exception):
    pass


def parse_json_lenient(text: str) -> dict:
    """Parse model output that should be JSON, tolerating code fences and chatter."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("model returned no JSON object")
        data = json.loads(text[start:end + 1])
    if isinstance(data, list):
        data = {"findings": data}
    if not isinstance(data, dict):
        raise ValueError("model returned JSON that is not an object")
    return data
