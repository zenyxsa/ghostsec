"""Small standard-library client for a local Ollama instance."""

from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class OllamaError(RuntimeError):
    """Raised when the local Ollama service cannot complete a request."""


class OllamaClient:
    def __init__(self, model: str | None = None, host: str | None = None, timeout: int = 180):
        self.host = (host or os.getenv("GHOSTSEC_OLLAMA_HOST", "http://127.0.0.1:11434")).rstrip("/")
        self.model = model or os.getenv("GHOSTSEC_OLLAMA_MODEL", "qwen2.5:3b")
        self.timeout = timeout

    def _request(self, path: str, payload: dict | None = None) -> dict:
        url = f"{self.host}{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"} if data is not None else {},
            method="POST" if data is not None else "GET",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise OllamaError(f"Ollama returned HTTP {exc.code}: {detail[:500]}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise OllamaError(
                "Cannot reach Ollama at "
                f"{self.host}. Start the Ollama service and check that a model is installed. "
                f"Details: {exc}"
            ) from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OllamaError("Ollama returned an invalid JSON response.") from exc

    def list_models(self) -> list[str]:
        data = self._request("/api/tags")
        return [item.get("name", "") for item in data.get("models", []) if item.get("name")]

    def chat(self, messages: list[dict[str, str]]) -> str:
        data = self._request(
            "/api/chat",
            {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": 0.2},
            },
        )
        content = data.get("message", {}).get("content", "")
        if not content:
            raise OllamaError("The local model returned an empty response.")
        return content.strip()
