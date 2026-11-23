"""GhostSec's optional, local-first AI layer."""

from .analyst import analyze_file, run_chat
from .client import OllamaClient, OllamaError

__all__ = ["OllamaClient", "OllamaError", "analyze_file", "run_chat"]
