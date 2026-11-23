"""Structured, permission-gated tool registry for GhostSec AI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


class ToolError(RuntimeError):
    """Raised when a tool request is invalid or not authorized."""


@dataclass(frozen=True)
class ToolContext:
    """Explicit approval context supplied by the human-facing application."""

    authorized_targets: tuple[str, ...] = ()
    user_confirmed: bool = False


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    handler: Callable[..., Any]
    required_args: tuple[str, ...] = ()
    allowed_args: tuple[str, ...] = ()
    target_arg: str | None = "target"
    requires_confirmation: bool = True


class ToolRegistry:
    """Register Python callables; never accepts arbitrary shell command strings."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if not spec.name or not spec.name.replace("_", "").isalnum():
            raise ValueError("Tool names must be non-empty alphanumeric identifiers.")
        if spec.name in self._tools:
            raise ValueError(f"Tool already registered: {spec.name}")
        if not set(spec.required_args).issubset(spec.allowed_args):
            raise ValueError("Every required argument must also be allowed.")
        self._tools[spec.name] = spec

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "name": spec.name,
                "description": spec.description,
                "required_args": list(spec.required_args),
                "allowed_args": list(spec.allowed_args),
            }
            for spec in self._tools.values()
        ]

    def validate(
        self, name: str, arguments: dict[str, Any], context: ToolContext | None = None
    ) -> ToolSpec:
        """Validate a tool request without executing its handler."""
        if not isinstance(name, str):
            raise ToolError("Tool name must be a string.")

        spec = self._tools.get(name)
        if spec is None:
            raise ToolError(f"Unknown tool: {name}")

        if not isinstance(arguments, dict):
            raise ToolError("Tool arguments must be a JSON object.")

        supplied = set(arguments)
        allowed = set(spec.allowed_args)
        missing = set(spec.required_args) - supplied
        extra = supplied - allowed

        if missing:
            raise ToolError(
                "Missing required arguments: "
                + ", ".join(sorted(missing))
            )
        if extra:
            raise ToolError(
                "Unexpected arguments: "
                + ", ".join(sorted(repr(item) for item in extra))
            )

        if context is None:
            context = ToolContext()

        if not isinstance(context, ToolContext):
            raise ToolError("A valid tool context is required.")

        if not isinstance(context.authorized_targets, tuple):
            raise ToolError("Authorized targets must be a tuple.")

        if any(not isinstance(item, str) for item in context.authorized_targets):
            raise ToolError("Authorized targets must contain strings.")

        if spec.requires_confirmation and context.user_confirmed is not True:
            raise ToolError(
                "Human confirmation is required before this tool can run."
            )

        if spec.target_arg:
            target = arguments.get(spec.target_arg)
            if not isinstance(target, str) or not target:
                raise ToolError(f"A valid {spec.target_arg!r} is required.")
            if target not in context.authorized_targets:
                raise ToolError(
                    "Target is not in the explicitly authorized scope."
                )

        return spec

    def execute(
        self, name: str, arguments: dict[str, Any], context: ToolContext | None = None
    ) -> Any:
        """Validate and execute one registered tool."""
        spec = self.validate(name, arguments, context)
        return spec.handler(**arguments)
