from __future__ import annotations

import re
from typing import Any, Callable

from .targets import normalize_target
from .tools import ToolRegistry, ToolSpec


MAX_PORT_RANGE = 1024


def _validate_hostname(value: Any, require_dot: bool = False) -> str:
    return normalize_target(value, require_dot=require_dot)


def _validate_port_range(start_port: Any, end_port: Any) -> None:
    if (
        isinstance(start_port, bool)
        or isinstance(end_port, bool)
        or not isinstance(start_port, int)
        or not isinstance(end_port, int)
    ):
        raise ValueError("Port numbers must be integers.")

    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        raise ValueError("Ports must be between 1 and 65535.")

    if end_port < start_port:
        raise ValueError("End port must be greater than or equal to start port.")

    if end_port - start_port + 1 > MAX_PORT_RANGE:
        raise ValueError(f"A scan is limited to {MAX_PORT_RANGE} ports.")


def build_ghostsec_registry(
    port_scanner: Callable[..., Any],
    subdomain_finder: Callable[..., Any],
) -> ToolRegistry:
    registry = ToolRegistry()

    def run_port_scan(target: str, start_port: int, end_port: int) -> Any:
        target = _validate_hostname(target)

        if isinstance(start_port, str) and start_port.isascii() and start_port.isdecimal():
            start_port = int(start_port)
        if isinstance(end_port, str) and end_port.isascii() and end_port.isdecimal():
            end_port = int(end_port)

        _validate_port_range(start_port, end_port)

        result = port_scanner(target, start_port, end_port)

        if result is None:
            raise RuntimeError("Port scan failed to resolve the target.")

        return result

    def run_subdomain_discovery(domain: str) -> Any:
        domain = _validate_hostname(domain, require_dot=True)
        return subdomain_finder(domain)

    registry.register(
        ToolSpec(
            name="port_scan",
            description=(
                "Scan a bounded TCP port range on a hostname or IP address "
                "explicitly authorized by the user."
            ),
            handler=run_port_scan,
            required_args=("target", "start_port", "end_port"),
            allowed_args=("target", "start_port", "end_port"),
            target_arg="target",
        )
    )

    registry.register(
        ToolSpec(
            name="subdomain_discovery",
            description=(
                "Resolve a small built-in list of common subdomains for an "
                "explicitly authorized domain."
            ),
            handler=run_subdomain_discovery,
            required_args=("domain",),
            allowed_args=("domain",),
            target_arg="domain",
        )
    )

    return registry
