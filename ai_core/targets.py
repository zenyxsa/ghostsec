"""Canonical validation for explicitly authorized network targets."""

from __future__ import annotations

import ipaddress
import re
from typing import Any


_NUMERIC_ADDRESS = re.compile(r"[0-9.]+")


def normalize_target(value: Any, require_dot: bool = False) -> str:
    """Return a canonical IP/hostname or reject ambiguous and malformed targets.

    IP addresses are normalized through :mod:`ipaddress`. Hostnames are
    checked as ASCII DNS labels and lower-cased. Numeric dotted strings that
    are not valid IPv4 addresses are rejected instead of being passed to
    platform-specific legacy address parsers.
    """
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 253
        or any(character.isspace() for character in value)
        or any(character in value for character in ("/", chr(92), "@", "?", "#"))
    ):
        raise ValueError("A valid hostname or IP address is required.")

    candidate = value[:-1] if value.endswith(".") else value
    if not candidate:
        raise ValueError("A valid hostname or IP address is required.")

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        if _NUMERIC_ADDRESS.fullmatch(candidate):
            raise ValueError(
                "Malformed numeric IP address; use canonical IPv4 or IPv6 notation."
            ) from None

        labels = candidate.split(".")
        for label in labels:
            if (
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or re.fullmatch(r"[A-Za-z0-9-]+", label) is None
            ):
                raise ValueError("Invalid hostname or domain.")

        normalized = candidate.lower()
        if require_dot and "." not in normalized:
            raise ValueError("A fully qualified domain name is required.")
        return normalized

    if require_dot:
        raise ValueError("A domain name is required, not an IP address.")
    return str(address)
