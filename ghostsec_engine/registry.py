from __future__ import annotations

import ipaddress
import importlib
import requests
from typing import Any

from ai_core.integrations import build_ghostsec_registry as build_base_registry
from ai_core.tools import ToolRegistry, ToolSpec
from .tools import run_dig, run_nikto, run_nmap, run_whatweb, run_whois


def validate_target(target: Any) -> str:
    if not isinstance(target, str) or not target or target != target.strip() or len(target) > 253:
        raise ValueError("A valid hostname or IP address is required.")
    if any(character.isspace() for character in target):
        raise ValueError("Whitespace is not permitted in a target.")
    if any(character in target for character in ("/", chr(92), "@", "?", "#")):
        raise ValueError("Provide a hostname or IP address, not a URL.")
    candidate = target.rstrip(".")
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    if not candidate or len(candidate) > 253:
        raise ValueError("Invalid hostname.")
    for label in candidate.split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise ValueError("Invalid hostname label.")
        if any(not (character.isascii() and (character.isalnum() or character == "-")) for character in label):
            raise ValueError("Invalid hostname characters.")
    return candidate


def run_headers(target: str) -> str:
    target = validate_target(target)
    results = []
    for scheme in ("https", "http"):
        try:
            response = requests.head(
                f"{scheme}://{target}",
                timeout=10,
                allow_redirects=False,
            )
            headers = chr(10).join(
                f"{key}: {value}" for key, value in response.headers.items()
            )
            results.append(
                f"[{scheme.upper()}] Status: {response.status_code}{chr(10)}{headers}"
            )
        except requests.RequestException as exc:
            results.append(f"[{scheme.upper()}] Request failed: {exc}")
    return (chr(10) * 2).join(results)

def validate_search_query(query: Any) -> str:
    if not isinstance(query, str) or not query.strip() or len(query) > 512:
        raise ValueError("Search query must contain 1 to 512 characters.")
    return query.strip()


def build_full_registry(port_scanner, subdomain_finder) -> ToolRegistry:
    registry = build_base_registry(port_scanner, subdomain_finder)

    target_tools = [
        ("nmap_scan", "Run a service and port assessment using Nmap.", run_nmap),
        ("whois_lookup", "Retrieve domain or IP registration information.", run_whois),
        ("whatweb_scan", "Fingerprint web technologies on an authorized host.", run_whatweb),
        ("headers_lookup", "Retrieve HTTP headers without following redirects.", run_headers),
        ("dns_lookup", "Retrieve DNS A, MX, NS and TXT records.", run_dig),
        ("nikto_scan", "Run an active web-server assessment using Nikto. Requires explicit approval.", run_nikto),
    ]

    for name, description, handler in target_tools:
        registry.register(ToolSpec(
            name=name,
            description=description,
            handler=lambda target, fn=handler: fn(validate_target(target)),
            required_args=("target",),
            allowed_args=("target",),
            target_arg="target",
        ))

    registry.register(ToolSpec(
        name="search_intel",
        description="Search public security intelligence, CVEs and remediation guidance.",
        handler=lambda query: importlib.import_module(".search", __package__).handle_search_dispatch(validate_search_query(query)),
        required_args=("query",),
        allowed_args=("query",),
        target_arg=None,
        requires_confirmation=False,
    ))

    return registry
