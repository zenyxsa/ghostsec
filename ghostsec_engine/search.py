#!/usr/bin/env python3
"""Public security-intelligence search and safe public-page text extraction.

Search results and fetched page content are untrusted input. Page fetching is
restricted to public HTTP(S) hosts, pins connections to validated DNS results,
and never follows redirects.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from urllib.parse import quote, urlsplit

from bs4 import BeautifulSoup
from ddgs import DDGS


MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_FETCH_CHARS = 20000
FETCH_TIMEOUT = 15


class SearchError(RuntimeError):
    """Raised when a public intelligence search fails."""


class PageFetchError(RuntimeError):
    """Raised when a public page cannot be fetched safely."""


def web_search(query: str, max_results: int = 5) -> str:
    """Search DuckDuckGo and return formatted public results."""
    if not isinstance(query, str) or not query.strip() or len(query) > 512:
        raise ValueError("Search query must contain 1 to 512 characters.")
    if isinstance(max_results, bool) or not isinstance(max_results, int) or not 1 <= max_results <= 10:
        raise ValueError("Search result count must be between 1 and 10.")

    print(f"  [*] Searching: {query}")
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query.strip(), max_results=max_results))
        if not results:
            return "[!] No search results found."

        output = f"[WEB SEARCH RESULTS FOR: {query.strip()}]\n"
        output += "─" * 50 + "\n"
        for index, item in enumerate(results, 1):
            title = str(item.get("title", "(untitled)"))[:500]
            href = str(item.get("href", ""))[:2048]
            snippet = str(item.get("body", ""))[:2000]
            output += f"\n[{index}] {title}\n"
            output += f"    URL     : {href}\n"
            output += f"    Snippet : {snippet}\n"
        return output
    except Exception as exc:
        raise SearchError(f"Public web search failed: {exc}") from exc


def search_cve(cve_id: str) -> str:
    """Search for a CVE and attempt a safe, public MITRE page lookup."""
    print(f"  [*] Looking up {cve_id}...")
    ddg_results = web_search(f"{cve_id} vulnerability exploit details", max_results=3)
    mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    try:
        mitre_data = fetch_page(mitre_url, max_chars=2000)
    except PageFetchError as exc:
        mitre_data = f"[!] MITRE page lookup unavailable: {exc}"
    return f"{ddg_results}\n\n[MITRE CVE LOOKUP: {cve_id}]\n{mitre_data}"


def search_exploit(service: str, version: str) -> str:
    """Find public vulnerability references; this function does not run exploits."""
    return web_search(f"{service} {version} exploit CVE vulnerability", max_results=5)


def search_fix(vuln_name: str) -> str:
    """Search for public mitigation and patch guidance."""
    return web_search(f"how to fix {vuln_name} security mitigation patch", max_results=3)


def _public_addresses(host: str, port: int) -> tuple[str, ...]:
    """Resolve a host and reject the entire answer if any address is non-public."""
    try:
        literal = ipaddress.ip_address(host)
        records = [literal]
    except ValueError:
        try:
            raw_records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise PageFetchError(f"Could not resolve public host {host}: {exc}") from exc
        records = []
        for record in raw_records:
            try:
                address = ipaddress.ip_address(record[4][0])
            except (ValueError, IndexError, TypeError):
                continue
            records.append(address)

    if not records:
        raise PageFetchError(f"No IP addresses were returned for {host}.")

    normalized = []
    for address in records:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if not address.is_global:
            raise PageFetchError(
                f"Refusing to fetch {host}: it resolves to a non-public address."
            )
        value = address.compressed
        if value not in normalized:
            normalized.append(value)
    return tuple(normalized)


def fetch_page(url: str, max_chars: int = 3000) -> str:
    """Fetch and extract text from one public HTTP(S) URL without following redirects."""
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise PageFetchError("URL must contain 1 to 2,048 characters.")
    if any(ord(char) <= 32 or ord(char) == 127 for char in url):
        raise PageFetchError("URL must not contain whitespace or control characters.")
    if (
        isinstance(max_chars, bool)
        or not isinstance(max_chars, int)
        or not 1 <= max_chars <= MAX_FETCH_CHARS
    ):
        raise ValueError(f"max_chars must be between 1 and {MAX_FETCH_CHARS}.")

    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise PageFetchError("Only HTTP and HTTPS URLs are allowed.")
        if not parsed.netloc or not parsed.hostname:
            raise PageFetchError("URL must include a hostname.")
        if parsed.username is not None or parsed.password is not None:
            raise PageFetchError("URLs containing embedded credentials are not allowed.")
        host = parsed.hostname.encode("idna").decode("ascii")
        port = parsed.port or (443 if scheme == "https" else 80)
    except PageFetchError:
        raise
    except (UnicodeError, ValueError) as exc:
        raise PageFetchError(f"Invalid URL: {exc}") from exc

    addresses = _public_addresses(host, port)
    raw_socket = None
    connection = None
    try:
        last_error = None
        for address in addresses:
            try:
                raw_socket = socket.create_connection((address, port), timeout=FETCH_TIMEOUT)
                peer = ipaddress.ip_address(raw_socket.getpeername()[0])
                if not peer.is_global:
                    raise PageFetchError("Connected peer is not a public IP address.")
                if peer != ipaddress.ip_address(address):
                    raise PageFetchError("Connected peer did not match the validated destination.")
                break
            except PageFetchError:
                if raw_socket is not None:
                    raw_socket.close()
                    raw_socket = None
                raise
            except OSError as exc:
                last_error = exc
                if raw_socket is not None:
                    raw_socket.close()
                    raw_socket = None
        if raw_socket is None:
            raise PageFetchError(f"Could not connect to public host {host}: {last_error}")

        connection_class = (
            http.client.HTTPSConnection if scheme == "https"
            else http.client.HTTPConnection
        )
        if scheme == "https":
            raw_socket = ssl.create_default_context().wrap_socket(
                raw_socket, server_hostname=host
            )
        connection = connection_class(host=host, port=port, timeout=FETCH_TIMEOUT)
        connection.sock = raw_socket

        path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        query = quote(parsed.query, safe="=&?/:@!$'()*+,;%-._~")
        request_target = path + (f"?{query}" if query else "")
        connection.request(
            "GET",
            request_target,
            headers={
                "User-Agent": "GhostSec/1.0 (public security research)",
                "Accept": "text/html,text/plain;q=0.9,*/*;q=0.1",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise PageFetchError(
                "Redirects are not followed. Review the destination URL separately."
            )
        if not 200 <= response.status < 300:
            raise PageFetchError(f"Page server returned HTTP {response.status}.")

        content_encoding = (response.getheader("Content-Encoding") or "identity").lower()
        if content_encoding not in {"", "identity"}:
            raise PageFetchError("Compressed page responses are not accepted.")
        content_length = response.getheader("Content-Length")
        if content_length:
            try:
                if int(content_length) > MAX_PAGE_BYTES:
                    raise PageFetchError("Page exceeds the 2 MiB response limit.")
            except ValueError as exc:
                raise PageFetchError("Page server returned an invalid Content-Length.") from exc

        raw_content = response.read(MAX_PAGE_BYTES + 1)
        if len(raw_content) > MAX_PAGE_BYTES:
            raise PageFetchError("Page exceeds the 2 MiB response limit.")
        charset = response.headers.get_content_charset() or "utf-8"
        html = raw_content.decode(charset, errors="replace")

        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()
        clean = "\n".join(
            line for line in soup.get_text(separator="\n", strip=True).splitlines()
            if line.strip()
        )
        if len(clean) > max_chars:
            clean = clean[:max_chars] + f"\n... [truncated at {max_chars} chars]"
        return clean
    except PageFetchError:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise PageFetchError(f"Public page fetch failed: {exc}") from exc
    finally:
        if connection is not None:
            connection.close()
        elif raw_socket is not None:
            raw_socket.close()


def handle_search_dispatch(query: str) -> str:
    """Route a bounded query to CVE, mitigation, or general public search."""
    query = query.strip()
    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", query, re.IGNORECASE)
    if cve_match:
        return search_cve(cve_match.group())
    lowered = query.lower()
    if any(word in lowered for word in ("exploit", "poc", "payload", "rce", "lfi", "sqli")):
        return web_search(query + " exploit poc github", max_results=5)
    if any(word in lowered for word in ("fix", "patch", "mitigate", "harden", "secure")):
        return search_fix(query)
    return web_search(query, max_results=5)


if __name__ == "__main__":
    print("[ GhostSec public search test ]\n")
    print("[1] General search")
    print("[2] CVE lookup")
    print("[3] Fetch a public URL")
    choice = input("Choice: ").strip()
    if choice == "1":
        print(web_search(input("Query: ").strip()))
    elif choice == "2":
        print(search_cve(input("CVE ID (e.g. CVE-2021-44228): ").strip()))
    elif choice == "3":
        print(fetch_page(input("URL: ").strip()))
