#!/usr/bin/env python3
"""
GHOSTSEC AI - tools.py
Recon tool runners — all output returned as strings to feed into the LLM.
Tools used: nmap, whois, whatweb, curl, dig, nikto
OS: Parrot OS (all these tools are pre-installed or easily available)
"""

import subprocess


# ─────────────────────────────────────────────
# BASE RUNNER
# ─────────────────────────────────────────────

def run_tool(command: list[str], timeout: int = 120) -> str:
    """Run an allowlisted scanner without invoking a shell."""
    allowed = {"nmap", "whois", "whatweb", "curl", "dig", "nikto"}
    if not isinstance(command, list) or not command:
        raise ValueError("A non-empty command argument list is required.")
    if any(not isinstance(arg, str) or not arg or chr(0) in arg for arg in command):
        raise ValueError("Command arguments must be non-empty strings without NUL bytes.")
    if command[0] not in allowed:
        raise ValueError("Executable is not in the scanner allowlist.")
    if len(command) > 32 or any(len(arg) > 4096 for arg in command):
        raise ValueError("Scanner command exceeds argument limits.")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 300:
        raise ValueError("Scanner timeout must be between 1 and 300 seconds.")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, shell=False, check=False)
        output = (result.stdout or "").strip()
        errors = (result.stderr or "").strip()
        if output and errors:
            return output + "\n[STDERR]\n" + errors
        if output:
            return output
        if errors:
            return errors
        return "[!] Tool returned no output."
    except subprocess.TimeoutExpired:
        return "[!] Scanner timed out after {} seconds.".format(timeout)
    except FileNotFoundError:
        return "[!] Scanner executable not found: {}".format(command[0])
    except OSError as exc:
        return "[!] Scanner execution failed: {}".format(exc)


# ─────────────────────────────────────────────
# INDIVIDUAL TOOLS
# ─────────────────────────────────────────────

def run_nmap(target: str) -> str:
    """
    nmap -sV -sC -T4 --open
    -sV  : detect service versions
    -sC  : run default scripts (basic vuln checks)
    -T4  : aggressive timing (faster)
    --open : only show open ports
    """
    print(f"  [*] nmap -sV -sC -T4 --open {target}")
    return run_tool(["nmap", "-sV", "-sC", "-T4", "--open", target], timeout=180)


def run_whois(target: str) -> str:
    """
    whois — domain registration, registrar, IP ownership info
    """
    print(f"  [*] whois {target}")
    return run_tool(["whois", target], timeout=30)


def run_whatweb(target: str) -> str:
    """
    whatweb -a 3 — fingerprint web technologies, CMS, frameworks, headers
    -a 3 : aggression level 3 (active but not destructive)
    """
    print(f"  [*] whatweb -a 3 {target}")
    return run_tool(["whatweb", "-a", "3", target], timeout=60)


def run_curl_headers(target: str) -> str:
    """
    curl -sI — fetch HTTP headers only
    Reveals: server software, X-Powered-By, cookies, security headers (or lack of them)
    """
    print(f"  [*] curl -sI http://{target}")
    output = run_tool([
        "curl", "-sI",
        "--max-time", "10",
        "--location",          # follow redirects
        f"http://{target}"
    ], timeout=20)

    # also try https
    https_output = run_tool([
        "curl", "-sI",
        "--max-time", "10",
        "--location",
        "-k",                  # ignore cert errors
        f"https://{target}"
    ], timeout=20)

    return f"[HTTP Headers]\n{output}\n\n[HTTPS Headers]\n{https_output}"


def run_dig(target: str) -> str:
    """
    dig — DNS records: A, MX, NS, TXT
    Useful for subdomains, mail servers, SPF/DKIM info
    """
    print(f"  [*] dig {target} ANY")
    a_record  = run_tool(["dig", "+short", "A",   target], timeout=15)
    mx_record = run_tool(["dig", "+short", "MX",  target], timeout=15)
    ns_record = run_tool(["dig", "+short", "NS",  target], timeout=15)
    txt_record= run_tool(["dig", "+short", "TXT", target], timeout=15)

    return (
        f"[A Records]\n{a_record}\n\n"
        f"[MX Records]\n{mx_record}\n\n"
        f"[NS Records]\n{ns_record}\n\n"
        f"[TXT Records]\n{txt_record}"
    )


def run_nikto(target: str) -> str:
    """
    nikto -h — web server vulnerability scanner
    Checks for outdated software, dangerous files, misconfigurations
    WARNING: noisy tool, only run with permission
    """
    print(f"  [*] nikto -h {target}  (this may take a while...)")
    return run_tool(["nikto", "-h", target, "-nointeractive"], timeout=300)


# ─────────────────────────────────────────────
