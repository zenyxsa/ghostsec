#!/usr/bin/env python3
"""GhostSec scanner runners with explicit execution-failure reporting."""

import subprocess


class ScannerExecutionError(RuntimeError):
    """Raised when an approved scanner cannot complete successfully."""


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
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            shell=False, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerExecutionError(
            "Scanner timed out after {} seconds.".format(timeout)
        ) from exc
    except FileNotFoundError as exc:
        raise ScannerExecutionError(
            "Scanner executable is not installed or not on PATH: {}".format(command[0])
        ) from exc
    except OSError as exc:
        raise ScannerExecutionError("Scanner execution failed: {}".format(exc)) from exc

    output = (result.stdout or "").strip()
    errors = (result.stderr or "").strip()
    return_code = getattr(result, "returncode", 0)

    if return_code != 0:
        details = "\n".join(part for part in (output, errors) if part)
        message = "{} exited with status {}.".format(command[0], return_code)
        if details:
            message += "\n" + details
        raise ScannerExecutionError(message)

    if output and errors:
        return output + "\n[STDERR]\n" + errors
    if output:
        return output
    if errors:
        return errors
    return "[!] Tool returned no output."


def run_nmap(target: str) -> str:
    """Run Nmap service/version detection and default scripts on an authorized target."""
    print(f"  [*] nmap -sV -sC -T4 --open {target}")
    return run_tool(["nmap", "-sV", "-sC", "-T4", "--open", target], timeout=180)


def run_whois(target: str) -> str:
    """Retrieve domain or IP registration information."""
    print(f"  [*] whois {target}")
    return run_tool(["whois", target], timeout=30)


def run_whatweb(target: str) -> str:
    """Fingerprint web technologies on an authorized host."""
    print(f"  [*] whatweb -a 3 {target}")
    return run_tool(["whatweb", "-a", "3", target], timeout=60)


def run_curl_headers(target: str) -> str:
    """Retrieve HTTP headers for an authorized host."""
    print(f"  [*] curl -sI http://{target}")
    output = run_tool([
        "curl", "-sI", "--max-time", "10", "--location", f"http://{target}"
    ], timeout=20)
    https_output = run_tool([
        "curl", "-sI", "--max-time", "10", "--location", "-k", f"https://{target}"
    ], timeout=20)
    return f"[HTTP Headers]\n{output}\n\n[HTTPS Headers]\n{https_output}"


def run_dig(target: str) -> str:
    """Retrieve A, MX, NS and TXT DNS records."""
    print(f"  [*] dig {target} ANY")
    a_record = run_tool(["dig", "+short", "A", target], timeout=15)
    mx_record = run_tool(["dig", "+short", "MX", target], timeout=15)
    ns_record = run_tool(["dig", "+short", "NS", target], timeout=15)
    txt_record = run_tool(["dig", "+short", "TXT", target], timeout=15)
    return (
        f"[A Records]\n{a_record}\n\n"
        f"[MX Records]\n{mx_record}\n\n"
        f"[NS Records]\n{ns_record}\n\n"
        f"[TXT Records]\n{txt_record}"
    )


def run_nikto(target: str) -> str:
    """Run Nikto after explicit approval; this is an active, noisy check."""
    print(f"  [*] nikto -h {target}  (this may take a while...)")
    return run_tool(["nikto", "-h", target, "-nointeractive"], timeout=300)
