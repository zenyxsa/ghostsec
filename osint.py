#!/usr/bin/env python3
"""Defensive OSINT helpers for GhostSec.

This module deliberately reports breach metadata only. It never retrieves,
stores, or displays passwords, hashes, tokens, or leaked credential dumps.
"""

import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from ipaddress import ip_address


URL_RE = re.compile(r"^https?://", re.I)
BRAND_TERMS = {
    "microsoft", "outlook", "office365", "office", "paypal", "apple",
    "icloud", "google", "gmail", "facebook", "instagram", "amazon",
    "netflix", "steam", "discord", "docusign", "dropbox", "coinbase",
    "binance", "linkedin", "adobe",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "top", "xyz", "work", "buzz", "cam", "rest",
}

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "wallet", "password", "signin", "unlock", "bonus", "gift", "claim",
    "free", "invoice", "payment",
}


def _request(url, data=None, headers=None, timeout=10):
    req = urllib.request.Request(
        url,
        data=data,
        headers=headers or {"User-Agent": "GhostSec/1.2"},
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def normalize_url(value):
    value = value.strip()
    if not URL_RE.match(value):
        value = "https://" + value
    return value


def analyze_url(url, check_urlhaus=True):
    """Return explainable URL risk indicators.

    This is an indicator-based assessment, not a guarantee that a URL is safe.
    """
    url = normalize_url(url)
    parsed = urllib.parse.urlparse(url)
    findings = []
    score = 0

    if parsed.scheme not in ("http", "https"):
        findings.append("Unsupported URL scheme.")
        score += 50

    if parsed.scheme == "http":
        findings.append("Uses unencrypted HTTP instead of HTTPS.")
        score += 20

    host = parsed.hostname or ""
    if not host:
        findings.append("URL does not contain a valid hostname.")
        score += 50
    else:
        try:
            ip_address(host)
            findings.append("URL uses a raw IP address instead of a domain.")
            score += 15
        except ValueError:
            pass

        if "@" in parsed.netloc:
            findings.append("Contains an @ symbol, which can obscure the real destination.")
            score += 30

        lowered = parsed.path.lower() + "?" + parsed.query.lower()
        matched = sorted(word for word in SUSPICIOUS_WORDS if word in lowered)
        if matched:
            findings.append(
                "Contains commonly abused lure terms: " + ", ".join(matched) + "."
            )
            score += min(25, len(matched) * 5)

        if len(url) > 180:
            findings.append("Unusually long URL.")
            score += 10

        if host.count(".") >= 4:
            findings.append("Deeply nested hostname/subdomain structure.")
            score += 10

        labels = [label for label in host.split(".") if label]
        subdomain = ".".join(labels[:-2])
        brand_matches = sorted(
            brand for brand in BRAND_TERMS
            if brand in subdomain.lower() or (
                len(labels) >= 2 and brand in labels[-2].lower()
            )
        )
        if brand_matches:
            findings.append(
                "Hostname contains brand/service names commonly targeted for impersonation: "
                + ", ".join(brand_matches) + "."
            )
            score += min(35, 20 + max(0, len(brand_matches) - 1) * 5)

        if "xn--" in host.lower():
            findings.append("Hostname contains punycode, which can be used in look-alike domains.")
            score += 25

        if any(label.count("-") >= 2 for label in labels):
            findings.append("Hostname contains heavily hyphenated labels, a pattern sometimes used in look-alike domains.")
            score += 10

        tld = labels[-1].lower() if labels else ""
        if tld in SUSPICIOUS_TLDS:
            findings.append(f"Uses a TLD frequently seen in disposable or abuse-heavy registrations: .{tld}.")
            score += 10

        if subdomain:
            words = set(re.split(r"[-.]", subdomain.lower()))
            if words & BRAND_TERMS and words & SUSPICIOUS_WORDS:
                findings.append(
                    "Subdomain combines a recognizable brand with a credential/lure term."
                )
                score += 25

        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            findings.append("Hostname did not resolve through the local DNS resolver.")
            score += 25

    reputation = {
        "urlhaus": None,
        "phishtank": None,
    }

    if check_urlhaus:
        try:
            payload = urllib.parse.urlencode({"url": url}).encode()
            raw = _request(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data=payload,
                headers={"User-Agent": "GhostSec/1.1"},
            )
            reputation["urlhaus"] = json.loads(raw)
            if reputation["urlhaus"].get("query_status") == "ok":
                findings.append("URL is listed by URLhaus as a known malicious URL.")
                score += 70
        except Exception as exc:
            reputation["urlhaus"] = {"error": str(exc)}

    # PhishTank checks the URL string against its community-verified phishing
    # database. This does not visit the target URL.
    try:
        payload = urllib.parse.urlencode({
            "url": url,
            "format": "json",
        }).encode()
        raw = _request(
            "https://checkurl.phishtank.com/checkurl/",
            data=payload,
            headers={"User-Agent": "GhostSec/1.1"},
        )
        reputation["phishtank"] = json.loads(raw)
        pt = reputation["phishtank"].get("results", {})
        if pt.get("in_database"):
            verified = str(pt.get("verified", "")).lower() in {"y", "yes", "true"}
            valid = str(pt.get("valid", "")).lower() in {"y", "yes", "true"}
            online = str(pt.get("online", "")).lower() in {"y", "yes", "true"}
            if verified and valid:
                findings.append(
                    "URL is listed by PhishTank as a verified, valid phishing URL."
                )
                score += 85
            elif pt.get("in_database"):
                findings.append("URL is present in the PhishTank phishing database.")
                score += 55
            if online:
                findings.append("PhishTank currently reports the phishing URL as online.")
                score += 10
    except Exception as exc:
        reputation["phishtank"] = {"error": str(exc)}

    score = min(score, 100)
    if score >= 70:
        verdict = "HIGH RISK"
    elif score >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "NO KNOWN INDICATORS"

    return {
        "url": url,
        "verdict": verdict,
        "risk_score": score,
        "findings": findings or [
            "No known indicators were returned by the configured reputation checks."
        ],
        "reputation": reputation,
        # Kept for compatibility with existing consumers.
        "urlhaus": reputation["urlhaus"],
    }


def breach_lookup(account):
    """Check HIBP for breach metadata using HIBP_API_KEY.

    HIBP's response is intentionally reduced to client-safe metadata.
    No passwords, hashes, tokens, or raw compromised records are returned.
    """
    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        return {
            "status": "not_configured",
            "message": "Set HIBP_API_KEY to enable breach exposure checks.",
        }

    account = account.strip()
    if not account:
        raise ValueError("Account/email cannot be empty.")

    endpoint = (
        "https://haveibeenpwned.com/api/v3/breachedaccount/"
        + urllib.parse.quote(account, safe="")
        + "?truncateResponse=false"
    )
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "GhostSec/1.1",
    }

    try:
        raw = _request(endpoint, headers=headers)
        breaches = json.loads(raw)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"status": "not_found", "account": account, "breaches": []}
        if exc.code == 401:
            return {"status": "error", "message": "HIBP API key was rejected."}
        if exc.code == 429:
            return {"status": "error", "message": "HIBP rate limit reached."}
        return {"status": "error", "message": f"HIBP returned HTTP {exc.code}."}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}

    safe = []
    for breach in breaches:
        safe.append({
            "name": breach.get("Name"),
            "title": breach.get("Title"),
            "domain": breach.get("Domain"),
            "breach_date": breach.get("BreachDate"),
            "added_date": breach.get("AddedDate"),
            "modified_date": breach.get("ModifiedDate"),
            "pwn_count": breach.get("PwnCount"),
            "data_classes": breach.get("DataClasses", []),
            "is_verified": breach.get("IsVerified"),
            "is_sensitive": breach.get("IsSensitive"),
        })

    return {
        "status": "found",
        "account": account,
        "breach_count": len(safe),
        "breaches": safe,
    }


def print_url_report(result):
    print("\n=== GhostSec URL Risk Report ===")
    print(f"URL: {result['url']}")
    print(f"Verdict: {result['verdict']}")
    print(f"Risk score: {result['risk_score']}/100")
    print("\nWhy:")
    for finding in result["findings"]:
        print(f"  - {finding}")

    uh = result.get("urlhaus")
    if isinstance(uh, dict) and uh.get("query_status") == "ok":
        print("\nURLhaus:")
        print(f"  Threat: {uh.get('threat', 'unknown')}")
        print(f"  Status: {uh.get('url_status', 'unknown')}")


def print_breach_report(result):
    print("\n=== GhostSec Breach Exposure Report ===")
    if result.get("status") != "found":
        print(result.get("message", "No breach records found."))
        return

    print(f"Account: {result['account']}")
    print(f"Breaches found: {result['breach_count']}")
    for breach in result["breaches"]:
        print(f"\n  {breach['title'] or breach['name']}")
        print(f"  Date: {breach['breach_date']}")
        print(f"  Records: {breach['pwn_count']:,}" if breach.get("pwn_count") else "  Records: unknown")
        print("  Exposed data classes: " + ", ".join(breach["data_classes"]))
        print(f"  Verified: {breach['is_verified']}")
        print(f"  Sensitive: {breach['is_sensitive']}")
