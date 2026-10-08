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

LEGITIMATE_BRAND_DOMAINS = {
    "microsoft": {"microsoft.com", "microsoftonline.com"},
    "outlook": {"outlook.com", "microsoft.com", "microsoftonline.com"},
    "office365": {"office.com", "microsoft.com", "microsoftonline.com"},
    "office": {"office.com", "microsoft.com", "microsoftonline.com"},
    "paypal": {"paypal.com"},
    "apple": {"apple.com"},
    "icloud": {"icloud.com", "apple.com"},
    "google": {"google.com"},
    "gmail": {"gmail.com", "google.com"},
    "facebook": {"facebook.com", "meta.com"},
    "instagram": {"instagram.com", "meta.com"},
    "amazon": {"amazon.com", "amazon.in"},
    "netflix": {"netflix.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "discord": {"discord.com"},
    "docusign": {"docusign.com"},
    "dropbox": {"dropbox.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "linkedin": {"linkedin.com"},
    "adobe": {"adobe.com"},
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
        registrable_domain = ".".join(labels[-2:]).lower() if len(labels) >= 2 else host.lower()
        brand_matches = sorted(
            brand for brand in BRAND_TERMS
            if brand in subdomain.lower() or (
                len(labels) >= 2 and brand in labels[-2].lower()
            )
        )
        legitimate_brands = sorted(
            brand for brand in brand_matches
            if registrable_domain in LEGITIMATE_BRAND_DOMAINS.get(brand, set())
        )
        impersonated_brands = sorted(
            brand for brand in brand_matches if brand not in legitimate_brands
        )
        if brand_matches:
            findings.append(
                "Hostname contains brand/service names commonly targeted for impersonation: "
                + ", ".join(brand_matches) + "."
            )
        if impersonated_brands:
            findings.append(
                "Brand name appears on a domain not recognized as an official domain: "
                + ", ".join(impersonated_brands) + "."
            )
            score += min(45, 30 + max(0, len(impersonated_brands) - 1) * 5)

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
            subdomain_lower = subdomain.lower()
            lure_matches = sorted(
                word for word in SUSPICIOUS_WORDS if word in subdomain_lower
            )
            if impersonated_brands and lure_matches:
                findings.append(
                    "Hostname combines a recognizable brand with credential/lure terms: "
                    + ", ".join(lure_matches) + "."
                )
                score += 30

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


def _xposedornot_lookup(account):
    """Check XposedOrNot's free community API for breach metadata."""
    endpoint = (
        "https://api.xposedornot.com/v1/check-email/"
        + urllib.parse.quote(account, safe="")
        + "?details=true"
    )
    try:
        raw = _request(endpoint, headers={"User-Agent": "GhostSec/1.2"})
        data = json.loads(raw)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"status": "not_found", "account": account, "breaches": [], "source": "XposedOrNot"}
        if exc.code == 429:
            return {"status": "error", "message": "XposedOrNot rate limit reached. Try again later.", "source": "XposedOrNot"}
        return {"status": "error", "message": f"XposedOrNot returned HTTP {exc.code}.", "source": "XposedOrNot"}
    except Exception as exc:
        return {"status": "error", "message": str(exc), "source": "XposedOrNot"}

    raw_breaches = data.get("breaches", [])
    if raw_breaches and isinstance(raw_breaches[0], list):
        raw_breaches = raw_breaches[0]

    breaches = []
    for item in raw_breaches or []:
        if isinstance(item, str):
            breaches.append({
                "name": item,
                "title": item,
                "domain": None,
                "breach_date": None,
                "pwn_count": None,
                "data_classes": [],
                "is_verified": None,
                "is_sensitive": None,
            })
        elif isinstance(item, dict):
            breaches.append({
                "name": item.get("breachID") or item.get("name"),
                "title": item.get("title") or item.get("breachID") or item.get("name"),
                "domain": item.get("domain"),
                "breach_date": item.get("breachedDate"),
                "pwn_count": item.get("exposedRecords"),
                "data_classes": item.get("exposedData", []),
                "is_verified": item.get("verified"),
                "is_sensitive": item.get("sensitive"),
            })

    return {
        "status": "found" if breaches else "not_found",
        "account": account,
        "breach_count": len(breaches),
        "breaches": breaches,
        "source": "XposedOrNot",
    }


def breach_lookup(account):
    """Check an account for public breach exposure.

    HIBP is used when HIBP_API_KEY is configured. Otherwise GhostSec falls
    back to XposedOrNot's free, keyless community API.
    """
    account = account.strip()
    if not account:
        raise ValueError("Account/email cannot be empty.")

    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        return _xposedornot_lookup(account)

    endpoint = (
        "https://haveibeenpwned.com/api/v3/breachedaccount/"
        + urllib.parse.quote(account, safe="")
        + "?truncateResponse=false"
    )
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "GhostSec/1.2",
    }

    try:
        raw = _request(endpoint, headers=headers)
        breaches = json.loads(raw)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"status": "not_found", "account": account, "breaches": [], "source": "HIBP"}
        if exc.code in {401, 429}:
            fallback = _xposedornot_lookup(account)
            if fallback.get("status") in {"found", "not_found"}:
                fallback["hibp_fallback"] = "HIBP was unavailable, so XposedOrNot was used."
                return fallback
            message = "HIBP API key was rejected." if exc.code == 401 else "HIBP rate limit reached."
            return {"status": "error", "message": message, "source": "HIBP"}
        return {"status": "error", "message": f"HIBP returned HTTP {exc.code}.", "source": "HIBP"}
    except Exception as exc:
        return {"status": "error", "message": str(exc), "source": "HIBP"}

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
        "source": "HIBP",
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
    if result.get("source"):
        print(f"Source: {result['source']}")
    if result.get("hibp_fallback"):
        print(f"Note: {result['hibp_fallback']}")
    print(f"Breaches found: {result['breach_count']}")
    for breach in result["breaches"]:
        print(f"\n  {breach['title'] or breach['name']}")
        print(f"  Date: {breach['breach_date']}")
        print(f"  Records: {breach['pwn_count']:,}" if breach.get("pwn_count") else "  Records: unknown")
        print("  Exposed data classes: " + ", ".join(breach["data_classes"]))
        print(f"  Verified: {breach['is_verified']}")
        print(f"  Sensitive: {breach['is_sensitive']}")
