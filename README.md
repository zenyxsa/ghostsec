# 👻 GhostSec

> **A lightweight Python cybersecurity automation toolkit for defensive security research, authorized auditing, and learning.**

<p align="center">
  <img src="assets/ghostsec-banner.png" alt="GhostSec cyberpunk anime banner" width="100%">
</p>

## ✦ Features

| Module | What it does |
|---|---|
| **Port Scanner** | Fast multi-threaded TCP port scanning with configurable ranges and JSON/text output. |
| **Subdomain Finder** | Dictionary-based subdomain discovery with DNS resolution. |
| **Password Strength Checker** | Evaluates password complexity using length, character classes, and common weakness indicators. |
| **System Information Gatherer** | Collects OS, CPU, memory, architecture, hostname, and local network information. |
| **Simple Log Analyzer** | Parses local .log / .txt files and highlights suspicious entries such as ERROR, FAILED, and UNAUTHORIZED. |
| **URL Risk Detector** | Scores URLs using explainable indicators including deceptive structure, suspicious terms, raw IPs, DNS results, and reputation checks. |
| **Breach Exposure OSINT** | Checks email/account identifiers against publicly reported breach metadata using XposedOrNot, with optional HIBP support. |
| **Phone Number OSINT** | Locally validates and normalizes phone numbers and reports numbering metadata such as region, type, carrier, location, and time zones. |

## ⚙️ Installation

```bash
git clone https://github.com/zenyxsa/ghostsec.git
cd ghostsec
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## 🚀 Usage

Interactive mode:

```bash
python ghostsec.py
```

CLI examples:

```bash
python ghostsec.py scan 127.0.0.1
python ghostsec.py subdomain example.com
python ghostsec.py passwd
python ghostsec.py sysinfo
python ghostsec.py log example.log
python ghostsec.py phone +91 9876543210
```

## 🔎 OSINT

GhostSec includes privacy-conscious OSINT features for URL, breach-metadata, and phone-number analysis.

- **URL Risk Detector** — explainable URL heuristics and reputation checks.
- **Breach Exposure OSINT** — XposedOrNot is used by default for publicly reported email breach metadata; HIBP can be configured optionally.
- **Phone Number OSINT** — performs local validation and numbering metadata analysis. It does **not** upload phone numbers to a breach database by default.

## 🛡️ Disclaimer

GhostSec is intended for ethical hacking, educational purposes, defensive security research, and authorized auditing only.

**Do not use GhostSec against systems, accounts, networks, or data without authorization.**

The author and contributors are not responsible for damage, disruption, privacy violations, or other misuse resulting from this software. Always respect applicable laws, policies, and the privacy of others.

---

## 📜 License

GhostSec is released under the **MIT License**.

You are free to use, modify, study, and distribute the project in accordance with the license.

---

<p align="center">
  <strong>GhostSec</strong> • Built by <a href="https://github.com/zenyxsa">zenyxsa</a>
</p>

<p align="center">
  <img src="assets/ghostsec-banner.png" alt="GhostSec cyberpunk anime banner" width="100%">
</p>
