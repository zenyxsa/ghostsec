# GhostSec

<p align="center">
  <strong>Python Cybersecurity Automation & OSINT Toolkit</strong><br>
  Scan • Analyze • Discover • Investigate
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-2ea44f?style=for-the-badge" alt="Linux and Windows">
  <img src="https://img.shields.io/badge/License-MIT-orange?style=for-the-badge" alt="MIT License">
</p>

GhostSec is a lightweight, modular Python CLI built for **cybersecurity learning, reconnaissance, defensive OSINT, and authorized security testing**. It combines practical network, system, URL, breach-metadata, and phone-number utilities behind a simple interactive shell as well as script-friendly commands.

> **Small tool. Big possibilities.**  
> — zenyxsa

---

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

---

## ⚡ Quick Start

### Clone

~~~bash
git clone https://github.com/zenyxsa/ghostsec.git
cd ghostsec
~~~

### Create a virtual environment

Linux / macOS:

~~~bash
python -m venv .venv
source .venv/bin/activate
~~~

Fish shell:

~~~fish
python -m venv .venv
source .venv/bin/activate.fish
~~~

Windows:

~~~powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
~~~

### Install dependencies

~~~bash
python -m pip install -r requirements.txt
~~~

### Launch GhostSec

~~~bash
python ghostsec.py
~~~

---

## 🖥️ Interactive Mode

Running GhostSec without arguments opens the interactive menu:

~~~text
╔══════════════════════════════════════════╗
║              G H O S T S E C             ║
║       Python Cybersecurity Toolkit        ║
╚══════════════════════════════════════════╝

1) Port Scanner
2) Subdomain Finder
3) Password Strength Checker
4) System Information Gatherer
5) Simple Log Analyzer
6) URL Risk Detector
7) Breach Exposure OSINT
8) Phone Number OSINT
0) Exit
~~~

This mode is useful when exploring the toolkit manually, while direct CLI mode is better for repeatable workflows and automation.

---

## 🧰 Direct CLI Usage

### 1. Port Scanner

~~~bash
python ghostsec.py scan example.com -s 1 -e 1000
python ghostsec.py scan 192.168.1.1 -s 1 -e 65535 -o scan_results.json
~~~

### 2. Subdomain Finder

~~~bash
python ghostsec.py subdomain example.com
python ghostsec.py subdomain example.com -w my_wordlist.txt
~~~

### 3. Password Strength Checker

~~~bash
python ghostsec.py passwd "Your$ecretP@ssword123!"
~~~

### 4. System Information

~~~bash
python ghostsec.py sysinfo
python ghostsec.py sysinfo -o system_info.json
~~~

### 5. Log Analyzer

~~~bash
python ghostsec.py log /var/log/auth.log
python ghostsec.py log ./application.log -o log_report.txt
~~~

### 6. URL Risk Detector

GhostSec performs an explainable, indicator-based URL assessment rather than claiming that a URL is absolutely safe or malicious.

~~~bash
python ghostsec.py url https://example.com
python ghostsec.py url https://example.com -o url_report.json
python ghostsec.py url https://example.com --no-urlhaus
~~~

Indicators can include:

- HTTP instead of HTTPS
- Raw IP addresses
- Suspicious URL lure terms
- Deceptive hostname structure
- Punycode
- Heavy hostname hyphenation
- Suspicious top-level domains
- DNS resolution failures
- Brand impersonation patterns
- URLhaus reputation data
- PhishTank reputation data when available

### 7. Breach Exposure OSINT

GhostSec can check whether an **email/account identifier** appears in publicly reported breach metadata.

Free mode uses the keyless XposedOrNot community API:

~~~bash
python ghostsec.py breach user@example.com
python ghostsec.py breach user@example.com -o breach_report.json
~~~

Optional Have I Been Pwned integration:

~~~bash
export HIBP_API_KEY="your_api_key"
python ghostsec.py breach user@example.com
~~~

If HIBP is unavailable or rejects the configured key, GhostSec can fall back to XposedOrNot.

The breach module intentionally reports **metadata only**. It does not retrieve or display leaked passwords, password hashes, session tokens, authentication cookies, or credential dumps.

### 8. Phone Number OSINT

Phone OSINT uses the local python-phonenumbers metadata bundled with the package. The number is normalized and validated locally, then GhostSec can report:

- E.164 formatted number
- Validity / possible-number status
- Country or numbering region
- Number type
- Carrier / network metadata when available
- Approximate numbering location
- Associated time zones

Example:

~~~bash
python ghostsec.py phone +91 8077981361
python ghostsec.py phone +91 8077981361 -o phone_report.json
~~~

For numbers without a country code, GhostSec defaults to India (IN) unless another region is supplied:

~~~bash
python ghostsec.py phone 8077981361 --region IN
~~~

### Important phone-OSINT limitation

Phone Number OSINT is **not a live location tracker and does not identify the person who owns a number**. Carrier and location values are numbering-plan metadata and can be incomplete or outdated, especially after number portability.

GhostSec also does **not** query an unverified free phone-breach database. Phone breach lookup remains unavailable unless a legitimate provider is explicitly configured in a future release.

---

## 🔐 Privacy & Safety

GhostSec is designed to keep local checks local whenever possible.

- Phone-number validation and metadata use local python-phonenumbers datasets.
- Password checking is performed locally.
- System information is collected from the machine running GhostSec.
- Log analysis reads the files you explicitly provide.
- URL reputation checks may contact third-party services when enabled.
- Breach exposure checks send the queried account identifier to the configured breach-data provider.
- GhostSec does not intentionally retrieve leaked credentials or credential dumps.

Always understand what data a third-party OSINT service receives before using it with real information.

---

## 📦 Requirements

- **Python 3.10+**
- pip
- Internet access for network/reputation/OSINT modules that use remote services
- Dependencies listed in requirements.txt

Install everything with:

~~~bash
python -m pip install -r requirements.txt
~~~

---

## 🗂️ Project Structure

~~~text
ghostsec/
├── ghostsec.py          # Main CLI and interactive shell
├── osint.py             # URL, breach, and phone OSINT functionality
├── requirements.txt     # Python dependencies
├── README.md            # Documentation
└── .gitignore
~~~

---

## 🧪 Output & Automation

Most modules can be used interactively or from the command line, making GhostSec suitable for small automation workflows.

Where supported, use -o / --output to save results:

~~~bash
python ghostsec.py scan example.com -o scan.json
python ghostsec.py url https://example.com -o url_report.json
python ghostsec.py breach user@example.com -o breach_report.json
python ghostsec.py phone +91 8077981361 -o phone_report.json
~~~

---

## ⚠️ Disclaimer

GhostSec is intended for:

- Education and cybersecurity learning
- Defensive security research
- Authorized penetration testing
- Systems and networks you own or have explicit permission to assess

**Do not use GhostSec against systems, accounts, networks, or data without authorization.**

The author and contributors are not responsible for damage, disruption, privacy violations, or other misuse resulting from this software. Always respect applicable laws, policies, and the privacy of others.

---

## 📜 License

GhostSec is released under the **MIT License**.

You are free to use, modify, study, and distribute the project in accordance with the license.

---

<p align="center">
  <img src="assets/ghostsec-banner.jpg" alt="GhostSec cyberpunk anime banner" width="100%">
</p>

<p align="center">
  <strong>GhostSec</strong> • Built by <a href="https://github.com/zenyxsa">zenyxsa</a>
</p>
**Made by [zenyxsa]**

<p align="center">

<p align="center">
  <img src="assets/ghostsec-banner.png" alt="GhostSec cyberpunk anime banner" width="100%">
</p>
