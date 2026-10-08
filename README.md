# GhostSec - Python Cybersecurity Automation Tool

![Python Version](https://img.shields.io/badge/Python-3.x-blue.svg)
![OS](https://img.shields.io/badge/OS-Linux%20%7C%20Windows-green.svg)
![License](https://img.shields.io/badge/License-MIT-orange.svg)

GhostSec is a beginner-to-intermediate level cybersecurity CLI automation tool wrapped in a sleek, customizable Hacker-style shell. It was designed by **zenyxsa** as an all-in-one footprinting and reconnaissance toolkit. 

## Features
- **Port Scanner:** Fast, multi-threaded sequential port scanning with live loading feedback.
- **Subdomain Finder:** Dictionary-based brute-force payload to uncover hidden subdomains.
- **Password Strength Checker:** RegEx-powered algorithm to instantly evaluate your password's complexity.
- **System Information Gatherer:** Enumerates OS details, hardware structure, and local IP/hostname.
- **Simple Log Analyzer:** Reads local log files (`.log` or `.txt`) and flags suspicious entries like "ERROR", "FAILED", or "UNAUTHORIZED".

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/zenyxsa/ghostsec.git
cd ghostsec
```

### 2. Install Requirements
Colorama is used to generate the cool green, red, and blue hacker terminal aesthetic.
```bash
pip install colorama
```

## Usage

You can use the tool in two modes. 

### 🟢 Interactive Shell Mode
Run the tool without any arguments to drop into the customized "Kali-style" immersive menu:
```bash
python ghostsec.py
```
*Prompt Style:* `zenyxsa@kali:~# `

### 🔴 Direct CLI Mode (For Scripts & Automation)
You can directly pass arguments to trigger specific modules without viewing the menu.

**1. Port Scanner**
```bash
python ghostsec.py scan example.com -s 1 -e 1000 -o scan_results.json
```

**2. Subdomain Finder**
```bash
python ghostsec.py subdomain example.com
# To use a custom wordlist:
python ghostsec.py subdomain example.com -w my_wordlist.txt
```

**3. Password Checker**
```bash
python ghostsec.py passwd "Your$ecretP@ssword123!"
```

**4. System Information**
```bash
python ghostsec.py sysinfo -o my_system_data.txt
```

**5. Log Analyzer**
```bash
# Provide the absolute or relative path to the log you want to scan:
python ghostsec.py log /var/log/auth.log
```


### 6. URL Risk Detector

Analyze a URL using explainable indicators such as HTTP vs HTTPS, raw IP hosts, deceptive URL structure, suspicious lure terms, DNS resolution, and an optional URLhaus reputation lookup.

```bash
python ghostsec.py url https://example.com
python ghostsec.py url https://example.com -o url_report.json
python ghostsec.py url https://example.com --no-urlhaus
```

The result is an **indicator-based risk assessment**, not a guarantee that a URL is safe.

### 7. Breach Exposure OSINT

Check whether an email/account identifier appears in publicly reported breaches through the Have I Been Pwned API. GhostSec reports client-safe breach metadata such as breach name, date, affected record count, and exposed data categories.

Set your HIBP API key in the environment:

```bash
export HIBP_API_KEY="your_api_key"
python ghostsec.py breach user@example.com
python ghostsec.py breach user@example.com -o breach_report.json
```

GhostSec intentionally does **not** retrieve, display, or store leaked passwords, password hashes, session tokens, or credential dumps.

## Disclaimer
*This tool is intended for ethical hacking, educational purposes, and authorized auditing only. The developers assume no liability for misuse.*

---
**Made by [zenyxsa]**
