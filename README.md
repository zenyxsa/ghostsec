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
| **GhostSec Local AI** | Optional Ollama-powered local chat and analysis of existing JSON, text, and log reports. |

## ⚙️ Installation

Clone the repository and create a virtual environment:

```sh
git clone https://github.com/zenyxsa/ghostsec.git
cd ghostsec
python -m venv .venv
```

Activate the virtual environment using the command for your shell.

**Bash / Zsh:**

```bash
source .venv/bin/activate
```

**Fish shell:**

```fish
source .venv/bin/activate.fish
```

Install the dependencies:

```sh
python -m pip install -r requirements.txt
```

### Troubleshooting

If Python reports `No module named pip` inside the virtual environment, try bootstrapping pip and then installing the requirements:

```sh
.venv/bin/python -m ensurepip --upgrade
.venv/bin/python -m pip install -r requirements.txt
```

On some Linux distributions, `ensurepip` may be unavailable because of how Python is packaged. If that command fails, check your distribution's Python/venv package instructions.

## 🚀 Usage

Interactive mode:

```sh
python ghostsec.py
```

CLI examples:

```sh
python ghostsec.py scan 127.0.0.1
python ghostsec.py subdomain example.com
python ghostsec.py passwd
python ghostsec.py sysinfo
python ghostsec.py log example.log
python ghostsec.py phone +91 9876543210
python ghostsec.py ai-chat
python ghostsec.py ai-analyze reports/scan.json
```

## 🧠 GhostSec Local AI

GhostSec includes an optional local-first AI analyst powered by [Ollama](https://ollama.com). The AI layer uses Ollama's local HTTP API and does not require a hosted AI API key.

Install and start Ollama, then download a model that fits your hardware. For example:

```sh
ollama pull qwen2.5:3b
ollama serve
```

Set the model (optional; defaults to `qwen2.5:3b`):

```sh
export GHOSTSEC_OLLAMA_MODEL=qwen2.5:3b
```

Start a local chat:

```sh
python ghostsec.py ai-chat
```

Analyze an existing report without executing it:

```sh
python ghostsec.py ai-analyze reports/scan.json
```

The endpoint defaults to `http://127.0.0.1:11434`. Override it with `GHOSTSEC_OLLAMA_HOST` if your local Ollama server uses another address. AI support is optional; the existing GhostSec tools continue to work without Ollama installed.

The AI analyst treats report contents as untrusted data, does not execute commands or launch scans, and is intended for defensive analysis of systems you own or are authorized to assess.


### Agent framework (developer preview)

The agent framework is being developed on the `feature/ghostsec-ai-agent-core` branch. It adds:

- A local Ollama-backed planner that returns a validated JSON plan.
- Specialist prompt profiles for reconnaissance, vulnerability intelligence, OSINT, and reporting.
- A structured Python tool registry. It does not accept arbitrary shell command strings.
- Explicit target scope and human-confirmation checks before registered tools execute.

At this stage, the planner creates plans only. No scanner tools are registered or automatically executed by the AI framework yet. Existing GhostSec scanners remain separate. The framework can be tested with:

```sh
python -m unittest discover -s tests -v
```

## 🔎 OSINT

GhostSec includes privacy-conscious OSINT features for URL, breach-metadata, and phone-number analysis.

- **URL Risk Detector** — explainable URL heuristics and reputation checks.
- **Breach Exposure OSINT** — XposedOrNot is used by default for publicly reported email breach metadata; HIBP can be configured optionally.
- **Phone Number OSINT** — performs local validation and numbering metadata analysis. It does **not** upload phone numbers to a breach database by default.

## 🛡️ Disclaimer

GhostSec is intended for ethical hacking, educational purposes, defensive security research, and authorized auditing only.

**Do not use GhostSec against systems, accounts, networks, or data without authorization.** The author and contributors are not responsible for damage, disruption, privacy violations, or other misuse resulting from this software. Always respect applicable laws, policies, and the privacy of others.

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
