# GhostSec

> A Python cybersecurity toolkit for defensive security research, authorized assessments, OSINT, and learning.

<p align="center">
  <img src="assets/ghostsec-banner.png" alt="GhostSec cyberpunk banner" width="100%">
</p>

GhostSec combines traditional command-line security utilities with an optional local Ollama-powered AI assessment workflow. It includes bounded network and web assessment tools, OSINT helpers, SQLite-backed assessment history, and HTML report export.

Use it only on systems, networks, domains, accounts, and data that you own or are explicitly authorized to assess.

## Features

| Area | Capability |
|---|---|
| Network utilities | TCP port scanning and dictionary-based subdomain discovery with DNS resolution. |
| Host information | System information gathering and local log analysis. |
| URL analysis | Explainable URL risk indicators and optional reputation checks. |
| OSINT | Public breach-metadata lookup and local phone-number validation/numbering metadata. |
| Local AI | Ollama-backed chat and analysis of local JSON, text, and log reports. |
| AI assessment agent | Validated model plans, a structured tool registry, explicit target authorization, and human approval before each execution round. |
| Assessment history | SQLite storage for sessions, tool results, findings, remediations, and final reports. |
| Report export | HTML export without extra dependencies; optional PDF export using ReportLab. |

## Requirements

- Python 3.10 or newer.
- The Python packages in `requirements.txt`.
- Ollama and a locally available model for `ai-chat`, `ai-analyze`, and `ai-assess`.
- Some agent tools call external system utilities. Install the tools you intend to use and ensure they are available on `PATH`:
  - `nmap` for Nmap scans.
  - `whois` for registration lookups.
  - `whatweb` for web technology fingerprinting.
  - `dig` for DNS lookups.
  - `nikto` for active web-server checks.

The standard-library TCP scanner, SQLite database, and HTML exporter do not need those external programs. An agent tool whose executable is missing cannot complete its check.

The built-in TCP scanner limits each invocation to 1,024 ports and uses a bounded worker pool. Split larger ranges into separate, deliberately reviewed scans.

## Installation

Clone the repository and create a virtual environment:

```sh
git clone https://github.com/zenyxsa/ghostsec.git
cd ghostsec
python3 -m venv .venv
```

Activate it using the command for your shell.

**Bash / Zsh:**

```bash
source .venv/bin/activate
```

**Fish:**

```fish
source .venv/bin/activate.fish
```

Install the required Python dependencies:

```sh
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Optional PDF support

HTML reports work with the standard library. PDF export requires ReportLab:

```sh
python -m pip install -r requirements-optional.txt
```

Alternatively, install just ReportLab:

```sh
python -m pip install reportlab
```

### Troubleshooting virtual environments

If the virtual environment has no `pip`, try:

```sh
.venv/bin/python -m ensurepip --upgrade
.venv/bin/python -m pip install -r requirements.txt
```

Some Linux distributions package `venv`/`ensurepip` separately. Follow your distribution's Python packaging instructions if `ensurepip` is unavailable.

## Quick start

Show available commands:

```sh
python ghostsec.py --help
```

Start the interactive menu:

```sh
python ghostsec.py
```

Examples of the traditional utilities:

```sh
python ghostsec.py scan 127.0.0.1
python ghostsec.py scan 127.0.0.1 --start 1 --end 1024
python ghostsec.py subdomain example.com
python ghostsec.py passwd 'ReplaceWithATestPassword'
python ghostsec.py sysinfo
python ghostsec.py log example.log
python ghostsec.py url https://example.com
python ghostsec.py breach person@example.com
python ghostsec.py phone "+919876543210" --region IN
```

Use a test account or a value you are authorized to check when trying OSINT commands. A breach-metadata lookup sends the queried account identifier to the configured external lookup service. Phone-number validation and numbering metadata are performed locally by default.

## Local AI with Ollama

GhostSec uses Ollama's local HTTP API for its model-backed features. The default model is `qwen2.5:3b` and the default endpoint is `http://127.0.0.1:11434`.

Install Ollama using its official instructions, make sure its local service is running, and download a model:

```sh
ollama pull qwen2.5:3b
```

Start a chat:

```sh
python ghostsec.py ai-chat
```

Analyze an existing local report without running scanners:

```sh
python ghostsec.py ai-analyze reports/scan.json
```

Optional configuration:

**Bash / Zsh:**

```bash
export GHOSTSEC_OLLAMA_MODEL=qwen2.5:3b
export GHOSTSEC_OLLAMA_HOST=http://127.0.0.1:11434
```

**Fish:**

```fish
set -gx GHOSTSEC_OLLAMA_MODEL qwen2.5:3b
set -gx GHOSTSEC_OLLAMA_HOST http://127.0.0.1:11434
```

AI functionality is optional for the traditional utilities. Model choice affects memory use and response speed; choose a model appropriate for your hardware.

## AI agent assessment workflow

`ai-assess` runs a bounded, multi-round assessment through GhostSec's registered tools. The model proposes structured actions; GhostSec validates the plan and arguments against the registry. It does not accept arbitrary shell command strings as tool calls.

The current registry includes:

| Tool | Purpose |
|---|---|
| `port_scan` | Bounded TCP port scan using GhostSec's scanner. |
| `subdomain_discovery` | Resolve a small built-in list of common subdomains. |
| `nmap_scan` | Nmap service and port assessment. |
| `whois_lookup` | Domain/IP registration information. |
| `whatweb_scan` | Web technology fingerprinting. |
| `headers_lookup` | HTTP HEAD requests without following redirects. |
| `dns_lookup` | DNS A, MX, NS, and TXT lookups. |
| `nikto_scan` | Active web-server assessment using Nikto. |
| `search_intel` | Public security-intelligence, CVE, and remediation searches. |

Example against a local system:

```sh
python ghostsec.py ai-assess "Review the services on my local machine" --authorize 127.0.0.1
```

For more than one authorized target, repeat `--authorize`:

```sh
python ghostsec.py ai-assess "Review these approved lab hosts" \
  --authorize 192.0.2.10 \
  --authorize 192.0.2.11
```

The addresses in that second example are documentation-only TEST-NET addresses; replace them with targets you are authorized to assess.

### Approval and scope controls

- Every target-scoped tool action must stay within the explicitly supplied `--authorize` scope.
- Hostnames are compared case-insensitively and canonical IP notation is used; malformed numeric-looking addresses are rejected.
- The agent displays the proposed actions and arguments for a round.
- The user must type `YES` to approve that round. Any other response cancels the proposed round without executing its actions.
- The loop is bounded to a maximum of nine rounds.
- Tool output is treated as untrusted evidence, not as instructions to the model.
- The final report is instructed to distinguish confirmed evidence from possibilities and unknowns, and not to invent scan results or vulnerabilities.
- The public `search_intel` tool is passive and is not individually confirmation-gated in the registry. It is still included in the proposed action list, and the current agent loop asks for `YES` before executing any round that contains actions. Search requests and page fetches use the network.

Nmap, Nikto, and other network checks can generate traffic and affect remote services. Authorization and approval do not remove the need to assess operational impact before running a check.

## Assessment history and reports

AI assessments are stored in SQLite. By default, the database is:

```text
~/.local/share/ghostsec/ghostsec.db
```

Override the location with `GHOSTSEC_DB_PATH`.

**Bash / Zsh:**

```bash
export GHOSTSEC_DB_PATH="$HOME/ghostsec-data/ghostsec.db"
```

**Fish:**

```fish
set -gx GHOSTSEC_DB_PATH "$HOME/ghostsec-data/ghostsec.db"
```

Commands:

```sh
# List the 20 most recent assessments
python ghostsec.py history

# List a different number (1–500)
python ghostsec.py history --limit 50

# Display a saved report and recorded tool results
python ghostsec.py report 1
```

The session record can contain the objective, authorized targets, status, timestamps, risk level, summary, final report, tool results, structured findings, and remediations. A field may be empty when that information was not recorded for a session.

## Exporting reports

HTML export uses Python's standard library and escapes report content before inserting it into the document:

```sh
# Export HTML to ./reports by default
python ghostsec.py export 1

# Explicit format and output directory
python ghostsec.py export 1 --format html --output-dir reports
```

PDF export requires the optional ReportLab dependency:

```sh
python ghostsec.py export 1 --format pdf
```

Export both formats when ReportLab is installed:

```sh
python ghostsec.py export 1 --format both
```

Exported filenames include the session ID and a sanitized target label. Treat exported reports as sensitive: they may contain target names, scan results, evidence, and remediation details.

## Architecture overview

```text
ghostsec.py                    CLI and legacy utility entry point
osint.py                       URL, breach-metadata, and phone OSINT
ai_core/
  client.py                    Ollama HTTP client
  orchestrator.py              Structured planning and approved execution
  tools.py                     Tool registry, validation, and execution context
  integrations.py              Original GhostSec scanner integrations
  analyst.py                   Local report analysis
agents/                        Specialist agent prompt profiles
ghostsec_engine/
  registry.py                  Combined GhostSec and adapted tool registry
  tools.py                     External utility wrappers
  agent_loop.py                Bounded human-approved assessment rounds
  storage.py                   SQLite persistence
  export.py                    HTML and optional PDF reporting
  search.py                    Optional public search/page-fetch integration
tests/                         Unit and integration tests
THIRD_PARTY_LICENSES/           Upstream license and attribution notices
```

The agent framework combines the original GhostSec integrations with adapted tools from the MIT-licensed METATRON project. The adapted functionality is routed through GhostSec's registry and validation/approval workflow; the original arbitrary-command dispatch path is not used by the agent. See `THIRD_PARTY_LICENSES/UPSTREAM-MIT.txt` for the upstream attribution and license notice.

## Network use and privacy

- Ollama model requests go to the configured Ollama endpoint. With the default endpoint, that is the local machine.
- `search_intel` sends search queries to DuckDuckGo through the `ddgs` package and may fetch public pages for text extraction.
- URL reputation and breach-metadata features may contact their configured external services.
- Phone-number validation does not upload the phone number to a breach database by default.
- Assessment history and exported reports are stored locally unless you choose to move or share them.

Review each feature's data flow before using it with sensitive identifiers or targets.

## Tests

Run the test suite from the repository root:

```sh
python3 -m unittest discover -s tests -v
```

The tests cover tool validation and authorization, agent-loop behavior, SQLite session persistence, GhostSec tool integrations, and HTML export behavior. Tests use mocks and temporary databases where appropriate; a passing test suite is not a guarantee that every external utility or remote service is installed or reachable.

## Limitations

- AI output can be incorrect. Verify findings manually and consult authoritative vendor advisories before making changes.
- Scanner coverage depends on target reachability, permissions, network conditions, installed executables, and tool versions.
- Search results and public OSINT sources may be incomplete, stale, or inaccurate.
- Structured findings and fixes are persisted when explicitly recorded; the AI's final narrative report is not automatically converted into verified structured vulnerability records.
- PDF output is optional and requires ReportLab.

## Disclaimer

GhostSec is intended for ethical hacking, education, defensive security research, and authorized auditing only. Do not use it against systems, networks, accounts, or data without permission. You are responsible for obtaining authorization, complying with applicable laws and policies, and evaluating the impact of any assessment. The project is provided without warranty; the author and contributors are not responsible for misuse or damage arising from its use.

## License and attribution

GhostSec is released under the MIT License. See the repository's `LICENSE` file for the project license. Adapted third-party code retains its upstream attribution and license terms; see `THIRD_PARTY_LICENSES/UPSTREAM-MIT.txt`.

<p align="center">
  <strong>GhostSec</strong> · Built by <a href="https://github.com/zenyxsa">zenyxsa</a>
</p>
