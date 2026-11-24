<div align="center">

# INFSCAN

**Ultimate Domain Scanner — Enterprise Edition (v6.1)**

An all-in-one, asynchronous reconnaissance framework for domains and web infrastructure.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Version-6.1-brightgreen.svg)](INFSCAN.py)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](#requirements)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Command-Line Options](#command-line-options)
  - [Examples](#examples)
- [Output & Reports](#output--reports)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Disclaimer](#disclaimer)
- [License](#license)
- [Author](#author)

---

## Overview

**INFSCAN** is a single-file Python toolkit that aggregates more than a dozen passive and active reconnaissance techniques into one command. It enumerates DNS records and subdomains, fingerprints web technologies and WAFs, inspects TLS configuration, scans common ports, discovers exposed files and directories, extracts secrets from JavaScript, evaluates takeover risk, and produces a weighted risk score with an optional HTML report.

The scanner is built on `asyncio` and `aiohttp`, with threaded workers where socket-based checks are required. Optional dependencies degrade gracefully: if a library is missing, the corresponding module is skipped with a warning rather than crashing the scan.

> **Note:** Runtime console messages are currently printed in Arabic. This documentation and the JSON/CSV report keys are in English.

---

## Features

| Category | Capabilities |
| --- | --- |
| **DNS** | Resolves A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, CAA, NAPTR and LOC records; extracts SPF and DMARC where present. |
| **Subdomains** | Passive enumeration across 11 sources — crt.sh, SecurityTrails, RapidDNS, BufferOver, HackerTarget, AlienVault OTX, CertSpotter, ThreatCrowd, Anubis, urlscan.io and DNSDumpster — plus active brute-force of ~100 common names. |
| **WAF Detection** | Signature-based identification of 13 WAF/CDN products (Cloudflare, AWS WAF, Akamai, Imperva, Sucuri, F5, ModSecurity, Wordfence, Fastly, Varnish, Barracuda, Fortinet, Radware). |
| **Technology Stack** | Detects 40+ technologies across web servers, CMSs, frameworks, front-end libraries, backends, clouds, analytics, containers and monitoring tools from headers, cookies and HTML. |
| **HTTP Analysis** | Tries HTTPS then HTTP, collects headers and body, audits seven key security headers (HSTS, CSP, X-Frame-Options, XCTO, XSS, Referrer-Policy, Permissions-Policy). |
| **TLS / SSL** | Certificate issuer and days-to-expiry, plus explicit TLS 1.0/1.1/1.2/1.3 support probing. |
| **Ports** | Concurrent TCP scan of 28 common ports with service-name resolution and risk-based colouring. |
| **Intelligence** | GeoIP lookup (ip-api.com), WHOIS metadata, optional Nmap integration (`-F -sV`), subdomain takeover detection against 10 cloud providers. |
| **Content Discovery** | Directory/file brute-force with a built-in wordlist (150+ entries) or a custom wordlist, baseline-length filtering, and redirect/forbidden/error classification. |
| **Secrets** | Downloads referenced JavaScript files and scans them with 23 regex patterns for API keys, tokens, credentials, connection strings and private keys. |
| **Risk Engine** | Heuristic scoring (0–100) with LOW / MEDIUM / HIGH classification based on findings. |
| **Reporting** | Colourised terminal output, JSON/CSV export, and a self-contained RTL HTML dashboard. Logging and on-disk caching are built in. |

---

## Requirements

- **Python 3.8+**

### Core dependencies (required)

```bash
pip install aiohttp beautifulsoup4
```

### Optional dependencies

Each is detected at import time; scans that need it are skipped if absent.

```bash
pip install dnspython pyOpenSSL python-whois tqdm
```

| Package | Enables |
| --- | --- |
| `dnspython` | DNS record enumeration and takeover CNAME lookups |
| `pyOpenSSL` | Certificate issuer / expiry details |
| `python-whois` | WHOIS records |
| `tqdm` | Progress bar during directory brute-forcing |
| `nmap` (system binary) | Optional Nmap integration — e.g. `sudo apt install nmap` |

---

## Installation

```bash
# Clone or copy the project
git clone <repository-url> INFSCAN
cd INFSCAN

# Install dependencies (ideally inside a virtual environment)
python3 -m venv .venv && source .venv/bin/activate
pip install aiohttp beautifulsoup4 dnspython pyOpenSSL python-whois tqdm

# Verify the tool runs
python3 INFSCAN.py --version
```

No build step is required — `INFSCAN.py` is fully self-contained. At runtime the tool creates the following directories: `.cache/`, `logs/`, `reports/` and `plugins/`.

---

## Usage

```
python3 INFSCAN.py <domain> [options]
```

### Command-Line Options

| Option | Description |
| --- | --- |
| `--all` | Enable every scan module. |
| `--quick` | Fast pass: skips directory brute-force, JS extraction and secrets. |
| `--dns` | Enumerate DNS records. |
| `--subdomains` | Enumerate subdomains from all sources. |
| `--takeover` | Check discovered subdomains for takeover risk (requires `--subdomains`). |
| `--http` | Fetch the site, collect headers/body and run HTTP-based checks. |
| `--waf` | Detect WAF / CDN (requires `--http`). |
| `--technologies` | Fingerprint the technology stack (requires `--http`). |
| `--ssl` | Certificate information. |
| `--ssl-protocols` | Probe TLS protocol versions (used with `--ssl`). |
| `--ports` | Scan common TCP ports. |
| `--geoip` | GeoIP lookup of the resolved IP. |
| `--whois` | WHOIS lookup. |
| `--nmap` | Run `nmap -F -sV` (requires the Nmap binary). |
| `--dirb` | Directory / file brute-force (requires `--http`). |
| `--js-extract` | Download JavaScript files referenced by the page. |
| `--secrets` | Scan extracted JavaScript for secrets. |
| `--wordlist FILE` | Custom wordlist for `--dirb`. |
| `--output, -o FILE` | Save results (`.json`, `.html` or `.csv`). |
| `--format {text,json,html,csv}` | Console output format (default: `text`). |
| `--report` | Generate an HTML report (equivalent to `-o report_<timestamp>.html`). |
| `--proxy URL` | HTTP proxy, e.g. `http://127.0.0.1:8080`. |
| `--threads N` | Concurrent workers (default: `50`). |
| `--timeout N` | Request timeout in seconds (default: `15`). |
| `--quiet` | Suppress banner and summary output. |
| `--no-color` | Disable ANSI colours. |
| `--version` | Print the tool version and exit. |

### Examples

```bash
# Full reconnaissance with an interactive dashboard-style report
python3 INFSCAN.py example.com --all --report

# Quick passive pass: DNS, subdomains, SSL and open ports
python3 INFSCAN.py example.com --dns --subdomains --ssl --ports

# Web application fingerprinting: HTTP + WAF + technologies + secret hunting
python3 INFSCAN.py example.com --http --waf --technologies --js-extract --secrets

# Directory discovery with a custom wordlist and structured JSON output
python3 INFSCAN.py example.com --http --dirb --wordlist wordlists/common.txt -o results.json

# Route traffic through a proxy, 20 threads, 30-second timeout, no colours
python3 INFSCAN.py example.com --all --proxy http://127.0.0.1:8080 \
    --threads 20 --timeout 30 --no-color -o results.csv
```

---

## Output & Reports

- **Terminal** — colourised, sectioned summary with a risk score (`Risk Score: N/100`, level `LOW | MEDIUM | HIGH`).
- **JSON** (`-o results.json`) — complete raw result object, including DNS records, subdomains, technologies, ports, headers, directories, JS files, secrets, WHOIS, GeoIP and risk analysis. Ideal for piping into other tools.
- **CSV** (`-o results.csv`) — single-row summary: domain, IP, subdomain/port/technology counts and risk score.
- **HTML** (`--report` or `-o report.html`) — self-contained, print-friendly RTL dashboard with stat cards, a risk meter and detailed tables. Also written to `reports/` when `-o` is not supplied.
- **Logs** — `logs/scan.log` (INFO+) and `logs/errors.log` (ERROR+).
- **Cache** — `.cache/scan_cache.pkl` stores results with a two-hour TTL to reduce repeated lookups.

---

## Architecture

`INFSCAN.py` is organised into independent scanner classes, all coordinated by the asynchronous `scan_domain()` function:

```
Config / Logger / Cache          shared infrastructure
DNSScanner                       DNS record resolution
SubdomainScanner                 11 passive sources + active common-name scan
WAFDetector / TechnologyDetector  response header, cookie and HTML fingerprinting
DirectoryScanner / JSExtractor / SecretsFinder   content and secret discovery
SubdomainTakeoverDetector         CNAME + provider fingerprint checks
AIRiskAnalyzer                    heuristic risk scoring
ReportGenerator                   HTML dashboard rendering
print_results() / main()          output formatting and CLI entry point
```

Passive HTTP sources are gathered concurrently with `asyncio.gather`, while socket-based DNS brute-force, port scanning and HTML downloads use bounded `ThreadPoolExecutor`/semaphore pools controlled by `--threads`.

---

## Configuration

Runtime defaults are defined in the `Config` class at the top of `INFSCAN.py` and can be overridden by CLI flags:

| Setting | Default | Override |
| --- | --- | --- |
| `TIMEOUT` | `15` seconds | `--timeout` |
| `THREADS` | `50` | `--threads` |
| `PROXY` | `None` | `--proxy` |
| `NO_COLOR` | `False` | `--no-color` |
| `USER_AGENT` | Mozilla/5.0 (Windows NT 10.0; Win64; x64) | edit source |
| `CACHE_DIR` / `LOGS_DIR` / `REPORTS_DIR` | `.cache` / `logs` / `reports` | edit source |

---

## Disclaimer

INFSCAN is intended for **authorized security testing, educational purposes and defensive assessment only**. Only scan systems and domains that you own or have explicit, written permission to test. Passive sources and third-party APIs have their own rate limits and terms of service. The authors assume no liability for misuse, damage or data obtained through this tool.

---

## License

Released under the [MIT License](LICENSE). See the LICENSE file for details.

---

## Author

**Security Professional** — INFSCAN v6.1, Enterprise Edition.

> Contributions, bug reports and feature requests are welcome via issues and pull requests.
