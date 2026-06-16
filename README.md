# 🛡️ VulnScan PRO — Full Async Web Vulnerability Scanner

![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![Async/Await](https://img.shields.io/badge/Async-100%25-brightgreen)
![License](https://img.shields.io/badge/License-GPL--3.0-red)
![Status](https://img.shields.io/badge/Status-Production--Ready-success)

**VulnScan PRO** is a high-performance, fully asynchronous web vulnerability scanner built with modern Python. It features comprehensive detection for 16+ vulnerability types, intelligent WAF detection with bypass strategies, and production-grade reliability through SQLite-based checkpointing and resume capability.

> **⚠️ AUTHORIZED SECURITY TESTING ONLY** — See [DISCLAIMER.md](DISCLAIMER.md) before use.

---

## 🚀 Key Features

### Core Capabilities
- **16+ Vulnerability Detectors**: SQLi, XSS, SSRF, XXE, IDOR, JWT, GraphQL, CORS, Port Scanning, Subdomain Enumeration, and more
- **100% Async**: Built on `asyncio`, `aiohttp`, and `asyncio.Lock` — no thread blocking
- **Smart WAF Detection**: Identifies Cloudflare, AWS WAF, Akamai, ModSecurity, F5, etc.
- **Automatic Bypass Strategies**: Case mutation, comment injection, hex encoding, unicode escaping
- **Advanced IDOR Detection**: Field-level sensitive data verification (not just similarity)
- **Time-Based SQLi**: Statistical baseline timing to reduce false positives
- **XXE Vector Coverage**: XML + multipart/form-data + SVG upload attacks
- **JWT Analysis**: Detects `alg:none`, weak HMAC secrets, algorithm confusion (with disclaimer)
- **GraphQL Scanner**: Introspection detection + field fuzzing
- **SPA Crawling**: True async Playwright integration for JavaScript-heavy apps

### Production Features
- **Checkpoint & Resume**: SQLite-backed persistence — stop/resume scans anytime
- **Rate Limiting**: Adaptive RPS with jitter to avoid fingerprinting
- **User-Agent Rotation**: 7+ realistic browser strings per request
- **HTML Report**: Beautiful, interactive findings dashboard
- **JSON Export**: Machine-readable results for CI/CD integration
- **Concurrent Scanning**: Configurable workers (default 20, tested up to 100+)
- **Debug Mode**: Verbose logging + full stack traces for troubleshooting

### Security-Hardened
- **XSS Protection**: `html.escape()` on ALL HTML output
- **SSL/TLS Options**: Custom CA bundle support (`--cacert`), verification toggle
- **Bearer Token Auth**: OAuth2/API token support (`--token`)
- **Aggressive Mode Gating**: Dangerous probes (metadata, file://) behind opt-in flag
- **Private IP Safeguard**: Explicit user confirmation before targeting RFC-1918 ranges

---

## 📋 Vulnerability Checklist

| Vulnerability | Detection | Bypass | Notes |
|---|---|---|---|
| **SQL Injection** | ✅ Error-based, Boolean-based, Time-based | ✅ 6 strategies | Statistical timing baseline |
| **Reflected XSS** | ✅ Payload reflection + DOM context | ✅ 5 strategies | SSTI as separate finding |
| **SSRF** | ✅ Safe probes + Aggressive (metadata) | ❌ N/A | AWS/GCP/Azure metadata, file://, gopher:// |
| **XXE** | ✅ Blind + Out-of-band (file read) | ❌ N/A | XML + form-data + SVG vectors |
| **IDOR** | ✅ Ownership validation + field verification | ❌ N/A | Detects leaked email, credit card, etc. |
| **JWT Weak Secret** | ✅ 28-entry secret wordlist | ❌ N/A | Disclaimer: claims only, no sig verify |
| **Broken CORS** | ✅ Wildcard + Origin reflection | ❌ N/A | Credentials bypass detection |
| **Weak Auth** | ✅ Missing CAPTCHA, CSRF token, rate limit | ❌ N/A | Detects hardened targets |
| **Information Disclosure** | ✅ Error pages, headers, API keys | ✅ WAF bypass | Regex-based signal detection |
| **Open Ports** | ✅ Redis, MongoDB, MySQL, Elastic, etc. | ❌ N/A | Async `open_connection` — no threads |
| **Subdomain Enumeration** | ✅ 23 common subdomains | ✅ DNS rate limited | aiodns (async) or socket fallback |
| **Sensitive Files** | ✅ .env, .git, wp-config, actuator, etc. | ✅ Crawler-based | 50+ default paths + crawler discoveries |
| **GraphQL Introspection** | ✅ Endpoint + schema enum | ✅ Basic fuzzing | Detects mutations, directives |
| **Dependency Confusion** | ✅ Package manifest exposure | ❌ N/A | Identifies internal package patterns |
| **Port Scanning** | ✅ 15 critical ports | ✅ Timeout tuning | `asyncio.open_connection` (no threads) |
| **Attack Chain Analysis** | ✅ 4 predefined chains | ❌ N/A | SSRF→Metadata, SQLi→Auth, XSS→CSRF |

---

## 🛠️ Installation

### Requirements
- **Python 3.8+** (3.10+ recommended for best async performance)
- **Linux/macOS/Windows** with network access
- **pip** or **poetry**

### Quick Start

```bash
# Clone repository
git clone https://github.com/Lil-PyLogic/vulnscan-pro.git
cd vulnscan-pro

# Install dependencies
pip install -r requirements.txt

# Optional: Full features (SPA crawlinggo=pytho
