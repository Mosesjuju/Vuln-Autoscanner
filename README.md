# VULN-AUTOSCANNER v1.0 (NO AI)

A comprehensive, lightweight scanner that orchestrates multiple security tools in parallel:
- **Core Tools**: `nmap`, `gobuster`, `nikto`, `nuclei`
- **SSL/TLS Analysis**: `sslscan` 
- **Subdomain Enumeration**: `subfinder`
- **Technology Fingerprinting**: `whatweb`

Parses outputs with regex/rule-based scoring and generates JSON + styled HTML reports.

## Features

✨ **Parallel Execution** - ThreadPoolExecutor runs all tools concurrently  
📊 **Modern Progress Bars** - Real-time status with rich library  
🔍 **50+ Vulnerability Patterns** - CVE detection (2020-2025), injection flaws, misconfigurations  
🎯 **Enhanced Nmap Parsing** - XML parsing for service versions and port details  
🔒 **SSL/TLS Analysis** - Detects Heartbleed, weak ciphers, certificate issues  
🌐 **Subdomain Discovery** - Expands attack surface automatically  
🛠️ **Tech Fingerprinting** - Identifies CMS, frameworks, server versions  
🥷 **Stealth Mode** - Rate limiting, custom user agents, request delays  
📑 **Rich Reports** - Collapsible HTML + JSON with risk scoring  

## Requirements

### System Tools
Install via your package manager:

```bash
# Debian/Ubuntu
sudo apt install nmap gobuster nikto sslscan

# Also install (from official sources):
# - nuclei: https://github.com/projectdiscovery/nuclei
# - subfinder: https://github.com/projectdiscovery/subfinder  
# - whatweb: https://github.com/urbanadventurer/WhatWeb
```

### Python Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Check Tool Installation
Before running scans, verify which tools are installed:

```bash
python scanner.py --check-tools
```

This shows a table of all tools with their installation status and commands to install missing ones.

### Basic Scan
```bash
python scanner.py testphp.vulnweb.com
```

### Advanced Options
```bash
# Fast mode with custom ports
python scanner.py example.com --fast --ports 80,443,8080

# Stealth mode with delays and custom UA
python scanner.py target.com --delay 2 --user-agent "Mozilla/5.0..."

# Skip specific tools
python scanner.py site.com --skip-ssl --skip-subdomains

# Custom wordlist for directory discovery
python scanner.py site.com --wordlist /path/to/wordlist.txt
```

### CLI Options
```
--ports PORTS          Comma-separated ports (default: 80,443)
--fast                 Fast mode (less aggressive)
--wordlist PATH        Custom wordlist for gobuster
--delay SECONDS        Delay between tool executions (stealth)
--user-agent UA        Custom user agent (random by default)
--throttle SECONDS     Request throttling delay
--skip-ssl             Skip SSL/TLS analysis
--skip-subdomains      Skip subdomain enumeration
--skip-fingerprint     Skip technology fingerprinting
--timeout SECONDS      Per-tool timeout (default: 300)
--verbose, -v          Show verbose output (commands, errors)
--check-tools          Check which tools are installed and exit
```

## Quick Start

1. **Check what tools you have:**
   ```bash
   python scanner.py --check-tools
   ```

2. **Install missing tools** (see output from step 1)

3. **Run your first scan:**
   ```bash
   python scanner.py testphp.vulnweb.com --fast
   ```

4. **Open the report:**
   ```bash
   firefox results/testphp.vulnweb.com_*/report.html
   ```

## Troubleshooting

### Quick Diagnostic

1. **Check tool installation:**
   ```bash
   python scanner.py --check-tools
   ```

2. **Run with verbose mode:**
   ```bash
   python scanner.py target.com --verbose
   ```

### Tools Returning 0 Results?

**Common Issues:**

1. **Subfinder**: Returns 0 subdomains if:
   - Domain has no public subdomains
   - Not in public DNS datasets (Censys, VirusTotal, etc.)
   - API keys not configured (`~/.config/subfinder/provider-config.yaml`)
   - Try with a well-known domain first: `python scanner.py google.com --verbose`

2. **WhatWeb**: Returns no output if:
   - Target is unreachable or blocking requests
   - Website requires authentication
   - Firewall/WAF is blocking the scanner
   - Try: `whatweb http://testphp.vulnweb.com` directly to verify

3. **Nikto**: Returns no output if:
   - Target is blocking scans (common with WAFs)
   - Website is down or slow to respond
   - Increase timeout: `--timeout 600`
   - Try with known vulnerable site: `http://testphp.vulnweb.com`

4. **SSLScan**: Fails if:
   - Target doesn't use HTTPS
   - Port 443 is closed or filtered
   - Skip if not needed: `--skip-ssl`

**Verify Tools Are Installed:**
```bash
which nmap gobuster nikto nuclei sslscan subfinder whatweb
```

**Test Individual Tools:**
```bash
subfinder -d testphp.vulnweb.com
whatweb http://testphp.vulnweb.com
nikto -h http://testphp.vulnweb.com
```

## Output Structure

```
results/<target>_<timestamp>/
├── nmap.txt / nmap.xml      # Port scan results
├── gobuster.txt             # Directory enumeration
├── nikto.txt                # Web server scan
├── nuclei.txt               # Template-based vuln scan
├── sslscan.txt              # SSL/TLS analysis
├── subfinder.txt            # Subdomain list
├── whatweb.txt              # Technology fingerprinting
├── summary.json             # Structured findings + metadata
└── report.html              # Styled, collapsible web report
```

## Detection Coverage

- **CVEs**: Log4Shell, Spring4Shell, Zerologon, Follina, Citrix Bleed, and more
- **Injections**: SQL, XSS, XXE, LDAP, Command injection, SSRF
- **Auth Issues**: Bypasses, default credentials, session vulnerabilities
- **Info Disclosure**: Sensitive files (.git, .env), error messages, backups
- **SSL/TLS**: Heartbleed, POODLE, weak ciphers, expired certificates
- **Misconfigurations**: CORS, missing security headers, directory listings

## Security & Legal

⚠️ **Only scan hosts you have explicit permission to test.**  
This tool is for authorized security assessments only. Unauthorized scanning may violate laws.

## Notes

- Non-intrusive parsing and heuristic risk scoring (no exploitation)
- Tools must be installed and available in PATH
- Missing tool errors are recorded in outputs
- For production scans, tune timeouts and wordlists
