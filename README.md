# VULN-AUTOSCANNER

Automated security scanner that runs multiple tools in parallel with intelligent parsing and reporting.

## Features

- **7 Security Tools**: nmap, gobuster, nikto, nuclei, sslscan, subfinder, whatweb
- **Parallel Execution**: ThreadPoolExecutor for concurrent scanning
- **Smart Detection**: 50+ vulnerability patterns including CVEs (2020-2025)
- **Modern UI**: Real-time progress bars and colored output
- **Multiple Reports**: JSON + styled HTML with risk scoring
- **Stealth Mode**: Rate limiting, custom user agents, request delays

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Check installed tools
python scanner.py --check-tools

# Run scan
python scanner.py testphp.vulnweb.com

# View report
firefox results/testphp.vulnweb.com_*/report.html
```

## Installation

**Python packages:**
```bash
pip install python-nmap jinja2 rich
```

**Security tools (Ubuntu/Debian):**
```bash
sudo apt install nmap gobuster nikto sslscan whatweb
```

**Go-based tools:**
```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## Usage

```bash
# Basic scan
python scanner.py <target>

# Fast scan with custom ports
python scanner.py example.com --fast --ports 80,443,8080

# Stealth mode
python scanner.py target.com --delay 2 --user-agent "Custom UA"

# Skip specific tools
python scanner.py site.com --skip-ssl --skip-subdomains

# Verbose output
python scanner.py target.com --verbose
```

## Options

| Option | Description |
|--------|-------------|
| `--fast` | Fast mode (less aggressive) |
| `--ports` | Comma-separated ports (default: 80,443) |
| `--delay` | Delay between tool executions (stealth) |
| `--user-agent` | Custom user agent |
| `--skip-ssl` | Skip SSL/TLS analysis |
| `--skip-subdomains` | Skip subdomain enumeration |
| `--skip-fingerprint` | Skip technology fingerprinting |
| `--verbose, -v` | Show verbose output |
| `--check-tools` | Check installed tools and exit |

## Output

```
results/<target>_<timestamp>/
├── nmap.txt / nmap.xml
├── gobuster.txt
├── nikto.txt
├── nuclei.txt
├── sslscan.txt
├── subfinder.txt
├── whatweb.txt
├── summary.json
└── report.html
```

## Detection Coverage

- **CVEs**: Log4Shell, Spring4Shell, Zerologon, Follina, Citrix Bleed, XZ Backdoor
- **Injections**: SQL, XSS, XXE, LDAP, Command injection, SSRF
- **Auth Issues**: Bypasses, default credentials, privilege escalation
- **SSL/TLS**: Heartbleed, POODLE, weak ciphers, expired certificates
- **Misconfigs**: CORS, missing security headers, directory listings

## Legal Notice

⚠️ **Only scan systems you have permission to test.** Unauthorized scanning may violate laws. This tool is for authorized security assessments only.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Author

[@Mosesjuju](https://github.com/Mosesjuju)
