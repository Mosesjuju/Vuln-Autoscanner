# VULN-AUTOSCANNER

Automated security scanner running 7 tools in parallel with drift detection and stealth mode.

## Features

- **7 Tools**: nmap, gobuster, nikto, nuclei, sslscan, subfinder, whatweb
- **Parallel Execution** with real-time progress bars
- **50+ CVE Patterns** (2020-2025): Log4Shell, Spring4Shell, Zerologon, etc.
- **Drift Detection**: Track vulnerability changes between scans
- **Stealth Mode**: Adaptive rate limiting with WAF/IDS evasion
- **JSON + HTML Reports** with risk scoring

## Quick Start

```bash
pip install -r requirements.txt
python scanner.py --check-tools
python scanner.py testphp.vulnweb.com
```

## Usage

```bash
python scanner.py <target>                    # Basic scan
python scanner.py site.com --fast             # Fast mode
python scanner.py site.com --stealth          # WAF evasion (3-8s delays)
python scanner.py site.com --ports 80,443,8080
```

## Drift Detection

Tracks changes between scans automatically:
```
📊 Drift Detection:
  Unchanged: 9
  +1 new findings
  -1 removed findings
```

Files: `results/scan_latest.json`, `results/scan_previous.json`

## Output

```
results/<target>_<timestamp>/
├── *.txt/xml           # Raw tool outputs
├── summary.json        # Structured findings
└── report.html         # Interactive report
```

## Key Options

| Flag | Description |
|------|-------------|
| `--fast` | Quick scan mode |
| `--stealth` | Adaptive delays + WAF detection |
| `--delay N` | Fixed N-second delays |
| `--verbose` | Show detailed stats |
| `--check-tools` | Verify installations |

## Legal

⚠️ Only scan authorized systems. Unauthorized scanning may violate laws.

## License

MIT - [@Mosesjuju](https://github.com/Mosesjuju)
