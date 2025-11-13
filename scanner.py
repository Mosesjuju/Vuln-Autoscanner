#!/usr/bin/env python3
"""
VULN-AUTOSCANNER v1.0 (NO AI)
Single-file CLI scanner that runs nmap, gobuster, nikto and nuclei in parallel,
parses outputs with regex/rule-based scoring and produces JSON + HTML reports.

Requirements: python-nmap, jinja2, rich
Install: pip install python-nmap jinja2 rich

Usage:
    python scanner.py <target> [--ports 80,443] [--fast] [--wordlist /path/to/wordlist]

Note: This script calls external CLI tools (nmap, gobuster, nikto, nuclei). Ensure
those tools are installed on the host. The script handles missing tools gracefully and
records that in the output.

"""

import argparse
import concurrent.futures
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
import datetime
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    import nmap as nmaplib  # type: ignore  # optional, fallback to CLI if missing
except Exception:
    nmaplib = None

try:
    from jinja2 import Template
except Exception:
    print("Missing dependency: jinja2. Install with: pip install jinja2", file=sys.stderr)
    raise

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
    from rich.live import Live
    from rich.panel import Panel
    from rich.layout import Layout
except Exception:
    Console = None

console = Console() if Console else None

# User agent rotation for stealth
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]

# Embedded Jinja2 template for HTML report (collapsible, styled, printable)
TEMPLATE_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>VULN-AUTOSCANNER Report - {{ target }}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 0; background:#f8f9fb; color:#222 }
    .header { background:#0b5; padding:16px; color:#fff }
    .container { padding:16px; max-width:1100px; margin:0 auto }
    .card { background:#fff; border-radius:6px; padding:12px; margin-bottom:12px; box-shadow:0 1px 4px rgba(0,0,0,0.06) }
    summary { font-weight:600; cursor:pointer; }
    .risk-pill { display:inline-block; padding:2px 8px; border-radius:999px; color:#fff; font-weight:700; font-size:12px }
    .risk-critical { background:#8b0000 }
    .risk-high { background:#d9534f }
    .risk-medium { background:#f0ad4e; color:#111 }
    .risk-low { background:#5bc0de }
    pre { background:#0f1724; color:#d6f8ff; padding:12px; overflow:auto; border-radius:4px }
    table { width:100%; border-collapse:collapse }
    th,td { text-align:left; padding:8px; border-bottom:1px solid #eee }
    @media print { .header, .no-print { display:none } }
  </style>
</head>
<body>
  <div class="header">
    <h1>VULN-AUTOSCANNER Report</h1>
    <div>{{ target }} &mdash; {{ timestamp }}</div>
  </div>
  <div class="container">
    <div class="card">
      <h2>Summary</h2>
      <p>Tools run: {{ tools|join(', ') }}</p>
      <table>
        <thead><tr><th>Tool</th><th>Findings</th><th>Highest Risk</th></tr></thead>
        <tbody>
        {% for tool in summary %}
          <tr>
            <td>{{ tool.tool }}</td>
            <td>{{ tool.findings|length }}</td>
            <td><span class="risk-pill risk-{{ tool.highest_risk|lower }}">{{ tool.highest_risk }}</span></td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>

    {% for tool in summary %}
    <div class="card">
      <details open>
        <summary>{{ tool.tool }} — {{ tool.findings|length }} findings</summary>
        {% if tool.raw_output %}
        <h4>Raw Output</h4>
        <pre>{{ tool.raw_output }}</pre>
        {% endif %}

        {% if tool.findings %}
          <h4>Parsed Findings</h4>
          {% for f in tool.findings %}
            <div style="margin-bottom:8px">
              <div style="display:flex;justify-content:space-between;align-items:center">
                <div><strong>{{ f.title }}</strong> <small style="color:#666">({{ f.rule }})</small></div>
                <div><span class="risk-pill risk-{{ f.risk|lower }}">{{ f.risk }}</span></div>
              </div>
              <div style="margin-top:6px;color:#333">{{ f.details }}</div>
              {% if f.evidence %}
                <pre>{{ f.evidence }}</pre>
              {% endif %}
            </div>
          {% endfor %}
        {% else %}
          <p><em>No findings parsed for this tool.</em></p>
        {% endif %}
      </details>
    </div>
    {% endfor %}

  </div>
</body>
</html>
"""


# --------------------------- Helper utilities ---------------------------

def now_ts() -> str:
    return datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def safe_run(cmd: List[str], timeout: int = 300) -> Dict[str, Any]:
    """Run a subprocess command and capture outputs. Return dict with stdout, stderr, rc, cmd."""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return {"rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "cmd": " ".join(cmd)}
    except FileNotFoundError as e:
        return {"rc": 127, "stdout": "", "stderr": str(e), "cmd": " ".join(cmd)}
    except subprocess.TimeoutExpired as e:
        return {"rc": -1, "stdout": getattr(e, 'stdout', '') or '', "stderr": f"timeout after {timeout}s", "cmd": " ".join(cmd)}


def check_tool_availability(tool_name: str) -> bool:
    """Check if a command-line tool is available in PATH."""
    return shutil.which(tool_name) is not None


def check_all_tools() -> Dict[str, bool]:
    """Check availability of all security tools."""
    tools = {
        'nmap': check_tool_availability('nmap'),
        'gobuster': check_tool_availability('gobuster'),
        'nikto': check_tool_availability('nikto'),
        'nuclei': check_tool_availability('nuclei'),
        'sslscan': check_tool_availability('sslscan'),
        'subfinder': check_tool_availability('subfinder'),
        'whatweb': check_tool_availability('whatweb'),
    }
    return tools


# --------------------------- Runner functions ---------------------------

def run_nmap(target: str, outdir: Path, ports: str = "80,443", fast: bool = False, delay: float = 0) -> Dict[str, Any]:
    """Run nmap and save nmap.txt and nmap.xml outputs. Use nmap CLI for broad compatibility."""
    if delay > 0:
        time.sleep(delay)
    out_txt = outdir / "nmap.txt"
    out_xml = outdir / "nmap.xml"
    flags = ["-sV"]
    if fast:
        flags = ["-F"]
    cmd = ["nmap"] + flags + ["-p", ports, "-oN", str(out_txt), "-oX", str(out_xml), target]
    res = safe_run(cmd)
    # Read produced output files if present
    txt = out_txt.read_text(encoding="utf-8") if out_txt.exists() else res.get("stdout", "")
    xml = out_xml.read_text(encoding="utf-8") if out_xml.exists() else res.get("stderr", "")
    return {"tool": "nmap", "raw": txt + "\n" + xml, "rc": res.get("rc", 0), "meta": {"cmd": res.get("cmd"), "xml_path": str(out_xml) if out_xml.exists() else None}}


def run_gobuster(target: str, outdir: Path, wordlist: str = None, fast: bool = False, user_agent: str = None, delay: float = 0) -> Dict[str, Any]:
    """Run gobuster (dir) against the target. If target looks like a host, convert to http://target/"""
    if delay > 0:
        time.sleep(delay)
    out = outdir / "gobuster.txt"
    # choose default wordlist paths (common locations) or fall back to built-in list
    default_paths = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/wordlists/wfuzz/general/common.txt"
    ]
    chosen = None
    if wordlist:
        chosen = wordlist
    else:
        for p in default_paths:
            if os.path.exists(p):
                chosen = p
                break
    if not chosen:
        # create a comprehensive temporary wordlist with common paths (2024-2025 updates)
        chosen = str(outdir / "__built_in_wordlist.txt")
        outdir.mkdir(parents=True, exist_ok=True)
        builtin_wordlist = """admin
administrator
admins
api
api/v1
api/v2
api/v3
backup
backups
bin
cgi-bin
config
configs
console
cpanel
css
dashboard
data
db
debug
dev
dist
docs
download
downloads
etc
files
graphql
home
htdocs
images
img
includes
index
js
lib
libs
login
logout
logs
media
misc
modules
old
panel
phpmyadmin
pma
private
public
register
root
scripts
server
setup
site
src
static
stats
temp
test
testing
tmp
upload
uploads
user
users
var
web
webadmin
wordpress
wp-admin
wp-content
wp-includes
wp-json
.git
.svn
.env
.htaccess
.htpasswd
config.php
database.yml
web.config
robots.txt
sitemap.xml
admin.php
login.php
dashboard.php
index.php
phpinfo.php
test.php
backup.zip
backup.tar.gz
db.sql
dump.sql
api-docs
swagger
swagger-ui
health
healthz
metrics
status
actuator
actuator/health
.well-known
security.txt
"""
        Path(chosen).write_text(builtin_wordlist, encoding="utf-8")

    url = target if re.match(r'https?://', target) else f"http://{target}"
    cmd = ["gobuster", "dir", "-u", url, "-w", chosen, "-q"]
    if user_agent:
        cmd += ["-a", user_agent]
    if fast:
        cmd += ["-t", "10"]
    res = safe_run(cmd)
    # If gobuster wrote nothing but stdout has entries, save stdout
    if res.get("stdout"):
        out.write_text(res.get("stdout"), encoding="utf-8")
    elif res.get("stderr"):
        out.write_text(res.get("stderr"), encoding="utf-8")
    return {"tool": "gobuster", "raw": (out.read_text(encoding="utf-8") if out.exists() else res.get("stdout", "")), "rc": res.get("rc", 0), "meta": {"cmd": res.get("cmd"), "wordlist": chosen, "user_agent": user_agent}}


def run_nikto(target: str, outdir: Path, fast: bool = False, user_agent: str = None, delay: float = 0) -> Dict[str, Any]:
    if delay > 0:
        time.sleep(delay)
    out = outdir / "nikto.txt"
    host = target if re.match(r'https?://', target) else f"http://{target}"
    
    # Use faster options to reduce scan time
    cmd = ["nikto", "-h", host, "-nointeractive", "-maxtime", "300"]  # 5 minute max
    
    if user_agent:
        cmd += ["-useragent", user_agent]
    
    if fast:
        # Fast mode: only check for interesting files/directories
        cmd += ["-Tuning", "x"]
    else:
        # Normal mode: balanced scan (skip slow checks)
        cmd += ["-Tuning", "x", "b", "c"]  # Interesting files, software identification, misc checks
    
    res = safe_run(cmd, timeout=360)  # 6 minute timeout (longer than maxtime)
    
    # Combine stdout and stderr - Nikto outputs to both
    combined = res.get("stdout", "") + "\n" + res.get("stderr", "")
    if combined.strip():
        out.write_text(combined, encoding="utf-8")
    
    raw_output = out.read_text(encoding="utf-8") if out.exists() else combined
    
    # Add diagnostic info
    if res.get("rc", 0) == 127:
        raw_output = f"[Tool Not Found] nikto is not installed or not in PATH\nInstall: apt install nikto\nCommand attempted: {res.get('cmd', '')}"
    elif not raw_output.strip() and res.get("rc", 0) != 0:
        raw_output = f"[Tool Error] nikto failed with exit code {res.get('rc', 0)}\nCommand: {res.get('cmd', '')}\nError: {res.get('stderr', 'Target may be unreachable or blocking scans')}"
    elif not raw_output.strip():
        raw_output = f"[No Results] nikto returned no output for {host}\nThis may indicate: target is unreachable, blocking scans, or no vulnerabilities found."
    
    return {"tool": "nikto", "raw": raw_output, "rc": res.get("rc", 0), "meta": {"cmd": res.get("cmd"), "user_agent": user_agent, "host": host}}


def run_nuclei(target: str, outdir: Path, fast: bool = False, delay: float = 0) -> Dict[str, Any]:
    if delay > 0:
        time.sleep(delay)
    out = outdir / "nuclei.txt"
    url = target if re.match(r'https?://', target) else f"http://{target}"
    cmd = ["nuclei", "-u", url, "-silent"]
    if fast:
        cmd += ["-t", "critical"]
    res = safe_run(cmd)
    if res.get("stdout"):
        out.write_text(res.get("stdout"), encoding="utf-8")
    elif res.get("stderr"):
        out.write_text(res.get("stderr"), encoding="utf-8")
    return {"tool": "nuclei", "raw": (out.read_text(encoding="utf-8") if out.exists() else res.get("stdout", "")), "rc": res.get("rc", 0), "meta": {"cmd": res.get("cmd")}}


def run_sslscan(target: str, outdir: Path, delay: float = 0) -> Dict[str, Any]:
    """Run sslscan to check SSL/TLS configuration, cipher suites, and vulnerabilities."""
    if delay > 0:
        time.sleep(delay)
    out = outdir / "sslscan.txt"
    # Extract hostname without protocol
    host = re.sub(r'https?://', '', target).split('/')[0].split(':')[0]
    cmd = ["sslscan", "--no-colour", host]
    res = safe_run(cmd, timeout=180)
    
    # Combine stdout and stderr for complete output
    combined = res.get("stdout", "") + "\n" + res.get("stderr", "")
    if combined.strip():
        out.write_text(combined, encoding="utf-8")
    
    raw_output = out.read_text(encoding="utf-8") if out.exists() else combined
    
    # Add diagnostic info if no output
    if not raw_output.strip() and res.get("rc", 0) != 0:
        raw_output = f"[Tool Error] sslscan failed with exit code {res.get('rc', 0)}\nCommand: {res.get('cmd', '')}\nError: {res.get('stderr', 'No output')}"
    
    return {"tool": "sslscan", "raw": raw_output, "rc": res.get("rc", 0), "meta": {"cmd": res.get("cmd"), "host": host}}


def run_subfinder(target: str, outdir: Path, delay: float = 0) -> Dict[str, Any]:
    """Run subfinder for subdomain enumeration."""
    if delay > 0:
        time.sleep(delay)
    out = outdir / "subfinder.txt"
    # Extract domain without protocol and path
    domain = re.sub(r'https?://', '', target).split('/')[0].split(':')[0]
    cmd = ["subfinder", "-d", domain, "-silent"]
    res = safe_run(cmd, timeout=120)
    
    # Combine stdout and stderr
    combined = res.get("stdout", "") + "\n" + res.get("stderr", "")
    if combined.strip():
        out.write_text(combined, encoding="utf-8")
    
    raw_output = out.read_text(encoding="utf-8") if out.exists() else combined
    
    # Add diagnostic info if tool failed or not installed
    if res.get("rc", 0) == 127:
        raw_output = f"[Tool Not Found] subfinder is not installed or not in PATH\nInstall: https://github.com/projectdiscovery/subfinder\nCommand attempted: {res.get('cmd', '')}"
    elif not raw_output.strip() and res.get("rc", 0) != 0:
        raw_output = f"[Tool Error] subfinder failed with exit code {res.get('rc', 0)}\nCommand: {res.get('cmd', '')}\nThis may be normal if the domain has no subdomains or is not publicly accessible."
    elif not raw_output.strip():
        raw_output = f"[No Results] subfinder found no subdomains for {domain}\nThis may indicate: no subdomains exist, domain is not in public datasets, or API keys not configured."
    
    return {"tool": "subfinder", "raw": raw_output, "rc": res.get("rc", 0), "meta": {"cmd": res.get("cmd"), "domain": domain}}


def run_whatweb(target: str, outdir: Path, user_agent: str = None, delay: float = 0) -> Dict[str, Any]:
    """Run whatweb for technology fingerprinting."""
    if delay > 0:
        time.sleep(delay)
    out = outdir / "whatweb.txt"
    url = target if re.match(r'https?://', target) else f"http://{target}"
    cmd = ["whatweb", "-a", "3", "--color=never", url]
    if user_agent:
        cmd += ["-U", user_agent]
    res = safe_run(cmd, timeout=120)
    
    # Combine stdout and stderr
    combined = res.get("stdout", "") + "\n" + res.get("stderr", "")
    if combined.strip():
        out.write_text(combined, encoding="utf-8")
    
    raw_output = out.read_text(encoding="utf-8") if out.exists() else combined
    
    # Add diagnostic info
    if res.get("rc", 0) == 127:
        raw_output = f"[Tool Not Found] whatweb is not installed or not in PATH\nInstall: gem install whatweb OR apt install whatweb\nCommand attempted: {res.get('cmd', '')}"
    elif not raw_output.strip() and res.get("rc", 0) != 0:
        raw_output = f"[Tool Error] whatweb failed with exit code {res.get('rc', 0)}\nCommand: {res.get('cmd', '')}\nError: {res.get('stderr', 'Target may be unreachable')}"
    elif not raw_output.strip():
        raw_output = f"[No Results] whatweb returned no output for {url}\nTarget may be blocking requests or is unreachable."
    
    return {"tool": "whatweb", "raw": raw_output, "rc": res.get("rc", 0), "meta": {"cmd": res.get("cmd"), "user_agent": user_agent, "url": url}}


# --------------------------- Parsers & Scoring ---------------------------

# Basic rule-based patterns and risk mapping
RISK_ORDER = ["Critical", "High", "Medium", "Low"]

# Expanded patterns with recent CVEs (2020-2025) and common vulnerabilities
PATTERNS = {
    # pattern: (title, risk, short_rule)
    
    # XSS Vulnerabilities (Enhanced Detection)
    r"<script[^>]*>.*?</script>|<script[^>]*>": ("XSS: Script tag injection", "High", "xss_script"),
    r"javascript:|data:text/html": ("XSS: JavaScript protocol", "High", "xss_js_proto"),
    r"onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=": ("XSS: Event handler injection", "High", "xss_event"),
    r"<iframe[^>]*>|<object[^>]*>|<embed[^>]*>": ("XSS: Dangerous tags", "High", "xss_tags"),
    r"eval\(|Function\(|setTimeout\(|setInterval\(": ("XSS: Dangerous JavaScript functions", "High", "xss_eval"),
    r"document\.cookie|document\.write|innerHTML|outerHTML": ("XSS: DOM manipulation", "Medium", "xss_dom"),
    r"<img[^>]*onerror|<svg[^>]*onload|<body[^>]*onload": ("XSS: Image/SVG exploit", "High", "xss_img_svg"),
    r"<input[^>]*onfocus|<details[^>]*ontoggle": ("XSS: Form element exploit", "Medium", "xss_form"),
    r"vbscript:|about:|view-source:": ("XSS: Alternative protocols", "Medium", "xss_protocols"),
    r"<!--.*<script.*-->|\/\*.*<script.*\*\/": ("XSS: Comment obfuscation", "High", "xss_comment"),
    
    # Generic CVE detection
    r"CVE-\d{4}-\d+": ("Known CVE detected", "Critical", "cve"),
    
    # High-profile CVEs (2020-2025)
    r"CVE-2021-44228|Log4Shell|log4j": ("Log4Shell (CVE-2021-44228)", "Critical", "log4shell"),
    r"CVE-2022-22965|Spring4Shell": ("Spring4Shell (CVE-2022-22965)", "Critical", "spring4shell"),
    r"CVE-2023-23397|Outlook": ("Outlook Elevation (CVE-2023-23397)", "Critical", "outlook_vuln"),
    r"CVE-2024-3094|xz backdoor": ("XZ Backdoor (CVE-2024-3094)", "Critical", "xz_backdoor"),
    r"CVE-2023-4966|Citrix Bleed": ("Citrix Bleed (CVE-2023-4966)", "Critical", "citrix_bleed"),
    r"CVE-2021-3156|Sudo Baron Samedit": ("Sudo Heap Overflow (CVE-2021-3156)", "Critical", "sudo_vuln"),
    r"CVE-2020-1472|Zerologon": ("Zerologon (CVE-2020-1472)", "Critical", "zerologon"),
    r"CVE-2022-30190|Follina": ("Follina MSDT (CVE-2022-30190)", "Critical", "follina"),
    r"CVE-2023-22515|Confluence": ("Confluence Auth Bypass (CVE-2023-22515)", "Critical", "confluence_vuln"),
    r"CVE-2024-21762|Fortinet": ("Fortinet SSL VPN (CVE-2024-21762)", "Critical", "fortinet_vuln"),
    
    # Injection vulnerabilities
    r"SQL injection|sql injection|SQLi|stack trace|SQL syntax": ("Potential SQL Injection", "High", "sql"),
    r"command injection|shell injection|RCE|remote code execution": ("Command/RCE vulnerability", "Critical", "rce"),
    r"LDAP injection|ldapi": ("LDAP Injection", "High", "ldap_inj"),
    r"XML injection|XXE|XML External Entity": ("XML/XXE Injection", "High", "xxe"),
    r"SSRF|Server-Side Request Forgery": ("Server-Side Request Forgery", "High", "ssrf"),
    
    # Authentication & Authorization
    r"401 Unauthorized|403 Forbidden": ("Auth restricted resource", "Low", "auth"),
    r"authentication bypass|auth bypass": ("Authentication Bypass", "Critical", "auth_bypass"),
    r"privilege escalation|privesc": ("Privilege Escalation", "High", "privesc"),
    r"default credentials|default password": ("Default Credentials", "High", "default_creds"),
    r"session fixation|session hijacking": ("Session Security Issue", "High", "session_vuln"),
    
    # Information disclosure
    r"Directory listing for|Index of /": ("Directory listing exposed", "Medium", "dir_list"),
    r"password|passwd|credentials|secret|api[_-]?key": ("Potential credential disclosure", "High", "creds"),
    r"\.git|\.svn|\.env|\.htaccess|web\.config": ("Sensitive file exposed", "Medium", "sensitive_file"),
    r"phpinfo\(\)|PHP Version": ("PHP Info disclosure", "Medium", "phpinfo"),
    r"stack trace|error message|exception": ("Error/Stack trace disclosure", "Medium", "error_disc"),
    r"backup|\.bak|\.old|\.backup|\.swp": ("Backup file found", "Medium", "backup_file"),
    
    # Security headers & configurations
    r"X-Frame-Options not set|Clickjacking": ("Missing clickjacking protection", "Low", "clickjack"),
    r"X-Content-Type-Options not set": ("Missing MIME-sniffing protection", "Low", "mime_sniff"),
    r"Strict-Transport-Security not set|HSTS": ("Missing HSTS header", "Low", "hsts"),
    r"Content-Security-Policy not set|CSP": ("Missing CSP header", "Low", "csp"),
    r"CORS misconfiguration|Access-Control-Allow-Origin: \*": ("CORS misconfiguration", "Medium", "cors"),
    
    # Server & version disclosure
    r"Server: Apache|Server: nginx|Server: Microsoft-IIS": ("Server header disclosure", "Low", "server_hdr"),
    r"X-Powered-By": ("Technology disclosure header", "Low", "powered_by"),
    
    # Nuclei severity markers
    r"score: critical|severity: critical|\[critical\]": ("Critical severity finding", "Critical", "sev_crit"),
    r"score: high|severity: high|\[high\]": ("High severity finding", "High", "sev_high"),
    
    # Path patterns (admin panels, etc.)
    r"/admin|/administrator|/wp-admin|/cpanel": ("Admin panel found", "Medium", "admin_page"),
    r"/phpmyadmin|/pma": ("PhpMyAdmin found", "Medium", "phpmyadmin"),
    r"/upload|/uploads|/files": ("Upload directory found", "Medium", "upload_dir"),
    r"/api|/api/v\d": ("API endpoint found", "Low", "api_endpoint"),
    
    # Common vulnerabilities
    r"path traversal|directory traversal|\.\.\/": ("Path Traversal", "High", "path_trav"),
    r"file inclusion|LFI|RFI": ("File Inclusion vulnerability", "High", "file_incl"),
    r"open redirect|unvalidated redirect": ("Open Redirect", "Medium", "open_redir"),
    r"CSRF|Cross-Site Request Forgery": ("CSRF vulnerability", "Medium", "csrf"),
    r"insecure deserialization": ("Insecure Deserialization", "High", "deserial"),
}


def score_text_findings(text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for pat, (title, risk, rule) in PATTERNS.items():
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            snippet = m.group(0)
            findings.append({
                "title": title,
                "rule": rule,
                "risk": risk,
                "details": f"Matched pattern /{pat}/: '{snippet}'",
                "evidence": _extract_context(text, m.start(), m.end())
            })
    # Heuristics: long lists of directories -> medium risk
    if len(re.findall(r"/\w+\s*-\s*\d{3}", text)) > 5:
        findings.append({"title": "Many discovered paths", "rule": "multiple_paths", "risk": "Medium", "details": "Gobuster discovered many directory entries", "evidence": text[:500]})

    return dedupe_findings(findings)


def _extract_context(text: str, s: int, e: int, ctx: int = 120) -> str:
    start = max(0, s - ctx)
    end = min(len(text), e + ctx)
    return text[start:end].strip()


def dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for f in findings:
        key = (f.get('title'), f.get('rule'), f.get('evidence', '')[:120])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def parse_nmap(raw: str) -> List[Dict[str, Any]]:
    # nmap output may include service versions and script results
    return score_text_findings(raw)


def parse_gobuster(raw: str) -> List[Dict[str, Any]]:
    """Parse gobuster output, only report sensitive/interesting paths."""
    findings = []
    
    # Skip if tool error or not found
    if raw.startswith("[Tool Not Found]") or raw.startswith("[Tool Error]") or raw.startswith("[No Results]"):
        if raw.startswith("[Tool Not Found]") or raw.startswith("[Tool Error]"):
            return [{
                "title": "Gobuster tool issue",
                "rule": "tool_error",
                "risk": "Low",
                "details": raw.split('\n')[0],
                "evidence": ""
            }]
        return []
    
    # Only flag paths with status codes that indicate actual findings
    # 200: Accessible resource, 301/302: Redirects (may reveal structure), 401/403: Protected resources
    interesting_paths = []
    for line in raw.splitlines():
        # Gobuster format: /path (Status: 200) [Size: 1234]
        match = re.search(r'(/[\w\-\./_]*)\s+\(Status:\s+(\d{3})\)', line)
        if match:
            path = match.group(1)
            status = match.group(2)
            
            # Only report interesting findings
            if status in ['200', '301', '302', '401', '403']:
                # Check if path matches sensitive patterns
                if any(pattern in path.lower() for pattern in [
                    'admin', 'config', 'backup', '.git', '.env', 'api', 
                    'login', 'upload', 'private', 'secret', '.bak', 'old',
                    'database', 'db', 'sql', 'phpmyadmin', 'test', 'dev'
                ]):
                    interesting_paths.append((path, status))
    
    # Add findings for interesting paths
    for path, status in interesting_paths:
        risk = "Medium"
        if any(p in path.lower() for p in ['admin', 'config', 'backup', '.git', '.env', 'database']):
            risk = "High"
        
        findings.append({
            "title": f"Sensitive path discovered: {path}",
            "rule": "sensitive_path",
            "risk": risk,
            "details": f"HTTP {status} - Path may contain sensitive resources",
            "evidence": path
        })
    
    # Run pattern matching only on full output (not per line)
    findings += score_text_findings(raw)
    
    return dedupe_findings(findings)


def parse_nikto(raw: str) -> List[Dict[str, Any]]:
    """Parse nikto output, filter out only the most noisy informational findings."""
    findings = []
    
    # Skip if tool error or not found
    if raw.startswith("[Tool Not Found]") or raw.startswith("[Tool Error]") or raw.startswith("[No Results]"):
        if raw.startswith("[Tool Not Found]") or raw.startswith("[Tool Error]"):
            return [{
                "title": "Nikto tool issue",
                "rule": "tool_error",
                "risk": "Low",
                "details": raw.split('\n')[0],
                "evidence": ""
            }]
        return []
    
    # Parse nikto findings line by line
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith('+'):
            continue
        
        # Skip only meta information and truly informational lines
        skip_patterns = [
            'Target IP:',
            'Target Hostname:',
            'Target Port:',
            'Start Time:',
            'End Time:',
            'Server: ',  # Just the server line, not findings about server
            'Scan terminated:',
            'host(s) tested',
            '----------',
        ]
        
        # Check if this is a line to skip
        should_skip = False
        for pattern in skip_patterns:
            if line.startswith('+ ' + pattern):
                should_skip = True
                break
        
        if should_skip:
            continue
        
        # Determine risk level based on content
        risk = "Medium"  # Default for Nikto findings
        
        # High risk indicators
        if any(high_risk in line.lower() for high_risk in [
            'sql injection', 'command injection', 'remote code execution',
            'authentication bypass', 'arbitrary code', 'rce',
            'file inclusion', 'directory traversal', '../',
            'default password', 'default credential'
        ]):
            risk = "High"
        
        # Critical indicators
        elif any(critical in line.lower() for critical in [
            'shell', 'backdoor', 'malware', 'trojan'
        ]):
            risk = "Critical"
        
        # Low risk - informational headers (but still report them)
        elif any(low_risk in line.lower() for low_risk in [
            'retrieved x-powered-by', 'x-frame-options', 'x-content-type-options',
            'uncommon header'
        ]):
            risk = "Low"
        
        findings.append({
            "title": "Nikto: " + line.strip('+ ')[:80],
            "rule": "nikto_finding",
            "risk": risk,
            "details": line.strip('+ '),
            "evidence": line
        })
    
    # Don't use score_text_findings for Nikto (findings already extracted above)
    
    return dedupe_findings(findings)


def parse_nuclei(raw: str) -> List[Dict[str, Any]]:
    """Parse nuclei output, only report medium/high/critical findings."""
    findings = []
    
    # Skip if tool error or not found
    if raw.startswith("[Tool Not Found]") or raw.startswith("[Tool Error]") or raw.startswith("[No Results]"):
        if raw.startswith("[Tool Not Found]") or raw.startswith("[Tool Error]"):
            return [{
                "title": "Nuclei tool issue",
                "rule": "tool_error",
                "risk": "Low",
                "details": raw.split('\n')[0],
                "evidence": ""
            }]
        return []
    
    for line in raw.splitlines():
        # Example nuclei line: "[high] CVE-2020-1234 - /path - template-id"
        if not line.strip():
            continue
        
        # severity in brackets
        m = re.search(r"\[(critical|high|medium|low|info)\]", line, flags=re.IGNORECASE)
        if m:
            sev = m.group(1).lower()
            
            # Skip low and info severity findings
            if sev in ['low', 'info']:
                continue
            
            # Extract template/vulnerability name
            title = re.sub(r"\[.*?\]", "", line).strip()
            risk = _map_severity_to_risk(sev)
            
            findings.append({
                "title": f"Nuclei: {title[:100]}",
                "rule": "nuclei_vuln",
                "risk": risk,
                "details": line.strip(),
                "evidence": line.strip()
            })
    
    # Don't run score_text_findings on nuclei output (too noisy)
    return dedupe_findings(findings)


def _map_severity_to_risk(sev: str) -> str:
    if sev.lower() == 'critical':
        return 'Critical'
    if sev.lower() == 'high':
        return 'High'
    if sev.lower() == 'medium':
        return 'Medium'
    return 'Low'


def parse_sslscan(raw: str) -> List[Dict[str, Any]]:
    """Parse sslscan output for SSL/TLS vulnerabilities."""
    findings = []
    
    # Skip if tool error or not found
    if raw.startswith("[Tool Not Found]") or raw.startswith("[Tool Error]"):
        findings.append({
            "title": "SSLScan tool issue",
            "rule": "tool_error",
            "risk": "Low",
            "details": raw.split('\n')[0],
            "evidence": ""
        })
        return findings
    
    # Check for known SSL/TLS vulnerabilities
    # Note: Check for positive vulnerability indicators, exclude "not vulnerable" statements
    vuln_patterns = {
        r"(?<!not )(?<!NOT )[Vv]ulnerable to.*[Hh]eartbleed": ("Heartbleed vulnerability (CVE-2014-0160)", "Critical", "heartbleed"),
        r"(?<!not )(?<!NOT )[Vv]ulnerable to.*POODLE": ("POODLE vulnerability", "High", "poodle"),
        r"(?<!not )(?<!NOT )[Vv]ulnerable to.*BEAST": ("BEAST vulnerability", "Medium", "beast"),
        r"SSLv2 enabled|SSLv3 enabled": ("Insecure SSL version enabled", "High", "ssl_version"),
        r"TLS 1\.0 enabled|TLS 1\.1 enabled": ("Outdated TLS version", "Medium", "tls_old"),
        r"Certificate expired|Certificate has expired": ("Expired SSL certificate", "High", "cert_expired"),
        r"Self-signed certificate": ("Self-signed certificate", "Medium", "self_signed"),
        r"Accepted.*(?:NULL|ANON|EXPORT|DES-|RC4|MD5)": ("Weak cipher suite", "Medium", "weak_cipher"),
    }
    
    for pat, (title, risk, rule) in vuln_patterns.items():
        for m in re.finditer(pat, raw, flags=re.IGNORECASE):
            # Additional check: skip if line contains "not vulnerable"
            line = raw[max(0, m.start()-100):m.end()+100]
            if "not vulnerable" in line.lower():
                continue
            findings.append({
                "title": title,
                "rule": rule,
                "risk": risk,
                "details": f"SSL/TLS issue detected: {m.group(0)}",
                "evidence": _extract_context(raw, m.start(), m.end(), ctx=80)
            })
    
    # Generic scoring (but skip diagnostic messages)
    if not raw.startswith("["):
        findings += score_text_findings(raw)
    
    return dedupe_findings(findings)


def parse_subfinder(raw: str) -> List[Dict[str, Any]]:
    """Parse subfinder output to count subdomains discovered."""
    findings = []
    
    # Skip if tool error or not found
    if raw.startswith("[Tool Not Found]") or raw.startswith("[Tool Error]"):
        findings.append({
            "title": "Subfinder tool issue",
            "rule": "tool_error",
            "risk": "Low",
            "details": raw.split('\n')[0],
            "evidence": ""
        })
        return findings
    
    # Skip if no results message
    if raw.startswith("[No Results]"):
        return []  # Don't report this as a finding
    
    subdomains = [line.strip() for line in raw.splitlines() if line.strip() and not line.startswith('[')]
    
    if len(subdomains) > 0:
        findings.append({
            "title": f"Discovered {len(subdomains)} subdomain(s)",
            "rule": "subdomain_enum",
            "risk": "Low" if len(subdomains) < 10 else "Medium",
            "details": f"Found {len(subdomains)} subdomains: {', '.join(subdomains[:5])}{'...' if len(subdomains) > 5 else ''}",
            "evidence": '\n'.join(subdomains[:10])
        })
    
    return findings


def parse_whatweb(raw: str) -> List[Dict[str, Any]]:
    """Parse whatweb output, only report outdated/vulnerable technologies."""
    findings = []
    
    # Skip if tool error or not found
    if raw.startswith("[Tool Not Found]") or raw.startswith("[Tool Error]") or raw.startswith("[No Results]"):
        if raw.startswith("[Tool Not Found]") or raw.startswith("[Tool Error]"):
            findings.append({
                "title": "WhatWeb tool issue",
                "rule": "tool_error",
                "risk": "Low",
                "details": raw.split('\n')[0],
                "evidence": ""
            })
        return findings
    
    # Known vulnerable/outdated technology versions
    vulnerable_versions = {
        # CMS versions with known vulnerabilities
        r"WordPress\[([0-5]\.[\d\.]+)\]": ("Outdated WordPress version", "High", "wordpress_old"),
        r"Joomla\[([0-3]\.[\d\.]+)\]": ("Outdated Joomla version", "High", "joomla_old"),
        r"Drupal\[([0-9]\.[\d\.]+)\]": ("Outdated Drupal version", "High", "drupal_old"),
        
        # PHP versions EOL (< 7.4 as of 2024)
        r"PHP\[([0-6]\.[\d\.]+)\]|PHP\[7\.[0-3]\.[\d]+\]": ("End-of-life PHP version", "High", "php_eol"),
        
        # Old jQuery versions with XSS vulnerabilities
        r"jQuery\[([0-2]\.[\d\.]+)\]|jQuery\[3\.0\.[\d]+\]": ("Vulnerable jQuery version", "Medium", "jquery_vuln"),
        
        # Old Apache versions
        r"Apache\[([0-1]\.[\d\.]+)\]|Apache\[2\.[0-3]\.[\d]+\]": ("Outdated Apache version", "Medium", "apache_old"),
        
        # Old Nginx versions
        r"nginx\[([0-1]\.[\d\.]+)\]": ("Outdated Nginx version", "Medium", "nginx_old"),
        
        # IIS old versions
        r"Microsoft-IIS\[([0-7]\.[\d]+)\]": ("Outdated IIS version", "Medium", "iis_old"),
    }
    
    for pat, (title, risk, rule) in vulnerable_versions.items():
        for m in re.finditer(pat, raw, flags=re.IGNORECASE):
            version = m.group(1) if m.groups() else ""
            details = f"{title}: {version}" if version else title
            findings.append({
                "title": title,
                "rule": rule,
                "risk": risk,
                "details": details,
                "evidence": m.group(0)
            })
    
    # Don't use generic score_text_findings for whatweb (too noisy)
    # Only report actual vulnerabilities found above
    
    return dedupe_findings(findings)


def parse_nmap_enhanced(raw: str, xml_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Enhanced nmap parser that uses XML output if available. Filters out low-risk open ports."""
    findings = []
    
    # High-risk ports that should always be flagged
    HIGH_RISK_PORTS = {
        '21': 'FTP - Insecure file transfer',
        '23': 'Telnet - Unencrypted remote access',
        '69': 'TFTP - Trivial file transfer',
        '135': 'MS-RPC - Windows RPC',
        '139': 'NetBIOS - File sharing',
        '445': 'SMB - File sharing (ransomware vector)',
        '1433': 'MS-SQL - Database server',
        '3306': 'MySQL - Database server',
        '3389': 'RDP - Remote Desktop',
        '5432': 'PostgreSQL - Database server',
        '5900': 'VNC - Remote access',
        '6379': 'Redis - Database (often unsecured)',
        '27017': 'MongoDB - Database (often unsecured)',
    }
    
    # Medium-risk services
    MEDIUM_RISK_SERVICES = ['mysql', 'postgresql', 'redis', 'mongodb', 'mssql', 'oracle']
    
    # Try to parse XML for structured data
    if xml_path and os.path.exists(xml_path):
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                # Extract ports and services
                for port in host.findall('.//port'):
                    portid = port.get('portid')
                    protocol = port.get('protocol')
                    state = port.find('state')
                    service = port.find('service')
                    
                    if state is not None and state.get('state') == 'open':
                        service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                        service_version = service.get('version', '') if service is not None else ''
                        product = service.get('product', '') if service is not None else ''
                        
                        # Only report high-risk ports and services
                        if portid in HIGH_RISK_PORTS:
                            risk = "High"
                            title = f"High-risk port {portid}/{protocol} open"
                            details = f"{HIGH_RISK_PORTS[portid]}: {product} {service_version}".strip()
                        elif service_name in MEDIUM_RISK_SERVICES:
                            risk = "Medium"
                            title = f"Database service exposed: {service_name}"
                            details = f"Port {portid}: {product} {service_version}".strip()
                        elif service_name in ['ssh', 'http', 'https', 'smtp', 'pop3', 'imap']:
                            # Common services - skip unless version is outdated
                            continue
                        else:
                            # Skip all other standard ports
                            continue
                        
                        findings.append({
                            "title": title,
                            "rule": "risky_port",
                            "risk": risk,
                            "details": details,
                            "evidence": f"Port {portid} is open running {service_name}"
                        })
        except Exception as e:
            # Fall back to text parsing
            findings.append({
                "title": "XML parse error",
                "rule": "parse_error",
                "risk": "Low",
                "details": f"Failed to parse nmap XML: {str(e)}",
                "evidence": ""
            })
    
    # Run text-based scoring only for actual vulnerabilities (not just open ports)
    text_findings = score_text_findings(raw)
    # Filter out generic "open port" mentions from score_text_findings
    text_findings = [f for f in text_findings if not (f.get('rule') == 'open_port' and f.get('risk') == 'Low')]
    findings += text_findings
    
    return dedupe_findings(findings)


# --------------------------- Report generation ---------------------------

def highest_risk(findings: List[Dict[str, Any]]) -> str:
    ranks = {r: i for i, r in enumerate(RISK_ORDER)}
    best = None
    for f in findings:
        r = f.get('risk', 'Low')
        if best is None or ranks.get(r, 3) < ranks.get(best, 3):
            best = r
    return best or 'Low'


def generate_json_summary(target: str, timestamp: str, results: List[Dict[str, Any]], outdir: Path) -> Path:
    summary = []
    for r in results:
        findings = r.get('parsed', [])
        summary.append({
            'tool': r.get('tool'),
            'findings': findings,
            'highest_risk': highest_risk(findings),
            'raw_output': (r.get('raw')[:100000])
        })
    payload = {
        'target': target,
        'timestamp': timestamp,
        'tools': [r.get('tool') for r in results],
        'summary': summary,
    }
    out = outdir / 'summary.json'
    out.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    return out


def generate_html_report(target: str, timestamp: str, results: List[Dict[str, Any]], outdir: Path) -> Path:
    # Render the embedded Jinja template
    summary = []
    for r in results:
        findings = r.get('parsed', [])
        summary.append({
            'tool': r.get('tool'),
            'findings': findings,
            'highest_risk': highest_risk(findings),
            'raw_output': r.get('raw')[:50000]
        })
    tpl = Template(TEMPLATE_HTML)
    html = tpl.render(target=target, timestamp=timestamp, tools=[r.get('tool') for r in results], summary=summary)
    out = outdir / 'report.html'
    out.write_text(html, encoding='utf-8')
    return out


# --------------------------- CLI & Orchestration ---------------------------

def cli_args():
    p = argparse.ArgumentParser(description='VULN-AUTOSCANNER v1.0 (NO AI)')
    p.add_argument('target', nargs='?', help='Target domain or URL (e.g. testphp.vulnweb.com or https://example.com)')
    p.add_argument('--ports', default='80,443', help='Comma-separated ports for nmap (default: 80,443)')
    p.add_argument('--fast', action='store_true', help='Run in fast mode (less aggressive scans)')
    p.add_argument('--wordlist', default=None, help='Path to wordlist for gobuster')
    p.add_argument('--timeout', type=int, default=300, help='Per-tool timeout in seconds')
    
    # Stealth and rate limiting options
    p.add_argument('--delay', type=float, default=0, help='Delay in seconds between tool executions (stealth mode)')
    p.add_argument('--user-agent', default=None, help='Custom user agent (random if not specified)')
    p.add_argument('--throttle', type=float, default=0, help='Throttle/delay between requests (where supported)')
    
    # Tool selection
    p.add_argument('--skip-ssl', action='store_true', help='Skip SSL/TLS scan')
    p.add_argument('--skip-subdomains', action='store_true', help='Skip subdomain enumeration')
    p.add_argument('--skip-fingerprint', action='store_true', help='Skip technology fingerprinting')
    
    # Debugging
    p.add_argument('--verbose', '-v', action='store_true', help='Show verbose output (commands executed, tool errors)')
    p.add_argument('--check-tools', action='store_true', help='Check which tools are installed and exit')
    
    return p.parse_args()


def main():
    args = cli_args()
    
    # Check tools availability first
    available_tools = check_all_tools()
    
    # If --check-tools flag, just show tool status and exit
    if args.check_tools:
        if console:
            console.print("\n[bold]Security Tools Status:[/bold]\n")
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Tool", style="cyan")
            table.add_column("Status", justify="center")
            table.add_column("Install Command", style="dim")
            
            install_cmds = {
                'nmap': 'apt install nmap',
                'gobuster': 'apt install gobuster',
                'nikto': 'apt install nikto',
                'nuclei': 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
                'sslscan': 'apt install sslscan',
                'subfinder': 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
                'whatweb': 'apt install whatweb',
            }
            
            for tool, installed in available_tools.items():
                status = "[green]✓ Installed[/green]" if installed else "[red]✗ Missing[/red]"
                install_cmd = install_cmds.get(tool, "See docs")
                table.add_row(tool, status, install_cmd if not installed else "")
            
            console.print(table)
            installed_count = sum(available_tools.values())
            console.print(f"\n[bold]Summary:[/bold] {installed_count}/{len(available_tools)} tools installed\n")
        else:
            for tool, installed in available_tools.items():
                status = "✓" if installed else "✗"
                print(f"{status} {tool}")
        sys.exit(0)
    
    # Require target if not just checking tools
    if not args.target:
        print("Error: target is required (or use --check-tools to see installed tools)")
        sys.exit(1)
    
    target = args.target
    ports = args.ports
    fast = args.fast
    wordlist = args.wordlist
    timeout = args.timeout
    delay = args.delay
    user_agent = args.user_agent or random.choice(USER_AGENTS)

    timestamp = now_ts()
    safe_target = re.sub(r'[^a-zA-Z0-9_.-]', '_', (target.replace('https://', '').replace('http://', '')))
    outdir = Path('results') / f"{safe_target}_{timestamp}"
    outdir.mkdir(parents=True, exist_ok=True)

    missing_tools = [tool for tool, avail in available_tools.items() if not avail]
    
    if console:
        console.print(f"\n[bold cyan]═══════════════════════════════════════════════════[/bold cyan]")
        console.print(f"[bold]  VULN-AUTOSCANNER v1.0[/bold]")
        console.print(f"[bold cyan]═══════════════════════════════════════════════════[/bold cyan]")
        console.print(f"[yellow]Target:[/yellow] [bold]{target}[/bold]")
        console.print(f"[yellow]Output:[/yellow] [green]{outdir}[/green]")
        console.print(f"[yellow]Mode:[/yellow] {'Fast' if fast else 'Normal'} | [yellow]Delay:[/yellow] {delay}s | [yellow]UA:[/yellow] {user_agent[:50]}...")
        
        # Show tool status
        if missing_tools:
            console.print(f"\n[bold yellow]⚠ Missing Tools:[/bold yellow] {', '.join(missing_tools)}")
            console.print(f"[dim]These tools will be skipped. Install them for full coverage.[/dim]")
        
        installed_count = len([t for t in available_tools.values() if t])
        console.print(f"[green]✓ Available:[/green] {installed_count}/{len(available_tools)} tools")
        console.print(f"[bold cyan]═══════════════════════════════════════════════════[/bold cyan]\n")

    results: List[Dict[str, Any]] = []

    # Build task list based on skip flags and tool availability
    tool_tasks = []
    
    # Core tools (always try to run)
    if available_tools.get('nmap', False):
        tool_tasks.append(('nmap', lambda: run_nmap(target, outdir, ports, fast, delay)))
    if available_tools.get('gobuster', False):
        tool_tasks.append(('gobuster', lambda: run_gobuster(target, outdir, wordlist, fast, user_agent, delay)))
    if available_tools.get('nikto', False):
        tool_tasks.append(('nikto', lambda: run_nikto(target, outdir, fast, user_agent, delay)))
    if available_tools.get('nuclei', False):
        tool_tasks.append(('nuclei', lambda: run_nuclei(target, outdir, fast, delay)))
    
    # Optional tools (check skip flags and availability)
    if not args.skip_ssl and available_tools.get('sslscan', False):
        tool_tasks.append(('sslscan', lambda: run_sslscan(target, outdir, delay)))
    if not args.skip_subdomains and available_tools.get('subfinder', False):
        tool_tasks.append(('subfinder', lambda: run_subfinder(target, outdir, delay)))
    if not args.skip_fingerprint and available_tools.get('whatweb', False):
        tool_tasks.append(('whatweb', lambda: run_whatweb(target, outdir, user_agent, delay)))
    
    # Warn if no tools available
    if not tool_tasks:
        if console:
            console.print("[bold red]ERROR:[/bold red] No security tools are installed!")
            console.print("Install at least: nmap, gobuster, nikto, or nuclei")
        sys.exit(1)

    # Modern progress bars with live stats
    if console and Progress:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(complete_style="green", finished_style="bold green"),
            TaskProgressColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            console=console,
            expand=True
        ) as progress:
            # Create progress tasks for each tool
            task_ids = {}
            for tool_name, _ in tool_tasks:
                task_ids[tool_name] = progress.add_task(f"[cyan]{tool_name:<12}", total=100)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(7, len(tool_tasks))) as ex:
                futures = {}
                for tool_name, tool_func in tool_tasks:
                    futures[ex.submit(tool_func)] = tool_name
                
                for fut in concurrent.futures.as_completed(futures):
                    tool_name = futures[fut]
                    try:
                        res = fut.result()
                        # Update description with result
                        rc_color = "green" if res.get('rc', 0) == 0 else "red"
                        progress.update(
                            task_ids[tool_name], 
                            completed=100,
                            description=f"[{rc_color}]✓ {tool_name:<10}[/{rc_color}]"
                        )
                        
                        # Show verbose info if enabled
                        if args.verbose and console:
                            cmd = res.get('meta', {}).get('cmd', 'N/A')
                            console.print(f"[dim]  └─ {tool_name}: {cmd}[/dim]")
                            if res.get('rc', 0) != 0:
                                console.print(f"[dim]     Exit code: {res.get('rc', 0)}[/dim]")
                    except Exception as e:
                        res = {"tool": tool_name, "raw": str(e), "rc": -1, "meta": {"error": str(e)}}
                        progress.update(
                            task_ids[tool_name], 
                            completed=100,
                            description=f"[red]✗ {tool_name:<10}[/red]"
                        )
                        if args.verbose and console:
                            console.print(f"[dim]  └─ {tool_name} error: {str(e)}[/dim]")
                    results.append(res)
    else:
        # Fallback without progress bars
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(7, len(tool_tasks))) as ex:
            futures = {}
            for tool_name, tool_func in tool_tasks:
                futures[ex.submit(tool_func)] = tool_name
            
            for fut in concurrent.futures.as_completed(futures):
                tool_name = futures[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"tool": tool_name, "raw": str(e), "rc": -1, "meta": {"error": str(e)}}
                results.append(res)
                if console:
                    console.print(f"[cyan]{tool_name}[/cyan] finished (rc={res.get('rc')})")

    # Parse outputs with enhanced parsers
    if console:
        console.print(f"\n[bold yellow]Parsing results...[/bold yellow]")
    
    parsed_results = []
    for r in results:
        tool = r.get('tool')
        raw = r.get('raw', '')
        parsed = []
        try:
            if tool == 'nmap':
                xml_path = r.get('meta', {}).get('xml_path')
                parsed = parse_nmap_enhanced(raw, xml_path)
            elif tool == 'gobuster':
                parsed = parse_gobuster(raw)
            elif tool == 'nikto':
                parsed = parse_nikto(raw)
            elif tool == 'nuclei':
                parsed = parse_nuclei(raw)
            elif tool == 'sslscan':
                parsed = parse_sslscan(raw)
            elif tool == 'subfinder':
                parsed = parse_subfinder(raw)
            elif tool == 'whatweb':
                parsed = parse_whatweb(raw)
            else:
                parsed = score_text_findings(raw)
        except Exception as e:
            parsed = [{"title": "Parser error", "rule": "parser_exception", "risk": "Low", "details": str(e), "evidence": raw[:400]}]
        parsed_results.append({"tool": tool, "raw": raw, "parsed": parsed, "meta": r.get('meta', {})})

    # Save summary JSON and HTML report
    summary_json = generate_json_summary(target, timestamp, parsed_results, outdir)
    summary_html = generate_html_report(target, timestamp, parsed_results, outdir)

    # Display final summary
    if console:
        console.print(f"\n[bold green]Scan complete![/bold green]\n")
        
        # Summary table
        table = Table(show_header=True, header_style="bold magenta", title="[bold]Results Summary[/bold]")
        table.add_column("Tool", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Findings", justify="right")
        table.add_column("Highest Risk", justify="center")
        
        for r in parsed_results:
            findings = r.get('parsed', [])
            rc = [res for res in results if res.get('tool') == r.get('tool')][0].get('rc', 0)
            status = "✓" if rc == 0 else "✗"
            status_color = "green" if rc == 0 else "red"
            risk = highest_risk(findings)
            risk_colors = {"Critical": "red", "High": "orange1", "Medium": "yellow", "Low": "green"}
            
            table.add_row(
                r.get('tool'),
                f"[{status_color}]{status}[/{status_color}]",
                str(len(findings)),
                f"[{risk_colors.get(risk, 'white')}]{risk}[/{risk_colors.get(risk, 'white')}]"
            )
        
        console.print(table)
        console.print(f"\n[bold]Reports:[/bold]")
        console.print(f"  📄 JSON: [green]{summary_json}[/green]")
        console.print(f"  🌐 HTML: [green]{summary_html}[/green]")
        console.print(f"\n[dim]Open HTML report in browser to view full details.[/dim]\n")
    else:
        print(f"Reports written: {summary_json}, {summary_html}")


if __name__ == '__main__':
    main()
