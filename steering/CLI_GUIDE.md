# R-Map CLI Guide: Plain English Commands

## Philosophy: Self-Documenting Commands

R-Map replaces nmap's cryptic flags with **plain English commands** that are self-explanatory.

**Design Principles:**
1. **Readable**: `--stealth-scan` instead of `-sS`
2. **Intuitive**: `--only-ping` instead of `-sn`
3. **Grouped**: Related options use consistent naming
4. **Backward Compatible**: Support nmap flags for familiarity

---

## Quick Comparison: nmap vs R-Map

| Task | nmap | R-Map Plain English |
|------|------|---------------------|
| **SYN scan** | `-sS` | `--scan syn` or `--stealth-scan` |
| **TCP connect** | `-sT` | `--scan connect` or `--tcp-scan` |
| **UDP scan** | `-sU` | `--scan udp` or `--udp-scan` |
| **Service detection** | `-sV` | `--service-detect` or `--grab-banners` |
| **OS detection** | `-O` | `--os-detect` or `--fingerprint-os` |
| **Skip ping** | `-Pn` | `--skip-ping` or `--no-ping` |
| **No DNS** | `-n` | `--no-dns` or `--skip-dns` |
| **All ports** | `-p-` | `--all-ports` or `--scan-all-ports` |
| **Fast scan** | `-F` | `--fast` or `--top-ports` |
| **Aggressive** | `-A` | `--scan-aggressive` or `--all-detection` |
| **Timing T4** | `-T4` | `--timing aggressive` or `--scan-fast` |

---

## Complete Command Reference

### SCAN TYPES

#### TCP Scanning
```bash
# SYN Stealth Scan (requires root)
rmap --scan syn TARGET
rmap --stealth-scan TARGET

# TCP Connect Scan (no root required)
rmap --scan connect TARGET
rmap --tcp-scan TARGET

# ACK Scan (firewall testing)
rmap --scan ack TARGET
rmap --firewall-test TARGET

# FIN Scan (stealthy)
rmap --scan fin TARGET

# NULL Scan (all flags off)
rmap --scan null TARGET

# Xmas Scan (FIN+PSH+URG)
rmap --scan xmas TARGET
```

#### UDP Scanning
```bash
# UDP port scan
rmap --scan udp TARGET
rmap --udp-scan TARGET

# Top UDP ports only
rmap --udp-scan --top-udp-ports TARGET
```

#### Combined Scanning
```bash
# TCP + UDP
rmap --scan "tcp+udp" TARGET
rmap --tcp-scan --udp-scan TARGET
```

---

### DISCOVERY & ENUMERATION

#### Host Discovery
```bash
# Just check if hosts are up (no port scan)
rmap --only-ping 192.168.1.0/24
rmap --discover-hosts 192.168.1.0/24

# Skip host discovery (assume all up)
rmap --skip-ping TARGET
rmap --no-ping TARGET

# TCP-based ping
rmap --tcp-ping TARGET

# ICMP ping (if implemented)
rmap --icmp-ping TARGET
```

#### Service Detection
```bash
# Detect service versions
rmap --service-detect TARGET
rmap --grab-banners TARGET
rmap -sV TARGET  # nmap compatibility

# Aggressive service detection
rmap --service-detect --probe-all TARGET
```

#### OS Fingerprinting
```bash
# Detect operating system
rmap --os-detect TARGET
rmap --fingerprint-os TARGET
rmap -O TARGET  # nmap compatibility

# Aggressive OS detection
rmap --os-detect --aggressive TARGET
```

---

### PORT SPECIFICATION

```bash
# Single port
rmap -p 80 TARGET
rmap --ports 80 TARGET

# Port range
rmap -p 1-1000 TARGET
rmap --ports 1-1000 TARGET

# Multiple ports/ranges
rmap -p 22,80,443,8000-9000 TARGET
rmap --ports "22,80,443,8000-9000" TARGET

# All ports (1-65535)
rmap --all-ports TARGET
rmap --scan-all-ports TARGET
rmap -p- TARGET  # nmap compatibility

# Top 100 ports (fast)
rmap --fast TARGET
rmap --top-ports TARGET
rmap -F TARGET  # nmap compatibility

# Top N ports
rmap --top-ports 1000 TARGET

# Top UDP ports
rmap --top-udp-ports TARGET
rmap --top-udp-ports 200 TARGET
```

---

### TIMING & PERFORMANCE

#### Timing Templates
```bash
# Paranoid (very slow, IDS evasion)
rmap --timing paranoid TARGET
rmap -T0 TARGET

# Sneaky (slow, IDS evasion)
rmap --timing sneaky TARGET
rmap -T1 TARGET

# Polite (slow, less bandwidth)
rmap --timing polite TARGET
rmap -T2 TARGET

# Normal (default)
rmap --timing normal TARGET
rmap -T3 TARGET

# Aggressive (fast)
rmap --timing aggressive TARGET
rmap --scan-fast TARGET
rmap -T4 TARGET

# Insane (very fast, may miss results)
rmap --timing insane TARGET
rmap -T5 TARGET
```

#### Scan Profiles (New!)
```bash
# Quick scan (top 100 TCP ports, no service detection)
rmap --quick-scan TARGET

# Thorough scan (all ports, service detection, OS detection)
rmap --thorough-scan TARGET

# Stealth scan (slow, SYN scan, avoid detection)
rmap --stealth-scan TARGET

# Aggressive scan (fast, all techniques)
rmap --aggressive-scan TARGET
rmap -A TARGET  # nmap compatibility
```

---

### OUTPUT & REPORTING

#### Output Formats
```bash
# Normal (human-readable, default)
rmap TARGET

# JSON output
rmap --format json TARGET
rmap -oJ results.json TARGET

# XML output
rmap --format xml TARGET
rmap -oX results.xml TARGET

# Save to file
rmap --output results.json --format json TARGET
rmap -o results.txt TARGET

# Verbose output
rmap --verbose TARGET
rmap --scan-verbose TARGET
rmap -v TARGET

# Very verbose
rmap -vv TARGET
rmap --verbose --verbose TARGET
```

#### Reporting (New!)
```bash
# HTML report with charts
rmap --report html --output scan.html TARGET

# PDF report (executive summary)
rmap --report pdf --output scan.pdf TARGET

# Markdown report
rmap --report markdown --output SCAN_RESULTS.md TARGET

# CSV export
rmap --report csv --output results.csv TARGET
```

---

### SCRIPTING & VULNERABILITY DETECTION

#### Script Categories
```bash
# Run all vulnerability scripts
rmap --script vuln TARGET
rmap --check-vulns TARGET

# Run all discovery scripts
rmap --script discovery TARGET
rmap --enumerate TARGET

# Run specific script
rmap --script ssh-brute TARGET
rmap --script http-headers TARGET

# Multiple scripts
rmap --script "vuln,discovery" TARGET

# Script arguments
rmap --script ssh-brute --script-args userdb=users.txt,passdb=pass.txt TARGET
```

#### Security Auditing (New!)
```bash
# Full security audit
rmap --security-audit TARGET
rmap --full-audit TARGET

# Check for known CVEs
rmap --check-cves TARGET

# Compliance check
rmap --compliance pci-dss TARGET
rmap --compliance hipaa TARGET
```

---

### ADVANCED OPTIONS

#### DNS Options
```bash
# No DNS resolution
rmap --no-dns TARGET
rmap --skip-dns TARGET
rmap -n TARGET

# Custom DNS server
rmap --dns-server 8.8.8.8 TARGET
```

#### Network Options
```bash
# Source port
rmap --source-port 53 TARGET

# Network interface
rmap --interface eth0 TARGET

# Maximum concurrent connections
rmap --max-connections 500 TARGET

# Global scan timeout
rmap --max-scan-time 3600 TARGET
```

#### Target Specification
```bash
# Single IP
rmap 192.168.1.1

# Hostname
rmap example.com

# CIDR notation
rmap 192.168.1.0/24

# IP range
rmap 192.168.1.1-254

# Multiple targets
rmap 192.168.1.1 10.0.0.1 example.com

# IPv6
rmap 2001:db8::1
rmap fe80::1

# From file
rmap --target-file targets.txt
rmap -iL targets.txt
```

---

## OBJECT-BASED COMMANDS (Innovation!)

### Discover Command
```bash
# Discover hosts on network
rmap discover hosts --network 192.168.1.0/24

# Discover services on host
rmap discover services --target example.com

# Discover vulnerabilities
rmap discover vulns --target 192.168.1.1
```

### Scan Command
```bash
# Scan with specific profile
rmap scan --type stealth --target example.com

# Scan with objective
rmap scan --objective ports --target 192.168.1.1
rmap scan --objective services --target example.com
rmap scan --objective os --target 10.0.0.1
rmap scan --objective vulns --target db.example.com
rmap scan --objective all --target 192.168.1.1
```

### Enumerate Command
```bash
# Enumerate users
rmap enumerate users --protocol smb --target 192.168.1.1

# Enumerate shares
rmap enumerate shares --target \\server

# Enumerate databases
rmap enumerate databases --target db.example.com
```

### Test Command
```bash
# Test firewall rules
rmap test firewall --target example.com

# Test SSL/TLS configuration
rmap test ssl --target https://example.com

# Test for specific vulnerability
rmap test heartbleed --target 192.168.1.1
```

---

## USE CASE EXAMPLES

### Basic Network Scan
```bash
# Quick scan of common ports
rmap --quick-scan 192.168.1.1

# Thorough scan with service detection
rmap --thorough-scan example.com

# Scan specific ports
rmap -p 80,443,8080 example.com --service-detect
```

### Security Auditing
```bash
# Full security audit
rmap --security-audit example.com --report pdf --output audit.pdf

# Check for vulnerabilities
rmap --check-vulns 192.168.1.0/24 --format json --output vulns.json

# Web application scan
rmap --web-scan https://example.com --check-cves
```

### Stealth Scanning
```bash
# Slow, stealthy scan
rmap --stealth-scan --timing paranoid example.com

# SYN scan with firewall evasion
rmap --scan syn --fragment --decoy-scan example.com
```

### Penetration Testing
```bash
# Aggressive scan with all techniques
rmap --aggressive-scan --all-ports example.com

# Vulnerability discovery
rmap --script "vuln,exploit" --timing aggressive 192.168.1.1

# Brute force attack
rmap --script ssh-brute --script-args userdb=users.txt,passdb=rockyou.txt 192.168.1.1
```

### Compliance Scanning
```bash
# PCI-DSS compliance check
rmap --compliance pci-dss 192.168.1.0/24 --report pdf --output pci-scan.pdf

# HIPAA compliance check
rmap --compliance hipaa db-server.example.com --format json
```

### Cloud Scanning
```bash
# AWS VPC scan
rmap scan-cloud --provider aws --region us-east-1 --vpc vpc-12345

# Kubernetes cluster scan
rmap scan-k8s --namespace production --context prod-cluster

# Docker container network scan
rmap scan-containers --docker-host unix:///var/run/docker.sock
```

---

## PLAIN ENGLISH CHEAT SHEET

### Common Tasks

| What You Want | Command |
|---------------|---------|
| **Quick scan** | `rmap --quick-scan TARGET` |
| **Full scan** | `rmap --thorough-scan TARGET` |
| **Check if host is up** | `rmap --only-ping TARGET` |
| **Scan web server** | `rmap --web-scan TARGET` |
| **Check for vulnerabilities** | `rmap --check-vulns TARGET` |
| **Get service versions** | `rmap --grab-banners TARGET` |
| **Identify OS** | `rmap --fingerprint-os TARGET` |
| **Scan all ports** | `rmap --all-ports TARGET` |
| **Fast scan** | `rmap --fast TARGET` |
| **Stealth scan** | `rmap --stealth-scan TARGET` |
| **UDP scan** | `rmap --udp-scan TARGET` |
| **Full audit** | `rmap --security-audit TARGET` |

---

## MIGRATION FROM NMAP

### Direct Flag Compatibility

R-Map supports all common nmap flags for easy migration:
- `-sS`, `-sT`, `-sU`: Scan types
- `-p`, `-F`, `-p-`: Port specification
- `-sV`, `-O`, `-A`: Detection options
- `-T0` through `-T5`: Timing templates
- `-Pn`, `-n`: Discovery options
- `-oN`, `-oX`, `-oG`: Output formats
- `-v`, `-vv`: Verbosity

### Plain English Alternatives

Every nmap flag has a readable R-Map equivalent:
```bash
# nmap command:
nmap -sS -sV -O -p- -T4 -Pn -n example.com

# R-Map equivalent (nmap style):
rmap -sS -sV -O -p- -T4 -Pn -n example.com

# R-Map plain English:
rmap --stealth-scan --service-detect --os-detect --all-ports --timing aggressive --skip-ping --no-dns example.com

# R-Map shorthand:
rmap --thorough-scan --timing aggressive --skip-ping example.com
```

---

**Pro Tip:** Use `--help` with any command to see all options!

```bash
rmap --help
rmap scan --help
rmap discover --help
rmap --scan --help
```
