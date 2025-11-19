# R-Map Quick Start Guide

**Time to complete:** 5 minutes
**Difficulty:** Beginner

## Table of Contents

- [Installation](#installation)
- [Your First Scan](#your-first-scan)
- [Common Use Cases](#common-use-cases)
- [Output Formats](#output-formats)
- [Cheat Sheet](#cheat-sheet)
- [Next Steps](#next-steps)

---

## Installation

### Option 1: Download Binary (Fastest)

```bash
# Linux (AMD64)
wget https://github.com/Ununp3ntium115/R-map/releases/latest/download/rmap-linux-x86_64.tar.gz
tar -xzf rmap-linux-x86_64.tar.gz
sudo mv rmap /usr/local/bin/
rmap --version
```

### Option 2: Docker (No Installation)

```bash
docker pull ghcr.io/ununp3ntium115/r-map:latest
docker run --rm ghcr.io/ununp3ntium115/r-map:latest --version
```

### Option 3: Build from Source

```bash
# Requires: Rust 1.70+ (install from rustup.rs)
git clone https://github.com/Ununp3ntium115/R-map.git
cd R-map
cargo build --release
./target/release/rmap --version
```

---

## Your First Scan

### 1. Basic Port Scan

Scan common ports on a single host:

```bash
rmap scanme.nmap.org
```

**What happens:**
- Scans top 100 most common ports (default)
- Uses TCP Connect scan (no root required)
- Shows open ports and services

**Expected output:**
```
Starting R-Map v1.0.0 scan at 2025-01-19 14:30:22

Host: scanme.nmap.org (45.33.32.156)
Status: Up
Latency: 12.5ms

PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http

Scan completed: 1 host up, 2 ports open (3.4 seconds)
```

### 2. Scan Specific Ports

```bash
rmap scanme.nmap.org -p 80,443
```

### 3. Service Detection

Identify what's running on open ports:

```bash
rmap scanme.nmap.org -p 22,80,443 -sV
```

**Expected output:**
```
PORT     STATE  SERVICE  VERSION
22/tcp   open   ssh      OpenSSH 8.2p1 Ubuntu
80/tcp   open   http     Apache/2.4.52
443/tcp  open   https    Apache/2.4.52 (mod_ssl)
```

### 4. Save Results to File

```bash
rmap scanme.nmap.org -p 80,443 --format json -o results.json
```

---

## Common Use Cases

### Scanning a Network

**Scan entire subnet:**
```bash
rmap 192.168.1.0/24 --fast
```

**Scan with service detection:**
```bash
rmap 192.168.1.0/24 --fast --service-detection
```

### Security Audit

**Check for vulnerabilities:**
```bash
rmap example.com --security-audit --scripts vuln
```

**OS detection:**
```bash
sudo rmap example.com --os-detect
```

### Stealth Scanning

**SYN stealth scan (requires root):**
```bash
sudo rmap example.com --scan syn -p 1-1000
```

**Firewall evasion:**
```bash
sudo rmap example.com --scan fin -p 80,443
```

### Fast Reconnaissance

**Quick network discovery:**
```bash
rmap 10.0.0.0/24 --fast --skip-ping --no-dns
```

**Top ports only:**
```bash
rmap example.com --fast
```

### Comprehensive Scan

**Full scan with all features:**
```bash
sudo rmap example.com \
  --scan syn \
  -p 1-65535 \
  --service-detection \
  --os-detect \
  --security-audit \
  --format html \
  -o comprehensive-report.html
```

---

## Output Formats

### JSON (Default for automation)

```bash
rmap example.com -p 80,443 --format json -o scan.json
```

**Use with jq:**
```bash
rmap example.com --format json | jq '.results[].ports[] | select(.state=="open")'
```

### XML (nmap-compatible)

```bash
rmap example.com -p 80,443 --format xml -o scan.xml
```

### HTML (Visual reports)

```bash
rmap 192.168.1.0/24 --fast --format html -o network-report.html
# Open in browser
firefox network-report.html
```

### PDF (Executive summary)

```bash
rmap example.com -sV --os-detect --format pdf -o report.pdf
```

### Grepable (CLI parsing)

```bash
rmap 192.168.1.0/24 --format grepable -o results.gnmap

# Parse with grep
grep "Ports:" results.gnmap
grep "open/tcp" results.gnmap | awk '{print $2}'
```

---

## Cheat Sheet

### Target Specification

| Format | Example | Description |
|--------|---------|-------------|
| Single IP | `rmap 192.168.1.1` | Scan one host |
| Hostname | `rmap example.com` | Scan by domain |
| CIDR | `rmap 10.0.0.0/24` | Scan 256 IPs |
| Multiple | `rmap host1 host2 host3` | Scan multiple |
| IPv6 | `rmap 2001:db8::1` | Scan IPv6 |

### Port Specification

| Format | Example | Description |
|--------|---------|-------------|
| Single | `-p 80` | One port |
| Multiple | `-p 80,443` | Comma-separated |
| Range | `-p 1-1000` | Port range |
| Mixed | `-p 22,80,443,8000-9000` | Combined |
| Fast | `--fast` | Top 100 ports |
| All | `--all-ports` | All 65535 ports |

### Scan Types

| Flag | Scan Type | Root? | Use Case |
|------|-----------|-------|----------|
| `--scan connect` | TCP Connect | No | Default, works everywhere |
| `--scan syn` | SYN Stealth | **Yes** | Faster, stealthier |
| `--scan ack` | ACK | **Yes** | Firewall detection |
| `--scan fin` | FIN | **Yes** | Evasion technique |
| `--scan null` | NULL | **Yes** | Evasion technique |
| `--scan xmas` | Xmas | **Yes** | Evasion technique |
| `--scan udp` | UDP | No | UDP services |

### Detection Options

| Flag | Description | Speed | Accuracy |
|------|-------------|-------|----------|
| `-sV` / `--service-detection` | Detect service versions | Slow | High |
| `--os-detect` | OS fingerprinting | Medium | 90%+ |
| `--security-audit` | Vulnerability scanning | Slow | High |
| `--scripts SCRIPT` | Run specific scripts | Varies | Varies |

### Performance Options

| Flag | Default | Range | Impact |
|------|---------|-------|--------|
| `--max-connections` | 100 | 1-1000 | More = faster, higher CPU |
| `--timeout` | 3s | 1-30s | Higher = slower, more complete |
| `--timing` | normal | paranoid → insane | Speed vs stealth tradeoff |

### Output Options

| Flag | Format | Use Case |
|------|--------|----------|
| `--format json` | JSON | APIs, automation |
| `--format xml` | XML | nmap compatibility |
| `--format html` | HTML | Visual reports |
| `--format pdf` | PDF | Management reports |
| `--format grepable` | Grepable | Shell scripting |
| `--format markdown` | Markdown | Documentation |
| `--format csv` | CSV | Spreadsheets |
| `--format sqlite` | SQLite | Historical tracking |

---

## Examples by Scenario

### 1. Web Server Audit

```bash
# Quick check
rmap example.com -p 80,443,8080 -sV

# Comprehensive
rmap example.com -p 80,443,8000-9000 -sV \
  --scripts http-vuln \
  --format html -o web-audit.html
```

### 2. Database Discovery

```bash
# Common database ports
rmap 192.168.1.0/24 -p 3306,5432,1433,27017,6379 -sV
```

### 3. Network Inventory

```bash
# Discover all hosts
rmap 10.0.0.0/16 --fast --skip-ping \
  --format csv -o inventory.csv

# Analyze in Excel
libreoffice inventory.csv
```

### 4. Compliance Scan

```bash
# PCI-DSS relevant ports
rmap 192.168.1.0/24 \
  -p 21,22,23,80,443,3306,3389,5432 \
  -sV --security-audit \
  --format pdf -o compliance-report.pdf
```

### 5. IoT Device Discovery

```bash
# Common IoT ports
rmap 192.168.1.0/24 \
  -p 80,443,554,8080,8443,1883,5683 \
  -sV --os-detect
```

---

## Docker Quick Start

### Basic Scan

```bash
docker run --rm ghcr.io/ununp3ntium115/r-map:latest \
  scanme.nmap.org -p 80,443
```

### With Custom Options

```bash
docker run --rm \
  -v $(pwd)/reports:/reports \
  ghcr.io/ununp3ntium115/r-map:latest \
  example.com -p 1-1000 -sV \
  --format json -o /reports/scan.json
```

### SYN Scan (Requires Capabilities)

```bash
docker run --rm \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  ghcr.io/ununp3ntium115/r-map:latest \
  example.com --scan syn -p 80,443
```

---

## Troubleshooting

### Permission Denied

**Problem:**
```
Error: Permission denied (os error 13)
```

**Solution:**
```bash
# For SYN scans, use sudo
sudo rmap example.com --scan syn -p 80

# Or use TCP Connect (no root needed)
rmap example.com --scan connect -p 80
```

### Target Blocked

**Problem:**
```
Error: Target blocked by SSRF protection
```

**Solution:**
This is intentional security. Private IPs and cloud metadata endpoints are blocked. Use nmap for these targets.

### Connection Timeout

**Problem:**
```
Error: Connection timed out
```

**Solution:**
```bash
# Increase timeout
rmap example.com --timeout 10

# Or check network connectivity
ping example.com
```

### Too Slow

**Problem:** Scan taking forever

**Solution:**
```bash
# Use faster timing
rmap example.com --timing aggressive

# Increase concurrency
rmap example.com --max-connections 500

# Use fast mode (top 100 ports)
rmap example.com --fast
```

---

## Next Steps

### Learn More

- **Full CLI Reference:** [steering/CLI_GUIDE.md](../steering/CLI_GUIDE.md)
- **Performance Tuning:** [steering/PERFORMANCE.md](../steering/PERFORMANCE.md)
- **Troubleshooting:** [steering/TROUBLESHOOTING.md](../steering/TROUBLESHOOTING.md)
- **API Usage:** [docs/API_GUIDE.md](API_GUIDE.md)
- **Deployment:** [docs/DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)

### Try Advanced Features

```bash
# API server
rmap-api --port 8080

# Kubernetes deployment
helm install rmap rmap/rmap

# Real-time monitoring
docker-compose up -d
# Access Grafana at http://localhost:3000
```

### Community

- **GitHub:** https://github.com/Ununp3ntium115/R-map
- **Issues:** https://github.com/Ununp3ntium115/R-map/issues
- **Discussions:** https://github.com/Ununp3ntium115/R-map/discussions

---

## Quick Reference Card

**Most Common Commands:**

```bash
# Basic scan
rmap example.com

# Specific ports
rmap example.com -p 80,443

# Service detection
rmap example.com -p 80,443 -sV

# Network scan
rmap 192.168.1.0/24 --fast

# Save results
rmap example.com -p 80,443 --format json -o scan.json

# Stealth scan (requires root)
sudo rmap example.com --scan syn -p 1-1000

# Security audit
rmap example.com --security-audit

# Get help
rmap --help
```

---

**Happy scanning!** 🚀

For more examples and advanced usage, see the [full documentation](../README.md).
