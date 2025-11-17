# R-Map Quick Reference Card

## Command Translation Guide: nmap → R-Map Plain English

### Scan Types

| nmap | R-Map Plain English | Description |
|------|---------------------|-------------|
| `-sS` | `--stealth-scan` | SYN stealth scan |
| `-sT` | `--tcp-scan` or `--connect-scan` | TCP connect scan |
| `-sU` | `--udp-scan` | UDP scan |
| `-sA` | `--ack-scan` or `--firewall-test` | ACK scan |
| `-sF` | `--fin-scan` | FIN scan |
| `-sN` | `--null-scan` | NULL scan |
| `-sX` | `--xmas-scan` | Xmas scan |
| `-sn` | `--only-ping` or `--discover-hosts` | Host discovery only |

### Detection & Enumeration

| nmap | R-Map Plain English | Description |
|------|---------------------|-------------|
| `-sV` | `--service-detect` or `--grab-banners` | Service version detection |
| `-O` | `--os-detect` or `--fingerprint-os` | OS fingerprinting |
| `-A` | `--aggressive-scan` | Aggressive scan (service + OS + scripts) |

### Port Specification

| nmap | R-Map Plain English | Description |
|------|---------------------|-------------|
| `-p-` | `--all-ports` or `--scan-all-ports` | Scan all 65,535 ports |
| `-F` | `--fast` or `--top-ports` | Top 100 ports only |
| `-p 22,80,443` | `-p 22,80,443` or `--ports 22,80,443` | Specific ports |

### Discovery Options

| nmap | R-Map Plain English | Description |
|------|---------------------|-------------|
| `-Pn` | `--skip-ping` or `--no-ping` | Skip host discovery |
| `-n` | `--no-dns` or `--skip-dns` | No DNS resolution |

### Timing Templates

| nmap | R-Map Plain English | Description |
|------|---------------------|-------------|
| `-T0` | `--timing paranoid` or `--timing-paranoid` | Paranoid (very slow) |
| `-T1` | `--timing sneaky` | Sneaky (slow) |
| `-T2` | `--timing polite` or `--timing-polite` | Polite (slow) |
| `-T3` | `--timing normal` | Normal (default) |
| `-T4` | `--timing aggressive` or `--timing-aggressive` or `--scan-fast` | Aggressive (fast) |
| `-T5` | `--timing insane` | Insane (very fast) |

### Output Formats

| nmap | R-Map Plain English | Description |
|------|---------------------|-------------|
| `-oN file` | `--output normal -f file` | Normal output to file |
| `-oX file` | `--output-xml file` | XML output to file |
| `-oJ file` | `--output-json file` | JSON output to file |
| N/A | `--output-markdown file` | Markdown output to file |
| `-oG file` | `--output grepable -f file` | Grepable output to file |

### Verbosity

| nmap | R-Map Plain English | Description |
|------|---------------------|-------------|
| `-v` | `-v` or `--verbose` or `--scan-verbose` | Verbose output |
| `-vv` | `-vv` | Very verbose output |

---

## Scan Profiles (R-Map Only)

These convenience profiles don't exist in nmap - they're R-Map innovations!

| Profile | Equivalent nmap Command | Use Case |
|---------|------------------------|----------|
| `--quick-scan` | `-F -T4` | Fast reconnaissance |
| `--thorough-scan` | `-p- -sV -O` | Comprehensive audit |
| `--aggressive-scan` | `-A -T4` | Penetration testing |
| `--security-audit` | `-p- -sV -O --script vuln` | Security compliance |
| `--web-scan` | `-p 80,443,8080,... -sV` | Web application testing |
| `--database-scan` | `-p 3306,5432,1433,... -sV` | Database security |

---

## Common Task Cheat Sheet

### Task: Quick scan of a target

**nmap style:**
```bash
nmap -F example.com
```

**R-Map plain English:**
```bash
rmap --quick-scan example.com
```

---

### Task: Find all open ports

**nmap style:**
```bash
nmap -p- example.com
```

**R-Map plain English:**
```bash
rmap --all-ports example.com
```

---

### Task: Identify services and versions

**nmap style:**
```bash
nmap -sV example.com
```

**R-Map plain English:**
```bash
rmap --service-detect example.com
# or
rmap --grab-banners example.com
```

---

### Task: Comprehensive security audit

**nmap style:**
```bash
nmap -sS -sV -O -p- --script vuln example.com
```

**R-Map plain English:**
```bash
rmap --security-audit example.com
```

---

### Task: Stealth scan (avoid detection)

**nmap style:**
```bash
sudo nmap -sS -T0 example.com
```

**R-Map plain English:**
```bash
sudo rmap --stealth-scan --timing-paranoid example.com
```

---

### Task: Just check if hosts are up

**nmap style:**
```bash
nmap -sn 192.168.1.0/24
```

**R-Map plain English:**
```bash
rmap --only-ping 192.168.1.0/24
# or
rmap --discover-hosts 192.168.1.0/24
```

---

### Task: Scan web application

**nmap style:**
```bash
nmap -p 80,443,8080,8443 -sV example.com
```

**R-Map plain English:**
```bash
rmap --web-scan example.com
```

---

### Task: Fast aggressive scan with all detection

**nmap style:**
```bash
nmap -A -T4 example.com
```

**R-Map plain English:**
```bash
rmap --aggressive-scan example.com
# or
rmap -A example.com
```

---

### Task: Save results to JSON

**nmap style:**
```bash
nmap -oX scan.xml example.com
# (then convert XML to JSON manually)
```

**R-Map plain English:**
```bash
rmap --output-json scan.json example.com
```

---

### Task: Scan database server

**nmap style:**
```bash
nmap -p 3306,5432,1433,27017,6379 -sV db.example.com
```

**R-Map plain English:**
```bash
rmap --database-scan db.example.com
```

---

## Mix and Match!

R-Map lets you combine nmap-style and plain English flags:

```bash
# nmap flags + plain English
rmap -sS --all-ports --output-json results.json example.com

# plain English + nmap flags
rmap --stealth-scan -p- --grab-banners -T4 example.com
```

---

## Pro Tips

1. **Use `--help` to see all options:**
   ```bash
   rmap --help
   ```

2. **Start with profiles for common tasks:**
   - Quick recon: `--quick-scan`
   - Full audit: `--security-audit`
   - Web apps: `--web-scan`
   - Databases: `--database-scan`

3. **Plain English is more readable in scripts:**
   ```bash
   # This is clear:
   rmap --web-scan --grab-banners --output-json report.json $TARGET

   # This is cryptic:
   rmap -p 80,443,8080,8443 -sV -oJ report.json $TARGET
   ```

4. **Use nmap flags if you already know them:**
   - All nmap flags still work!
   - No need to relearn if you're an nmap expert

5. **Markdown output is great for documentation:**
   ```bash
   rmap --security-audit --output-markdown audit.md example.com
   ```

---

## Need More Help?

- **Full documentation:** See `steering/CLI_GUIDE.md`
- **Implementation details:** See `PLAIN_ENGLISH_CLI_IMPLEMENTATION.md`
- **Help text:** Run `rmap --help`
- **Examples:** Run `rmap` with no arguments

---

**Remember:** R-Map is designed to be self-documenting. If you forget a flag, just run `rmap --help` or look at the examples!
