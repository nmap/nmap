# R-Map CLI Design: Better than nmap's cryptic flags

## Philosophy

**nmap's problem**: Cryptic single-letter flags that are hard to remember
- `-sS` = SYN scan (what does 'sS' mean?)
- `-Pn` = Skip ping (why 'Pn'?)
- `-nV` = No reverse DNS + version detection (confusing!)

**R-Map's solution**: Clear, descriptive long-form flags with intuitive short forms
- `--scan syn` or `-s syn` = SYN scan
- `--skip-ping` or `-P` = Skip host discovery
- `--no-dns --version` = Explicit separate flags

---

## Current Implementation Status

### ✅ Currently Implemented (v0.1.0)

| Feature | nmap | R-Map Current | Status |
|---------|------|---------------|--------|
| **Target specification** | `scanme.nmap.org` | `scanme.nmap.org` | ✅ Same |
| **Port specification** | `-p 22,80,443` | `-p 22,80,443` or `--ports 22,80,443` | ✅ Better |
| **Output format** | `-oX file.xml` | `--output xml --file file.xml` | ✅ Clearer |
| **Verbosity** | `-v` | `-v` or `--verbose` | ✅ Same |
| **Service detection** | `-A` | `-A` or `--aggressive` | ✅ Same |
| **Timeout** | `--host-timeout 3s` | `-t 3` or `--timeout 3` | ✅ Simpler |

### ❌ Missing Critical Features

| Feature | nmap Flag | Proposed R-Map | Priority |
|---------|-----------|----------------|----------|
| **Scan Types** |
| TCP SYN scan | `-sS` | `--scan syn` or `-s syn` | 🔴 HIGH |
| TCP connect | `-sT` | `--scan connect` or `-s connect` | ✅ DEFAULT |
| UDP scan | `-sU` | `--scan udp` or `-s udp` | 🔴 HIGH |
| Ping scan | `-sn` | `--scan ping` or `--ping-only` | 🟡 MEDIUM |
| **Host Discovery** |
| Skip ping | `-Pn` | `--skip-ping` or `-P` | 🔴 HIGH |
| ICMP ping | `-PE` | `--ping icmp` | 🟡 MEDIUM |
| TCP SYN ping | `-PS80,443` | `--ping-ports 80,443` | 🟡 MEDIUM |
| **DNS Options** |
| Never resolve | `-n` | `--no-dns` or `-n` | 🔴 HIGH |
| Always resolve | `-R` | `--dns` or `-R` | 🟡 MEDIUM |
| **Port Ranges** |
| Fast scan (100 ports) | `-F` | `--fast` or `-F` | 🟡 MEDIUM |
| All ports | `-p-` | `--all-ports` or `-p 1-65535` | 🟡 MEDIUM |
| Top ports | `--top-ports 1000` | `--top-ports 1000` | 🟡 MEDIUM |
| **Timing** |
| Timing template | `-T0` to `-T5` | `--timing 0` to `--timing 5` or `-T0` to `-T5` | 🟡 MEDIUM |
| **OS Detection** |
| OS detection | `-O` | `--os-detect` or `-O` | 🟢 LOW (not impl) |
| **Script Scanning** |
| Run script | `--script vuln` | `--script vuln` | 🟢 LOW (not impl) |
| **Output** |
| Normal output | `-oN file` | `--output normal --file file` | ✅ DONE |
| XML output | `-oX file` | `--output xml --file file` | ✅ DONE |
| Grepable | `-oG file` | `--output grepable --file file` | ✅ DONE |
| JSON | N/A | `--output json --file file` | ✅ BETTER |
| **Performance** |
| Max parallelism | `--max-parallelism 100` | `--max-parallel 100` | 🟡 MEDIUM |
| Min rate | `--min-rate 100` | `--min-rate 100` | 🟡 MEDIUM |
| Max rate | `--max-rate 1000` | `--max-rate 1000` | 🟡 MEDIUM |
| **Misc** |
| IPv6 | `-6` | `--ipv6` or `-6` | 🟢 LOW |
| Randomize hosts | `--randomize-hosts` | `--randomize` | 🟢 LOW |
| Interface | `-e eth0` | `--interface eth0` or `-i eth0` | 🟡 MEDIUM |

---

## Proposed Complete CLI Design

### Command Structure

```bash
rmap [OPTIONS] <TARGETS>...

# Better than nmap:
rmap --scan syn --ports 1-1000 --output json 192.168.1.0/24

# vs nmap:
nmap -sS -p1-1000 -oX - 192.168.1.0/24 | some-json-converter
```

### Scan Type Options (Better than -sS, -sT, -sU)

```bash
-s, --scan <TYPE>           Scan type
                            [possible values: connect, syn, udp, ping]
                            [default: connect]

# Examples:
rmap --scan syn 192.168.1.1              # Clear!
rmap -s connect scanme.nmap.org          # Short form
rmap --scan udp -p 53,161 192.168.1.0/24 # UDP scan
```

**vs nmap's confusing:**
```bash
nmap -sS  # What does sS mean? SYN?
nmap -sT  # TCP? But SYN is also TCP!
nmap -sU  # U for UDP, ok...
```

### Port Specification (Same as nmap, works well)

```bash
-p, --ports <PORTS>         Port specification
                            [default: 22,80,443,8080]

# Examples:
rmap -p 80                   # Single port
rmap -p 22,80,443            # List
rmap -p 1-1000               # Range
rmap -p 22,80,1000-2000      # Mixed
rmap --all-ports             # 1-65535
rmap --fast                  # Top 100 ports
rmap --top-ports 1000        # Top 1000 ports
```

### Host Discovery (Better than -Pn, -PS, -PE)

```bash
-P, --skip-ping             Skip host discovery (treat all as online)
    --ping-only             Only do host discovery, no port scan
    --ping-type <TYPE>      Host discovery method
                            [possible values: tcp, icmp, arp, none]
    --ping-ports <PORTS>    Ports to use for TCP ping [default: 80,443]

# Examples:
rmap --skip-ping 192.168.1.1              # Clear!
rmap -P 192.168.1.0/24                    # Short form
rmap --ping-only 192.168.1.0/24           # Only check if hosts are up
rmap --ping-type icmp 192.168.1.0/24      # Use ICMP echo
rmap --ping-ports 22,80,443 192.168.1.1   # Custom ping ports
```

**vs nmap's cryptic:**
```bash
nmap -Pn  # Skip ping... but why 'Pn'?
nmap -PS80,443  # TCP SYN ping... PS means what?
nmap -PE  # ICMP echo... PE?
```

### DNS Resolution (Better than -n, -R)

```bash
-n, --no-dns                Never do reverse DNS resolution
-R, --dns                   Always do reverse DNS (even for IPs)
    --dns-servers <IPS>     Custom DNS servers

# Examples:
rmap --no-dns 192.168.1.1         # Clear!
rmap -n 192.168.1.0/24            # Short form
rmap --dns 8.8.8.8                # Resolve IPs to hostnames
```

### Service & Version Detection (Better than -sV, -A)

```bash
-A, --aggressive            Enable aggressive scan (service + version + OS)
-S, --service-detect        Probe open ports for service info
-V, --version-detect        Determine service versions
    --version-intensity <N> Version detection intensity [0-9]

# Examples:
rmap -A scanme.nmap.org              # Aggressive (all detection)
rmap --service-detect 192.168.1.1    # Just service names
rmap --version-detect 192.168.1.1    # Service + versions
```

### OS Detection (Better than -O)

```bash
-O, --os-detect             Enable OS detection
    --os-scan-limit         Only OS detect hosts with open port
    --fuzzy-os              Guess OS even with limited info

# Examples:
rmap --os-detect scanme.nmap.org
rmap -O 192.168.1.1
```

### Timing & Performance (Better than -T0 through -T5)

```bash
-T, --timing <LEVEL>        Timing template [0-5]
                            0=paranoid, 1=sneaky, 2=polite,
                            3=normal, 4=aggressive, 5=insane
                            [default: 3]
-t, --timeout <SECS>        Connection timeout [default: 3]
    --max-parallel <N>      Max parallel scans
    --min-rate <N>          Minimum packets per second
    --max-rate <N>          Maximum packets per second
    --scan-delay <MS>       Delay between probes

# Examples:
rmap -T4 192.168.1.0/24              # Fast scan
rmap --timing 0 scanme.nmap.org      # Stealth scan
rmap --max-parallel 100 192.168.1.0/24
rmap --min-rate 100 --max-rate 1000 192.168.1.1
```

### Output Options (Better than -oN, -oX, -oG)

```bash
-o, --output <FORMAT>       Output format
                            [possible values: normal, json, xml, grepable]
                            [default: normal]
-f, --file <PATH>           Save output to file
    --append                Append to file instead of overwrite
    --no-color              Disable colored output

# Examples:
rmap --output json --file results.json 192.168.1.1
rmap -o xml -f scan.xml scanme.nmap.org
rmap --output grepable 192.168.1.0/24 | grep 'open'
```

**vs nmap's confusing:**
```bash
nmap -oN normal.txt   # 'N' for normal
nmap -oX xml.xml      # 'X' for XML
nmap -oG grep.txt     # 'G' for grepable
nmap -oA basename     # 'A' for all formats... wait, -A is also aggressive scan!
```

### Verbosity & Debugging (Same as nmap)

```bash
-v, --verbose               Increase verbosity (can be used multiple times)
-d, --debug                 Enable debug output
-q, --quiet                 Quiet mode (minimal output)
    --packet-trace          Show all packets sent/received

# Examples:
rmap -v scanme.nmap.org      # Basic verbosity
rmap -vv 192.168.1.1         # More verbose
rmap -vvv 192.168.1.1        # Maximum verbosity
rmap --quiet 192.168.1.0/24  # Minimal output
```

### Misc Options

```bash
-6, --ipv6                  Enable IPv6 scanning
-i, --interface <NAME>      Use specific network interface
    --randomize             Randomize target order
    --exclude <HOSTS>       Exclude hosts/networks
    --exclude-file <FILE>   Exclude hosts from file
    --resume <FILE>         Resume aborted scan
    --max-retries <N>       Maximum probe retries

# Examples:
rmap --interface eth0 192.168.1.0/24
rmap --randomize 192.168.1.0/24
rmap --exclude 192.168.1.1,192.168.1.5 192.168.1.0/24
```

---

## Comparison: R-Map vs nmap

### Example 1: Fast SYN scan with service detection

**nmap (cryptic):**
```bash
sudo nmap -sS -T4 -sV -p- -oX results.xml 192.168.1.0/24
# What does this mean? You need to memorize flags!
```

**rmap (clear):**
```bash
sudo rmap --scan syn --timing 4 --version-detect --all-ports \
          --output xml --file results.xml 192.168.1.0/24
# Crystal clear what each option does!
```

### Example 2: Stealth scan without DNS

**nmap:**
```bash
sudo nmap -sS -T0 -Pn -n -p 22,80,443 target.com
# -Pn? -n? What do these mean?
```

**rmap:**
```bash
sudo rmap --scan syn --timing 0 --skip-ping --no-dns \
          --ports 22,80,443 target.com
# Self-documenting!
```

### Example 3: UDP scan with custom timing

**nmap:**
```bash
sudo nmap -sU -T4 --max-retries 1 --min-rate 1000 -p 53,161,162 192.168.1.1
```

**rmap:**
```bash
sudo rmap --scan udp --timing 4 --max-retries 1 --min-rate 1000 \
          --ports 53,161,162 192.168.1.1
# Same clarity!
```

---

## What Makes R-Map Better?

### 1. **Descriptive Long Forms**
- `--skip-ping` instead of `-Pn`
- `--no-dns` instead of `-n`
- `--scan syn` instead of `-sS`

### 2. **Logical Grouping**
- All scan types under `--scan <TYPE>`
- All output under `--output <FORMAT> --file <PATH>`
- All timing under `--timing <LEVEL>` + specific options

### 3. **Consistent Patterns**
- Boolean flags: `--skip-ping`, `--no-dns`, `--ipv6`
- Value flags: `--scan <TYPE>`, `--output <FORMAT>`, `--timing <N>`
- No confusing overloading (nmap's `-A` vs `-oA`)

### 4. **Self-Documenting**
```bash
rmap --help  # Shows clear descriptions
rmap --scan  # Lists available scan types
```

### 5. **JSON Output (nmap doesn't have this!)**
```bash
rmap --output json --file results.json target.com
# Native JSON support, no XML conversion needed!
```

---

## Implementation Priority

### Phase 1: Critical Flags (Release v0.2.0)
- [ ] `--scan <TYPE>` (syn, connect, udp)
- [ ] `--skip-ping` / `-P`
- [ ] `--no-dns` / `-n`
- [ ] `--fast` / `-F`
- [ ] `--all-ports`
- [ ] `--timing <N>` improvements

### Phase 2: Important Flags (Release v0.3.0)
- [ ] `--service-detect` / `-S`
- [ ] `--version-detect` / `-V`
- [ ] `--ping-type <TYPE>`
- [ ] `--max-parallel <N>`
- [ ] `--min-rate` / `--max-rate`

### Phase 3: Advanced Flags (Release v0.4.0)
- [ ] `--os-detect` / `-O`
- [ ] `--script <NAME>`
- [ ] `--interface <NAME>`
- [ ] `--randomize`
- [ ] `--exclude <HOSTS>`

---

## Backward Compatibility with nmap

We can support nmap's flags as aliases:

```bash
# nmap compatibility mode
rmap -sS -p- -T4 192.168.1.1

# Translates internally to:
rmap --scan syn --all-ports --timing 4 192.168.1.1
```

This way, nmap users can switch easily, but newcomers get the better syntax!

---

## Conclusion

**R-Map's CLI Design Advantages:**

✅ **More intuitive** - No need to memorize cryptic flags
✅ **Self-documenting** - Flags describe what they do
✅ **Consistent** - Logical patterns throughout
✅ **Modern** - Native JSON support, better defaults
✅ **Backward compatible** - Can support nmap flags as aliases

**The result:** A network scanner that's just as powerful as nmap, but way easier to use!
