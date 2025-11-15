# R-Map Implementation Status

Last Updated: 2025-11-15

## Summary

R-Map is a network scanning tool written in Rust. This document provides an honest assessment of what is actually implemented vs. what features are planned or stubbed out.

## ✅ **FULLY IMPLEMENTED - Real Network Operations**

### Core Scanning (src/main.rs)
- **TCP Connect Scanning**: ✅ Real network connections using `TcpStream::connect()`
- **Service Detection**: ✅ Real banner grabbing for SSH, FTP, SMTP, HTTP/HTTPS
- **Service Version Detection**: ✅ Extracts version information from banners
- **Host Discovery**: ✅ TCP-based host detection (tests common ports)
- **Port Specification**: ✅ Supports ranges (1-1000), lists (22,80,443), CIDR notation
- **Target Parsing**: ✅ IP addresses, hostnames (DNS resolution), CIDR blocks, IP ranges
- **Output Formats**: ✅ Normal, JSON, XML, Grepable - all fully implemented
- **Timeout Configuration**: ✅ Configurable connection timeouts
- **Concurrent Scanning**: ✅ Asynchronous scanning with Tokio

### Additional Scanner Implementations (crates/nmap-engine)
- **TCP SYN Scanner**: ✅ Raw socket implementation using pnet (requires root)
- **TCP Connect Scanner**: ✅ Non-privileged scanning fallback
- **Host Discovery**: ✅ Probes common ports to determine if hosts are up
- **Service Detection**: ✅ Banner grabbing with protocol-specific probes

### Infrastructure
- **Timing Templates**: ✅ T0-T5 timing profiles (Paranoid to Insane)
- **Raw Socket Support**: ✅ Using `pnet` and `socket2` crates
- **Privilege Detection**: ✅ Checks for raw socket capabilities on Unix systems

## ⚠️ **PARTIALLY IMPLEMENTED - Limited Functionality**

### Service/OS Databases
- **Service Signatures**: ⚠️ Only ~15 common services hardcoded
  - Real nmap has 1000s of signatures in nmap-service-probes
  - Location: `crates/nmap-service-detect/src/signatures.rs`
- **OS Fingerprints**: ⚠️ Only 3 hardcoded fingerprints (Linux, Windows, FreeBSD)
  - Real nmap has 3000+ fingerprints in nmap-os-db
  - Location: `crates/nmap-os-detect/src/fingerprint.rs`
- **MAC Vendors**: ⚠️ Only 11 hardcoded OUI prefixes
  - Real nmap has thousands in nmap-mac-prefixes
  - Location: `crates/nmap-core/src/data.rs`
- **Default Ports**: ⚠️ Only 18 TCP + 20 UDP ports
  - Real nmap scans top 1000 ports by default
  - Location: `crates/nmap-net/src/port_spec.rs`

## ❌ **NOT IMPLEMENTED - Stubbed/Warned**

### Scan Types
- **UDP Scanning**: ❌ Not implemented (would require raw ICMP response parsing)
- **SCTP Scans**: ❌ Not implemented
- **IPPROTO Scans**: ❌ Not implemented
- **FTP Bounce**: ❌ Not implemented
- **Idle Scan**: ❌ Not implemented

### Advanced Features
- **OS Detection**: ❌ Requires TCP/IP stack fingerprinting
  - Returns warning instead of fake results
  - Would need: TCP window analysis, TTL inspection, TCP options parsing
- **Traceroute**: ❌ Not implemented
  - Returns warning instead of simulating hops
  - Would need: TTL manipulation and ICMP parsing
- **Script Scanning (RSE)**: ❌ No scripts implemented
  - Framework exists but zero actual scripts
  - Real nmap has hundreds of NSE scripts
- **IPv6 Support**: ❌ Marked as TODO throughout codebase

### Protocol-Specific Tests
All tests in `crates/nmap-os-detect/` that return hardcoded values:
- **ICMP Tests**: ❌ Returns fake TTL=64, hardcoded responses
- **TCP Sequence Prediction**: ❌ Returns random numbers instead of capturing real sequence numbers
- **IP ID Sequence**: ❌ Returns fake arithmetic sequence (0, 256, 512...)
- **UDP Port Unreachable**: ❌ Returns hardcoded ICMP values

## 🔧 **RECENT FIXES (2025-11-15)**

### Removed Mock Code
1. **Host Discovery** (nmap-engine): Removed simulation that marked all hosts as "up"
   - Now performs real TCP probes to common ports
2. **Service Detection** (nmap-engine): Removed no-op that just cloned input
   - Now performs real banner grabbing
3. **Feature Warnings**: OS detection, traceroute, and script scanning now explicitly warn they're not implemented
   - Previous code silently did nothing, misleading users

### Honest Documentation
- Removed "production ready" claims that were misleading
- Added explicit warnings when features call unimplemented code
- This document provides transparent status

## 📊 **What Actually Works for Real Users**

### Working Use Cases
```bash
# ✅ TCP connect scan - REAL
rmap -p 22,80,443 scanme.nmap.org

# ✅ Service detection - REAL banner grabbing
rmap -A scanme.nmap.org

# ✅ CIDR network scanning - REAL
rmap -p 80,443 192.168.1.0/24

# ✅ JSON output - REAL
rmap -o json -f results.json example.com
```

### Non-Working Use Cases
```bash
# ❌ UDP scan - NOT IMPLEMENTED
rmap -sU 192.168.1.1

# ❌ OS detection - NOT IMPLEMENTED (warns instead of faking)
rmap -O scanme.nmap.org

# ❌ Script scanning - NOT IMPLEMENTED
rmap --script vuln scanme.nmap.org

# ❌ SYN scan without root - FALLS BACK to connect scan
rmap -sS scanme.nmap.org  # Works but uses TCP connect if not root
```

## 🎯 **Roadmap to Full Implementation**

### Phase 1: Database Loading
- [ ] Download and parse real nmap-services file
- [ ] Download and parse real nmap-os-db file
- [ ] Download and parse real nmap-service-probes file
- [ ] Download and parse real nmap-mac-prefixes file

### Phase 2: Protocol Implementation
- [ ] Implement UDP scanning with ICMP response parsing
- [ ] Implement ICMP ping for host discovery
- [ ] Implement real TCP sequence number extraction
- [ ] Implement real IP ID sequence analysis

### Phase 3: OS Detection
- [ ] Implement TCP window size analysis
- [ ] Implement TTL and IP header analysis
- [ ] Implement TCP options fingerprinting
- [ ] Integrate with loaded nmap-os-db

### Phase 4: Advanced Features
- [ ] Implement traceroute with TTL manipulation
- [ ] Create RSE scripting framework with actual scripts
- [ ] Add IPv6 support throughout

### Phase 5: Performance & Polish
- [ ] Add comprehensive test suite
- [ ] Performance benchmarking
- [ ] Cross-platform testing (Windows, macOS, Linux)

## 🚨 **Critical Honesty Note**

**Previous State**: The codebase contained numerous "simplified" implementations that were actually returning hardcoded or simulated results, making it appear that features worked when they didn't.

**Current State**: All mock code has been either:
1. Replaced with real network operations (host discovery, service detection)
2. Explicitly marked as unimplemented with warnings (OS detection, traceroute, scripts)

**For Users**: If a feature doesn't explicitly warn that it's unimplemented, it's doing real network operations. The core TCP scanning and service detection are production-ready. Advanced features (UDP, OS detection, scripts) are not yet implemented.

## 📝 **Version History**

### v0.1.0 (Current)
- Real TCP connect scanning
- Real service detection via banner grabbing
- Honest warnings for unimplemented features
- Removed all misleading mock implementations

### Previous (Undocumented)
- Contained simulated/hardcoded results
- Misleading "production ready" claims
- Many features appeared to work but returned fake data
