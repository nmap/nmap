# R-Map v0.1.0-alpha - Windows Release

**Release Date:** 2025-11-19
**Status:** Alpha Pre-Release (Unsigned)
**Platform:** Windows x64
**Download:** [rmap-windows-dist/](rmap-windows-dist/)

---

## 🎉 First Alpha Release!

This is the **first alpha pre-release** of R-Map for Windows! This release provides a fully functional TCP network scanner with service detection, multiple output formats, and comprehensive testing.

### ⚠️ Alpha Release Notice

This is an **ALPHA** pre-release for early testing and feedback:
- ✅ All core features tested and verified
- ✅ 28 real-world tests passed (100% success rate)
- ✅ Production hosts validated
- ⚠️ Executable is **unsigned** (will be signed in v0.1.0 final release)
- ⚠️ For testing and evaluation only
- ⚠️ Not recommended for production use

---

## 📦 What's Included

### Executable
- **rmap.exe** (1.5 MB) - Windows x64 PE32+ executable
- No dependencies required
- No administrator rights needed
- Statically linked - runs standalone

### Documentation
- **README.txt** (6.5 KB) - Complete usage guide
- **MANIFEST.txt** (5.2 KB) - Package inventory and checksums
- **SIGNING_INSTRUCTIONS.txt** (1.3 KB) - PGP signing reference
- **PGP_SIGNING_GUIDE.txt** (9.4 KB) - Comprehensive signing guide

### Testing & Verification
- **quick_audit.bat** (11 KB) - 10 automated tests
- **ua_test_suite.bat** (7.4 KB) - 15 comprehensive tests
- **rmap.exe.sha256** (75 B) - SHA256 checksum
- **verify_signature.bat** (3.5 KB) - Verification script (for future signed releases)

### PGP Signing Infrastructure
- **PyroDIFR (PyroDIFR)_0xACAFF196_public.asc** (3.2 KB) - Public key
- **sign_executable.bat** (3.3 KB) - Automated signing script

---

## ✅ Features

### Core Scanning Capabilities
- ✅ **TCP Connect Scanning** - Full TCP connection-based port scanning
- ✅ **Service Detection** - Banner grabbing with version information
- ✅ **Multi-Target Scanning** - Scan multiple hosts concurrently
- ✅ **DNS Resolution** - Automatic hostname resolution
- ✅ **Port Ranges** - Support for custom port ranges (1-65535)

### Output Formats
- ✅ **JSON** - Machine-readable API-friendly format
- ✅ **XML** - nmap-compatible XML output
- ✅ **Grepable** - Easy parsing for shell scripts
- ✅ **Human-Readable** - Clear console output

### Security Features
- ✅ **Memory Safe** - Written in 100% Rust
- ✅ **Input Validation** - Comprehensive target validation
- ✅ **SSRF Protection** - Cloud metadata endpoint blocking
- ✅ **Resource Limits** - Prevents resource exhaustion

---

## 🚀 Quick Start

### Basic Usage

```bash
# Quick scan
rmap.exe scanme.nmap.org

# Specific ports
rmap.exe example.com -p 22,80,443

# Service detection
rmap.exe scanme.nmap.org -p 22,80,443 -A

# JSON output
rmap.exe 8.8.8.8 -p 80,443 -o json
```

### Verification

#### SHA256 Checksum
```powershell
Get-FileHash rmap.exe -Algorithm SHA256
```
**Expected:** `41ba46bce983f7490eacab4518441cf0f80f846499a2b01019be6ae2c574b889`

#### Automated Testing
```batch
quick_audit.bat
```

---

## 📊 Test Results

### Comprehensive Testing Complete

**Total Tests:** 28
**Success Rate:** 100% (28/28 passed)
**Test Coverage:**
- ✅ Version & help output
- ✅ Single target scans
- ✅ Multi-target scans
- ✅ Service detection
- ✅ All output formats (JSON, XML, Grepable)
- ✅ Port ranges
- ✅ DNS resolution
- ✅ File output

### Production Hosts Validated

| Target | IP | Ports Found | Version Info |
|--------|-----|-------------|--------------|
| **scanme.nmap.org** | 45.33.32.156 | 22, 80, 443 | OpenSSH 6.6.1p1, Apache 2.4.7 |
| **github.com** | 140.82.114.4 | 22, 80, 443 | Detected |
| **Google DNS** | 8.8.8.8 | 80, 443 | Open |
| **Cloudflare DNS** | 1.1.1.1 | 80, 443 | Open |

### Sample Service Detection Output

```
Target: scanme.nmap.org (45.33.32.156)
Duration: 0.30 seconds

PORT     STATE   SERVICE   VERSION
22/tcp   open    ssh       OpenSSH_6.6.1p1 Ubuntu 2ubuntu2.13
80/tcp   open    http      Apache/2.4.7 (Ubuntu)
443/tcp  open    https
```

---

## ⚡ Performance Benchmarks

| Test | Result |
|------|--------|
| **Single port** | 0.07-0.16s |
| **Multi-port (3 ports)** | 0.30s |
| **Service detection** | 0.11-0.30s |
| **Google DNS scan** | 0.85s |
| **Multi-target (3 hosts)** | 3.36s |

**Grade:** ✅ **EXCELLENT**

---

## 🔐 Security & Integrity

### Executable Information
- **Format:** Windows PE32+ executable
- **Architecture:** x86-64
- **Compiler:** rustc 1.89.0 (29483883e 2025-08-04)
- **Memory Safety:** ✅ Rust guarantees
- **Dependencies:** Statically linked (no external DLLs)

### SHA256 Checksum
```
41ba46bce983f7490eacab4518441cf0f80f846499a2b01019be6ae2c574b889
```

**Verify with PowerShell:**
```powershell
Get-FileHash rmap.exe -Algorithm SHA256
```

**Verify with Command Prompt:**
```cmd
certutil -hashfile rmap.exe SHA256
```

### PGP Signing (Coming in Final Release)

This alpha release is **unsigned**. The final v0.1.0 release will be signed with PGP key `0xACAFF196`.

**Public Key Information:**
- Owner: PyroDIFR (PyroDIFR) <PyroDIFR@proton.me>
- Key ID: 0xACAFF196
- Algorithm: RSA 4096-bit
- Fingerprint: 0393969181188112779FB863C287B0F5ACAFF196

The package includes signing infrastructure ready for the final release:
- Public key file included
- Automated signing/verification scripts ready
- Comprehensive signing guide provided

---

## 📋 Known Limitations

### Current Version (v0.1.0-alpha)
- ⚠️ **No SYN stealth scan** - Requires Npcap SDK (planned for v0.2.0)
- ⚠️ **No UDP scanning** - Requires Npcap SDK (planned for v0.2.0)
- ⚠️ **No OS fingerprinting** - Requires Npcap SDK (planned for v0.2.0)
- ⚠️ **TCP Connect only** - Full connection-based scanning

### Not Included
- **SYN stealth scanning** - Coming in v0.2.0
- **Advanced TCP scans** - ACK/FIN/NULL/Xmas (coming in v0.2.0)
- **UDP protocol scanning** - Coming in v0.2.0
- **OS detection** - Coming in v0.2.0
- **NSE-style scripts** - Planned for v0.3.0

See [v0.2.0 development branch](https://github.com/Ununp3ntium115/R-map) for advanced features.

---

## 🎓 Usage Examples

### Example 1: Quick Network Scan
```bash
rmap.exe 192.168.1.1 -p 80,443,3306,5432
```

**Use Case:** Check if common services are running on a server

### Example 2: Service Version Detection
```bash
rmap.exe scanme.nmap.org -p 22,80,443 -A
```

**Output:**
```
22/tcp   open  ssh     OpenSSH_6.6.1p1 Ubuntu 2ubuntu2.13
80/tcp   open  http    Apache/2.4.7 (Ubuntu)
443/tcp  open  https
```

### Example 3: Export to JSON for Automation
```bash
rmap.exe 8.8.8.8 -p 80,443 -o scan_results.json
```

**Output File:** `scan_results.json`
```json
{
  "hosts": [{
    "target": "8.8.8.8",
    "ports": [
      {"port": 80, "state": "open", "service": "http"},
      {"port": 443, "state": "open", "service": "https"}
    ]
  }]
}
```

### Example 4: Multi-Target Scanning
```bash
rmap.exe scanme.nmap.org github.com 8.8.8.8 -p 22,80,443 -o xml
```

**Use Case:** Scan multiple hosts in one command

---

## 🐛 Known Issues

### Alpha Release Issues

1. **No Package Signature** - Executable is unsigned in this alpha release
   - **Workaround:** Verify SHA256 hash manually
   - **Fix:** Will be signed in v0.1.0 final release

2. **Windows Defender May Flag** - Some antivirus may flag unsigned network tools
   - **Workaround:** Add exception after verifying SHA256
   - **Fix:** Official signature coming in final release

3. **No Raw Socket Support** - Requires Npcap for advanced scans
   - **Workaround:** Use TCP Connect scanning (default)
   - **Fix:** v0.2.0 will include Npcap SDK integration

### Reporting Issues

Found a bug? Please report it!
- **GitHub Issues:** https://github.com/Ununp3ntium115/R-map/issues
- **Include:** rmap.exe version, command used, error message
- **Security Issues:** Email security@r-map.io (do not open public issue)

---

## 📞 Support & Resources

### Documentation
- **README.txt** - Complete usage guide in the package
- **GitHub README** - https://github.com/Ununp3ntium115/R-map
- **Test Suite** - Run `quick_audit.bat` to validate installation

### Community
- **Issues:** https://github.com/Ununp3ntium115/R-map/issues
- **Discussions:** https://github.com/Ununp3ntium115/R-map/discussions
- **Releases:** https://github.com/Ununp3ntium115/R-map/releases

### Additional Documentation
- REAL_WORLD_UA_TEST_RESULTS.md
- AUTOMATED_AUDIT_COMPLETE.md
- UA_FINAL_SUMMARY.md
- PGP_SIGNING_GUIDE.txt

---

## 🔄 Upgrade Path

### From Alpha to Final Release

When v0.1.0 final is released:

1. **Download** new signed release
2. **Verify** PGP signature:
   ```batch
   verify_signature.bat
   ```
3. **Replace** rmap.exe with signed version
4. **Test** with quick_audit.bat

### Migration to v0.2.0

Version 0.2.0 will include:
- ✅ SYN stealth scanning (requires Npcap)
- ✅ UDP protocol scanning
- ✅ Advanced TCP scan types
- ✅ OS fingerprinting

**No breaking changes** - v0.1.0 commands will work in v0.2.0

---

## 📜 License

R-Map is dual-licensed under:
- **MIT License** - http://opensource.org/licenses/MIT
- **Apache License 2.0** - http://www.apache.org/licenses/LICENSE-2.0

You may choose either license for your use.

---

## 🙏 Acknowledgments

- **nmap Project** - Inspiration and reference
- **Rust Community** - Amazing tools and libraries
- **Early Testers** - Thank you for testing this alpha release!

---

## 📝 Changelog

### v0.1.0-alpha (2025-11-19)

#### Added
- ✅ TCP Connect scanning
- ✅ Service detection with banner grabbing
- ✅ JSON, XML, Grepable output formats
- ✅ Multi-target concurrent scanning
- ✅ DNS resolution
- ✅ Port range support (1-65535)
- ✅ SSRF protection (cloud metadata blocking)
- ✅ Input validation
- ✅ Automated test suites (28 tests)
- ✅ PGP signing infrastructure (ready for final release)
- ✅ Complete documentation package

#### Tested
- ✅ 28 comprehensive tests (100% success)
- ✅ 4 production hosts validated
- ✅ Service detection verified (OpenSSH, Apache)
- ✅ All output formats validated
- ✅ Performance benchmarked

#### Known Limitations
- ⚠️ No SYN/UDP scanning (requires v0.2.0 + Npcap)
- ⚠️ No OS fingerprinting (coming in v0.2.0)
- ⚠️ Unsigned executable (will sign for final release)

---

## 🎯 Next Steps

### For Users

1. **Download** the package: `rmap-windows-dist.zip`
2. **Extract** all files to a directory
3. **Verify** the SHA256 checksum matches
4. **Run** quick_audit.bat to validate functionality
5. **Test** with `rmap.exe --help`
6. **Provide Feedback** via GitHub Issues

### For Developers

1. **Review** the source code on GitHub
2. **Report Issues** you encounter
3. **Suggest Features** for v0.2.0
4. **Contribute** via Pull Requests

---

## 🚦 Release Schedule

- **v0.1.0-alpha** - 2025-11-19 (THIS RELEASE - Unsigned)
- **v0.1.0** - TBD (Signed final release)
- **v0.2.0** - Q1 2025 (Npcap integration, SYN/UDP scanning)
- **v0.3.0** - Q2 2025 (Security scripts, firewall evasion)
- **v1.0.0** - Q2 2025 (Production release, external audit)

---

## ⚖️ Disclaimer

**IMPORTANT:** This software is intended for authorized security testing only.

- ✅ Use only on networks you own or have explicit permission to test
- ❌ Do not scan networks without authorization
- ❌ Do not use for malicious purposes
- ❌ Unauthorized scanning may be illegal in your jurisdiction

The developers assume no liability for misuse of this software.

---

## 📬 Contact

- **GitHub:** https://github.com/Ununp3ntium115/R-map
- **Issues:** https://github.com/Ununp3ntium115/R-map/issues
- **Security:** security@r-map.io
- **PGP Key Owner:** PyroDIFR@proton.me

---

**Thank you for testing R-Map v0.1.0-alpha!** 🎉

Your feedback helps make R-Map better. Please report any issues or suggestions on GitHub.

---

**Package ID:** rmap-windows-v0.1.0-alpha-20251119
**Build Date:** 2025-08-29
**Package Date:** 2025-11-19
**Status:** Alpha Pre-Release (Unsigned)
**Ready for:** Testing & Evaluation

*Built with ❤️ in Rust*
