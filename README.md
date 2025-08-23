# 🦀 R-Map - Rust Network Mapper

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/Ununp3ntium115/nmap)

**R-Map** is a modern, memory-safe network mapper written in Rust. It provides the powerful network discovery and security auditing capabilities of Nmap while leveraging Rust's safety guarantees and performance benefits.

## 🚀 Features

### ✅ **Core Scanning**
- **TCP Connect Scan**: Full three-way handshake scanning
- **TCP SYN Scan**: Stealth half-open scanning  
- **UDP Scan**: UDP port scanning with ICMP analysis
- **Async/Concurrent**: High-performance parallel scanning

### 🔍 **Service Detection**
- **Banner Grabbing**: Automatic service identification
- **Version Detection**: Product and version fingerprinting
- **Signature Database**: Extensible service recognition
- **CPE Integration**: Common Platform Enumeration support

### 🖥️ **OS Detection**
- **TCP Fingerprinting**: Advanced stack analysis
- **UDP Probes**: Operating system identification
- **ICMP Analysis**: Network stack characteristics
- **Timing Analysis**: Response pattern matching

### 📊 **Output Formats**
- **Normal**: Human-readable text output
- **XML**: Structured data format
- **JSON**: Modern API-friendly format
- **Grepable**: Machine-parseable output

### 🛡️ **Safety & Performance**
- **Memory Safe**: Zero buffer overflows
- **Thread Safe**: Concurrent scanning without data races
- **Resource Efficient**: Automatic cleanup and management
- **Cross Platform**: Windows, Linux, macOS support

## 🎯 Quick Start

### Installation
```bash
git clone https://github.com/Ununp3ntium115/nmap
cd nmap
cargo build --release --bin rmap
```

### Basic Usage
```bash
# Basic port scan
./target/release/rmap 192.168.1.1

# Scan specific ports
./target/release/rmap -p 22,80,443 scanme.nmap.org

# Service detection
./target/release/rmap -A 192.168.1.0/24

# Output to file
./target/release/rmap -o json -f results.json 8.8.8.8

# Timing control
./target/release/rmap -T4 --max-rate 1000 192.168.1.0/24

# OS detection
./target/release/rmap -O 192.168.1.1
```

### Command Line Options
```
USAGE:
    rmap [OPTIONS] <TARGETS>...

ARGS:
    <TARGETS>...    Target hosts or networks to scan

OPTIONS:
    -p, --ports <PORT_SPEC>         Port specification [default: 1-1000]
    -s, --scan-type <TYPE>          Scan type [default: tcp]
    -o, --output <FORMAT>           Output format [default: normal]
    -f, --file <FILE>               Output file
    -v, --verbose                   Increase verbosity level
    -T, --timing <LEVEL>            Timing template (0-5) [default: 3]
    -A, --aggressive                Enable aggressive scan
    -O, --os-detect                 Enable OS detection
    -V, --version-detect            Enable version detection
    -n, --no-ping                   Skip host discovery
        --max-rate <RATE>           Maximum packets per second
        --min-rate <RATE>           Minimum packets per second
    -h, --help                      Print help information
```

## 🏗️ Architecture

R-Map is built with a modular crate architecture:

```
rmap/
├── crates/
│   ├── nmap-core/          # Core types and configuration
│   ├── nmap-cli/           # Command-line interface
│   ├── nmap-engine/        # Scanning engines
│   ├── nmap-net/           # Network utilities & packet crafting
│   ├── nmap-targets/       # Target management
│   ├── nmap-timing/        # Rate limiting
│   ├── nmap-output/        # Output formatting
│   ├── nmap-os-detect/     # OS fingerprinting
│   ├── nmap-service-detect/# Service detection
│   ├── nmap-scripting/     # R-Map Scripting Engine (RSE)
│   └── rmap-bin/           # Main executable
└── Pure Rust implementation with zero C/C++ dependencies
```

## 🎮 Examples

### Basic Port Scan
```rust
use rmap::*;

#[tokio::main]
async fn main() -> Result<()> {
    let target = TargetHost::new(\"8.8.8.8\".parse()?);
    let ports = PortSpec::parse(\"80,443,8080\")?;
    
    let mut engine = ScanEngine::new(NmapOptions::default());
    let results = engine.scan_ports(&target, &ports).await?;
    
    for result in results {
        println!(\"{}/tcp - {}\", result.port, result.state);
    }
    
    Ok(())
}
```

### Service Detection
```rust
use rmap::*;

#[tokio::main]
async fn main() -> Result<()> {
    let target = TargetHost::new(\"example.com\".parse()?);
    let detector = ServiceDetector::new()?;
    
    let result = detector.detect_service(&target, 80, \"tcp\").await?;
    
    if let Some(service) = result.service {
        println!(\"Service: {} {}\", 
                 service.name, 
                 service.version.unwrap_or_default());
    }
    
    Ok(())
}
```

## 🔧 Development

### Prerequisites
- Rust 1.70 or later
- Cargo package manager
- Network access for testing

### Building
```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Build production binary
cargo build --release --bin rmap
```

### Testing
```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test --test integration

# Test specific crate
cargo test -p nmap-core
```

## 📈 Performance

R-Map provides significant improvements over traditional C++ implementations:

- **Memory Safety**: 100% safe Rust code eliminates buffer overflows
- **Concurrency**: Async/await enables efficient parallel scanning
- **Resource Management**: Automatic cleanup prevents memory leaks
- **Error Handling**: Comprehensive error propagation and recovery

### Benchmarks
- **Port Scanning**: Sub-second scanning for common port ranges
- **Service Detection**: Real-time banner analysis and identification
- **Memory Usage**: Minimal footprint with automatic resource management
- **Concurrency**: Scales efficiently across multiple CPU cores

## 🛡️ Security

R-Map prioritizes security through:

- **Memory Safety**: Rust's ownership system prevents common vulnerabilities
- **Input Validation**: Strong typing prevents injection attacks
- **Privilege Separation**: Minimal required permissions
- **Safe Concurrency**: Data race prevention at compile time

## 🚀 Pure Rust Implementation

R-Map is a **100% pure Rust** implementation with **zero C/C++ dependencies**:

### ✅ **Replaced C Libraries**
- **libpcap** → Pure Rust packet crafting (`nmap-net::packet`)
- **libdnet** → Rust networking utilities (`socket2`, `pnet`)
- **NSE/Lua** → R-Map Scripting Engine (RSE) in pure Rust
- **Data parsing** → Native Rust parsers for all data files
- **OS detection** → Rust-based fingerprinting algorithms

### 🔧 **Modern Dependencies**
- **Tokio**: Async runtime for high-performance I/O
- **Serde**: Serialization for JSON/XML output
- **Clap**: Modern CLI argument parsing
- **Anyhow**: Ergonomic error handling
- **Tracing**: Structured logging and diagnostics

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Code Style
- Follow Rust standard formatting (`cargo fmt`)
- Ensure all tests pass (`cargo test`)
- Add documentation for public APIs
- Include examples for new features

## 📚 Documentation

- [API Documentation](https://docs.rs/rmap)
- [User Guide](docs/user-guide.md)
- [Developer Guide](docs/developer-guide.md)
- [Architecture Overview](docs/architecture.md)

## 🎯 Roadmap

### Version 0.2.0
- [ ] Complete RSE scripting engine with vulnerability detection
- [ ] Advanced OS detection database
- [ ] IPv6 full support
- [ ] GUI interface (R-Map GUI)

### Version 0.3.0
- [ ] Plugin system architecture
- [ ] Performance optimizations
- [ ] Extended protocol support
- [ ] Cloud scanning capabilities

## 📄 License

R-Map is dual-licensed under the MIT and Apache 2.0 licenses.

- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

## 🙏 Acknowledgments

- **Nmap Project**: For the original network mapping concepts and techniques
- **Rust Community**: For the amazing ecosystem and tools
- **Contributors**: Everyone who has contributed to making R-Map better

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Ununp3ntium115/nmap/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Ununp3ntium115/nmap/discussions)
- **Documentation**: [Online Docs](https://docs.rs/rmap)

---

**R-Map**: *Rust-powered network mapping for the modern age* 🦀🗺️