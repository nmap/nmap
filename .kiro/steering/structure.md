# Project Structure

## Root Directory Layout

### Core Nmap Files
- `main.cc` - Entry point, calls nmap_main()
- `nmap.cc/.h` - Main Nmap functionality and command-line interface
- `NmapOps.cc/.h` - Global options and configuration management
- `Target.cc/.h`, `TargetGroup.cc/.h` - Target host management
- `scan_engine*.cc/.h` - Core scanning engines (connect, raw, etc.)
- `osscan*.cc/.h` - OS detection functionality
- `service_scan.cc/.h` - Service/version detection
- `output.cc/.h`, `xml.cc/.h` - Output formatting and XML generation

### Network and Protocol Handling
- `tcpip.cc/.h` - TCP/IP utilities and packet crafting
- `protocols.cc/.h` - Protocol definitions and handling
- `portlist.cc/.h` - Port state management
- `timing.cc/.h` - Timing and rate limiting
- `traceroute.cc/.h` - Traceroute functionality

### NSE (Nmap Scripting Engine)
- `nse_main.cc/.h` - NSE core engine
- `nse_*.cc/.h` - NSE subsystems (utility, nsock, dnet, fs, etc.)
- `nse_main.lua` - Main NSE Lua bootstrap
- `scripts/` - NSE script collection
- `nselib/` - NSE Lua libraries

### Utility and Support
- `utils.cc/.h` - General utility functions
- `nmap_error.cc/.h` - Error handling and reporting
- `charpool.cc/.h` - Memory management utilities
- `string_pool.cc/.h` - String pooling for memory efficiency

## Component Directories

### Core Libraries (Bundled Dependencies)
- `libpcap/` - Packet capture library (modified for Nmap)
- `libdnet-stripped/` - Low-level networking (Nmap-modified version)
- `libpcre/` - Perl-compatible regular expressions
- `liblua/` - Lua interpreter
- `liblinear/` - Machine learning library
- `libssh2/` - SSH2 protocol support
- `libz/` - Compression library
- `libnetutil/` - Nmap's networking utility library

### Companion Tools
- `zenmap/` - Python-based GUI frontend
- `ncat/` - Network utility (netcat replacement)
- `ndiff/` - Scan result comparison utility
- `nping/` - Packet generation and analysis tool

### Support Libraries
- `nbase/` - Base utility library shared across Nmap tools
- `nsock/` - Asynchronous networking library

### Documentation and Data
- `docs/` - Documentation, man pages, and style guides
- `scripts/` - NSE scripts organized by category
- `nselib/` - NSE Lua library modules
- `nmap-*` files - Data files (services, OS fingerprints, protocols, etc.)

### Build and Development
- `configure.ac` - Autoconf configuration
- `Makefile.in` - Main makefile template
- `tests/` - Test suite
- `macosx/`, `mswin32/` - Platform-specific build files

## File Naming Conventions

### C++ Source Files
- `.cc` extension for C++ source files
- `.h` extension for header files
- CamelCase for class names (e.g., `NmapOps`, `TargetGroup`)
- lowercase with underscores for functions and variables

### NSE Files
- `.nse` extension for NSE scripts
- `.lua` extension for NSE libraries
- Descriptive names with hyphens (e.g., `http-title.nse`)

### Data Files
- `nmap-services` - Port/service mappings
- `nmap-os-db` - OS fingerprint database
- `nmap-service-probes` - Service detection probes
- `nmap-protocols` - Protocol number mappings
- `nmap-rpc` - RPC program mappings
- `nmap-mac-prefixes` - MAC address vendor prefixes

## Architecture Patterns

### Modular Design
- Clear separation between scanning engines, output modules, and utilities
- Plugin-like architecture for NSE scripts
- Abstracted networking layer through libnetutil

### Cross-Platform Compatibility
- Platform-specific code isolated in separate modules
- Autotools-based configuration for different systems
- Bundled dependencies to reduce external requirements

### Memory Management
- Custom memory pools for performance
- RAII patterns in C++ code
- Careful resource cleanup in long-running scans