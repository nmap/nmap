# Technology Stack

## Build System

- **Primary Build System**: GNU Autotools (autoconf/automake)
  - `configure.ac` - Main autoconf configuration
  - `Makefile.in` - Main makefile template
- **Platform Support**: Cross-platform with platform-specific configurations
- **Dependency Management**: Bundled libraries with system library detection

## Core Technologies

### Languages
- **C++**: Main application code (scanning engine, core functionality)
- **C**: Low-level networking and system interfaces
- **Lua 5.4**: NSE scripting engine and scripts
- **Python 3**: Zenmap GUI, Ndiff utility, build scripts

### Key Libraries (Bundled)
- **libpcap**: Packet capture library
- **libdnet**: Low-level networking routines
- **libpcre2**: Perl-compatible regular expressions
- **liblua**: Lua interpreter
- **liblinear**: Machine learning library for OS detection
- **libssh2**: SSH2 protocol implementation (optional)
- **zlib**: Compression library (optional)
- **OpenSSL**: Cryptographic functions (optional)

### Networking Stack
- Raw sockets for packet crafting
- Berkeley sockets for standard networking
- Platform-specific packet capture (libpcap/Npcap)

## Common Build Commands

### Basic Build
```bash
./configure
make
make install
```

### Development Build
```bash
./configure --with-openssl --with-libssh2
make debug          # Build with debugging symbols
make static         # Build statically linked binary
```

### Component-Specific Builds
```bash
make build-zenmap   # Build GUI only
make build-ncat     # Build Ncat only
make build-nping    # Build Nping only
make build-ndiff    # Build Ndiff only
```

### Testing
```bash
make check          # Run all tests
make check-nse      # Test NSE scripts
make check-ncat     # Test Ncat
make check-ndiff    # Test Ndiff
```

### Cleaning
```bash
make clean          # Clean build artifacts
make distclean      # Clean everything including configure output
```

## Configuration Options

### Library Selection
- `--with-openssl=DIR` - Use specific OpenSSL installation
- `--with-libpcap=included` - Force use of bundled libpcap
- `--without-zenmap` - Skip Zenmap GUI build
- `--without-nping` - Skip Nping build
- `--with-localdirs` - Use /usr/local for headers/libs

### Platform-Specific Flags
- Linux: `-Wl,-E` for NSE C module support
- macOS: `-no-cpp-precomp` for older versions
- Solaris: Special checksum bug handling
- Windows: Uses Visual Studio project files