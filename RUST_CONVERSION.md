# Nmap Rust Conversion

This document outlines the conversion of Nmap from C++ to Rust.

## Project Structure

The Rust implementation follows a modular architecture with separate crates for different functionality:

### Core Crates

- **nmap-core**: Main library containing the engine and core types
- **nmap-cli**: Command-line interface parsing and handling
- **nmap-engine**: Scanning engine implementation
- **nmap-net**: Network utilities, socket handling, and protocol definitions
- **nmap-targets**: Target discovery and management
- **nmap-timing**: Timing templates and rate limiting
- **nmap-output**: Output formatting (normal, XML, JSON, grepable)

### Feature Crates

- **nmap-os-detect**: OS detection functionality
- **nmap-service-detect**: Service and version detection
- **nmap-scripting**: NSE (Nmap Scripting Engine) with Lua support

## Key Design Decisions

### Memory Safety
- Rust's ownership system eliminates memory leaks and buffer overflows
- No need for manual memory management like the C++ version
- Safe concurrency with Rust's type system

### Async/Await
- Uses Tokio for asynchronous I/O operations
- Better scalability for handling many concurrent connections
- Non-blocking network operations

### Error Handling
- Comprehensive error types with `anyhow` for error propagation
- No more segfaults or undefined behavior
- Graceful error recovery

### Modular Architecture
- Clean separation of concerns with crate boundaries
- Easy to test individual components
- Maintainable and extensible codebase

## Current Status

This is a minimal working skeleton that demonstrates the architecture. Key components implemented:

✅ Basic project structure and build system
✅ Command-line argument parsing
✅ Target discovery and parsing
✅ Basic scan engine framework
✅ Output formatting system
✅ Timing templates
✅ Error handling

## TODO

### High Priority
- [ ] Raw socket implementation for SYN scanning
- [ ] TCP connect() scanning
- [ ] UDP scanning
- [ ] ICMP ping implementation
- [ ] Port state detection logic
- [ ] Privilege checking and validation

### Medium Priority
- [ ] Service detection probes
- [ ] OS fingerprinting
- [ ] NSE script execution
- [ ] XML output format
- [ ] Scan resumption
- [ ] IPv6 support

### Low Priority
- [ ] Advanced scan types (FIN, NULL, Xmas, etc.)
- [ ] Decoy scanning
- [ ] Idle scanning
- [ ] Traceroute implementation
- [ ] Performance optimizations

## Building and Running

```bash
# Build the project
cargo build --release

# Run with basic options
cargo run -- -v scanme.nmap.org

# Run with aggressive scanning
cargo run -- -A -T4 192.168.1.0/24
```

## Architecture Comparison

### C++ Version
- Monolithic design with global state
- Manual memory management
- Blocking I/O with threads
- Complex build system (autotools)

### Rust Version
- Modular crate-based architecture
- Automatic memory management
- Async I/O with Tokio
- Simple build system (Cargo)

## Performance Considerations

The Rust version should provide:
- Better memory efficiency due to zero-cost abstractions
- Improved concurrency with async/await
- Reduced CPU overhead from memory management
- Better cache locality with owned data structures

## Security Benefits

- Memory safety prevents buffer overflows
- Type safety prevents many classes of bugs
- No null pointer dereferences
- Safe concurrency prevents data races
- Dependency management with Cargo audit

## Migration Strategy

1. **Phase 1**: Core functionality (current)
   - Basic scanning capabilities
   - Target parsing and discovery
   - Simple output formats

2. **Phase 2**: Advanced features
   - All scan types
   - Service/OS detection
   - NSE scripting

3. **Phase 3**: Optimization and compatibility
   - Performance tuning
   - Full feature parity
   - Extensive testing

## Contributing

When contributing to the Rust conversion:

1. Follow Rust naming conventions and idioms
2. Use `cargo fmt` for consistent formatting
3. Run `cargo clippy` for linting
4. Add comprehensive tests for new functionality
5. Update documentation for API changes

## Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific crate tests
cargo test -p nmap-core
```