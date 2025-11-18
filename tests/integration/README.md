# Integration Test Infrastructure for R-Map

This directory contains Docker-based integration tests that validate R-Map against real network services.

## Overview

Integration tests run actual scans against containerized services to ensure:
- Port scanning detects open/closed ports correctly
- Service detection identifies protocols accurately
- Banner grabbing extracts version information
- Output formats generate valid data
- Error handling works in real-world scenarios

## Test Environment

The test environment uses Docker Compose to spin up:
- **Target Services**: HTTP, SSH, FTP, MySQL servers with known configurations
- **R-Map Scanner**: The scanner binary to test
- **Validation**: Automated checks of scan results

## Running Integration Tests

```bash
# Start test environment
cd tests/integration
docker-compose up -d

# Wait for services to be ready
sleep 10

# Run integration tests
cargo test --test integration -- --test-threads=1

# Clean up
docker-compose down
```

## Test Structure

```
tests/integration/
├── docker-compose.yml      # Test service definitions
├── fixtures/               # Test data and configurations
│   ├── http/              # HTTP server configs
│   ├── ssh/               # SSH server configs
│   └── expected/          # Expected scan results
├── services/              # Custom service containers
└── integration_tests.rs   # Actual test code
```

## Test Scenarios

1. **Basic Port Scanning**
   - Scan known open ports (80, 22, 21, 3306)
   - Verify closed ports return correct state
   - Test filtered ports with firewall rules

2. **Service Detection**
   - HTTP banner: "nginx/1.24.0"
   - SSH banner: "OpenSSH_9.0"
   - FTP banner: "vsftpd 3.0.5"
   - MySQL version detection

3. **Protocol Validation**
   - TCP Connect scan accuracy
   - UDP scan for DNS (port 53)
   - Service-specific probes

4. **Output Format Validation**
   - JSON parseable and matches schema
   - XML valid against nmap DTD
   - Grepable format parseable

5. **Error Scenarios**
   - Connection refused handling
   - Connection timeout behavior
   - DNS resolution failures
   - Invalid target handling

## CI/CD Integration

Integration tests run in GitHub Actions:

```yaml
- name: Run integration tests
  run: |
    docker-compose -f tests/integration/docker-compose.yml up -d
    sleep 15
    cargo test --test integration
    docker-compose -f tests/integration/docker-compose.yml down
```

## Adding New Tests

1. Add service to `docker-compose.yml`
2. Create fixture data in `fixtures/`
3. Add test case in `integration_tests.rs`
4. Update expected results

Example:
```rust
#[tokio::test]
async fn test_mysql_detection() {
    let output = scan_target("mysql-test:3306").await;
    assert!(output.contains("mysql"));
    assert!(output.contains("5.7"));
}
```
