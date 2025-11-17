# R-Map Security Scripting Framework (RSE)

A production-ready, Rust-native scripting framework for R-Map that serves as a modern replacement for Nmap's NSE (Nmap Scripting Engine). All scripts are implemented in pure Rust for maximum performance, safety, and reliability.

## Features

- **Pure Rust Implementation**: No Lua required - all scripts are native Rust code
- **Async/Parallel Execution**: Scripts run concurrently for maximum performance
- **Type-Safe**: Leverages Rust's type system for compile-time guarantees
- **Modular Architecture**: Easy to extend with new vulnerability detection scripts
- **Comprehensive Coverage**: 20+ essential vulnerability detection scripts included

## Architecture

### Core Components

1. **Script Engine (`engine.rs`)**: Manages script registration, execution, and lifecycle
2. **Script Trait**: Defines the interface all scripts must implement
3. **Common Utilities (`common.rs`)**: Shared functionality for network operations
4. **Script Registry (`registry.rs`)**: Centralized registration and discovery

### Script Categories

- `Vuln`: Vulnerability detection
- `Safe`: Non-intrusive reconnaissance
- `Intrusive`: Active security testing
- `Auth`: Authentication testing
- `Exploit`: Exploit verification
- `Discovery`: Service discovery
- `Default`: Default credential testing

## Included Vulnerability Scripts (20 Total)

### HTTP Vulnerabilities (5 scripts)

1. **http-vuln-cve2021-41773**: Apache 2.4.49-2.4.50 Path Traversal (CVE-2021-41773)
2. **http-vuln-cve2017-5638**: Apache Struts2 RCE (CVE-2017-5638)
3. **http-default-accounts**: Default credential detection
4. **http-sql-injection**: Basic SQL injection detection
5. **http-security-headers**: Missing security headers detection

### SSL/TLS Vulnerabilities (3 scripts)

6. **ssl-heartbleed**: Heartbleed vulnerability (CVE-2014-0160)
7. **ssl-poodle**: POODLE SSL vulnerability (CVE-2014-3566)
8. **ssl-cert-expiry**: SSL certificate expiration check

### SMB Vulnerabilities (2 scripts)

9. **smb-vuln-ms17-010**: EternalBlue (MS17-010)
10. **smb-vuln-ms08-067**: Windows RPC vulnerability (MS08-067)

### Service-Specific Vulnerabilities (4 scripts)

11. **ssh-weak-algorithms**: Weak SSH cryptographic algorithms
12. **ftp-anon**: Anonymous FTP access detection
13. **mysql-empty-password**: MySQL empty root password
14. **telnet-encryption**: Telnet encryption status

### Network Service Vulnerabilities (6 scripts)

15. **dns-zone-transfer**: DNS AXFR zone transfer
16. **smtp-open-relay**: SMTP open relay detection
17. **ntp-monlist**: NTP monlist amplification (CVE-2013-5211)
18. **snmp-default-community**: Default SNMP community strings
19. **rdp-vuln-ms12-020**: RDP MS12-020 vulnerability
20. **http-xss-detection**: Basic XSS vulnerability detection

## Usage

### Basic Script Execution

```rust
use nmap_scripting::{ScriptEngine, ScriptContext, register_all_scripts};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize engine
    let engine = ScriptEngine::new();

    // Register all scripts
    register_all_scripts(&engine).await?;

    // Create context
    let context = ScriptContext {
        target_ip: "192.168.1.1".parse()?,
        target_port: Some(80),
        protocol: Some("tcp".to_string()),
        service: Some("http".to_string()),
        version: None,
        os_info: None,
        timing: ScriptTiming::default(),
        user_args: HashMap::new(),
    };

    // Execute scripts for service
    let results = engine.execute_for_service("http", &context).await?;

    // Process results
    for result in results {
        if !result.vulnerabilities.is_empty() {
            for vuln in &result.vulnerabilities {
                println!("VULNERABILITY: {} ({})", vuln.title, vuln.severity);
                println!("  Description: {}", vuln.description);
                println!("  CVSS: {:?}", vuln.cvss_score);
            }
        }
    }

    Ok(())
}
```

### Parallel Execution

```rust
// Execute multiple scripts in parallel
let script_names = vec![
    "http-vuln-cve2021-41773".to_string(),
    "http-security-headers".to_string(),
    "ssl-heartbleed".to_string(),
];

let results = engine.execute_scripts_parallel(script_names, &context).await;
```

### Service-Based Execution

```rust
// Automatically run all scripts for a specific service
let results = engine.execute_for_service("http", &context).await?;
```

### Execute All Vulnerability Scripts

```rust
// Run all 20 vulnerability detection scripts
let results = engine.execute_all_vulnerability_scripts(&context).await?;
```

## Creating Custom Scripts

```rust
use nmap_scripting::*;
use anyhow::Result;

pub struct MyCustomScript;

#[async_trait::async_trait]
impl Script for MyCustomScript {
    fn name(&self) -> &str { "my-custom-script" }
    fn description(&self) -> &str { "My custom vulnerability check" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Safe]
    }
    fn author(&self) -> &str { "Your Name" }
    fn license(&self) -> &str { "MIT" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("http") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        // Your vulnerability detection logic here
        let client = build_http_client()?;
        let url = format!("http://{}:{}/", context.target_ip,
                         context.target_port.unwrap_or(80));

        match http_request(&client, &url, "GET", 10).await {
            Ok(response) => {
                // Check for vulnerability
                if /* vulnerability detected */ false {
                    let vuln = Vulnerability {
                        id: "CUSTOM-001".to_string(),
                        title: "Custom Vulnerability".to_string(),
                        severity: VulnerabilitySeverity::High,
                        description: "Description here".to_string(),
                        references: vec![],
                        cvss_score: Some(7.0),
                    };

                    Ok(ScriptResult::success("VULNERABLE".to_string())
                        .with_vulnerability(vuln))
                } else {
                    Ok(ScriptResult::success("Not vulnerable".to_string()))
                }
            }
            Err(e) => Ok(ScriptResult::failure(format!("Error: {}", e))),
        }
    }
}

// Register your custom script
engine.register_script(Box::new(MyCustomScript)).await?;
```

## Testing

Run all tests:

```bash
cd crates/nmap-scripting
cargo test
```

Run specific test:

```bash
cargo test test_register_all_scripts
```

Run with output:

```bash
cargo test -- --nocapture
```

## Performance

- **Parallel Execution**: Up to 10 scripts run concurrently
- **Timeout Handling**: All network operations have configurable timeouts
- **Memory Safe**: No buffer overflows or memory leaks
- **Resource Limits**: Response sizes limited to prevent DoS

## Security Considerations

- All network operations have timeouts
- Response data is sanitized to prevent injection attacks
- Maximum response sizes enforced
- No arbitrary code execution (unlike Lua-based NSE)
- Type-safe implementation prevents common vulnerabilities

## Integration with R-Map

The script engine is integrated into `nmap-engine` via the `script_scan` method:

```rust
pub async fn script_scan(&self, targets: &[Host]) -> Result<Vec<Host>> {
    let engine = ScriptEngine::new();
    register_all_scripts(&engine).await?;

    for host in targets {
        for port in &host.ports {
            if let Some(service) = &port.service {
                let results = engine.execute_for_service(service, &context).await?;
                // Process results...
            }
        }
    }

    Ok(targets)
}
```

## Script Organization

```
crates/nmap-scripting/
├── Cargo.toml              # Dependencies
├── README.md               # This file
├── src/
│   ├── lib.rs             # Main module exports
│   ├── engine.rs          # Script execution engine
│   ├── builtin_scripts.rs # Discovery scripts
│   ├── common.rs          # Shared utilities
│   ├── registry.rs        # Script registration
│   ├── vuln_http.rs       # HTTP vulnerability scripts
│   ├── vuln_ssl.rs        # SSL/TLS vulnerability scripts
│   ├── vuln_smb.rs        # SMB vulnerability scripts
│   ├── vuln_services.rs   # SSH/FTP/DB scripts
│   └── vuln_network.rs    # Network service scripts
└── tests/
    └── integration_tests.rs # Integration tests
```

## Future Enhancements

- [ ] Script arguments support
- [ ] Script dependencies
- [ ] Script output templates
- [ ] Custom timing profiles per script
- [ ] Script result caching
- [ ] Plugin system for external scripts
- [ ] Script performance profiling
- [ ] Web UI for script management

## License

MIT OR Apache-2.0

## Contributors

R-Map Contributors
