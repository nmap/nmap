pub mod syn_scanner;
pub mod udp_scanner;
pub mod advanced_tcp_scanner;

// Re-export scanners for external use
pub use syn_scanner::{SynScanner, ConnectScanner};
pub use udp_scanner::UdpScanner;
pub use advanced_tcp_scanner::{AckScanner, FinScanner, NullScanner, XmasScanner};

use anyhow::Result;
use nmap_net::{Host, HostState, ScanType, check_raw_socket_privileges};
use tokio::time::Duration;
use tracing::{info, debug, warn};

/// Maximum length for banner strings to prevent resource exhaustion
const MAX_BANNER_LENGTH: usize = 512;

/// Sanitize banner data to prevent injection attacks and resource exhaustion
fn sanitize_banner(banner: &str) -> String {
    // Limit length to prevent resource exhaustion
    let truncated = if banner.len() > MAX_BANNER_LENGTH {
        warn!("Banner truncated from {} to {} bytes", banner.len(), MAX_BANNER_LENGTH);
        &banner[..MAX_BANNER_LENGTH]
    } else {
        banner
    };

    // Remove control characters (except tab, newline, carriage return)
    // This prevents terminal escape sequence injections
    let mut sanitized = String::with_capacity(truncated.len());
    for ch in truncated.chars() {
        if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' {
            // Replace control characters with '.'
            sanitized.push('.');
        } else {
            sanitized.push(ch);
        }
    }

    // Remove any ANSI escape sequences (e.g., \x1b[31m for red color)
    // Note: This regex is a constant pattern so it should never fail to compile
    let ansi_escape = match regex::Regex::new(r"\x1b\[[0-9;]*m") {
        Ok(regex) => regex,
        Err(e) => {
            warn!("Failed to compile ANSI escape regex (should never happen): {}", e);
            // Return sanitized string without ANSI removal if regex fails
            return sanitized.trim().to_string();
        }
    };
    let without_ansi = ansi_escape.replace_all(&sanitized, "");

    // Trim whitespace and return
    without_ansi.trim().to_string()
}

pub struct ScanEngine {
    options: nmap_core::NmapOptions,
    syn_scanner: Option<SynScanner>,
    connect_scanner: ConnectScanner,
    udp_scanner: UdpScanner,
    ack_scanner: Option<AckScanner>,
    fin_scanner: Option<FinScanner>,
    null_scanner: Option<NullScanner>,
    xmas_scanner: Option<XmasScanner>,
}

impl ScanEngine {
    pub fn new(options: &nmap_core::NmapOptions) -> Result<Self> {
        let timing_config = options.timing_template().config();

        // Try to create SYN scanner if we have privileges
        let syn_scanner = if check_raw_socket_privileges() {
            match SynScanner::new(timing_config.clone()) {
                Ok(scanner) => {
                    info!("Raw socket access available, using SYN scanning");
                    Some(scanner)
                }
                Err(e) => {
                    warn!("Failed to create raw socket: {}, falling back to connect scan", e);
                    None
                }
            }
        } else {
            info!("No raw socket privileges, using TCP connect scanning");
            None
        };

        let connect_scanner = ConnectScanner::new(timing_config.clone());
        let udp_scanner = UdpScanner::new(timing_config.clone());

        // Try to create advanced TCP scanners if we have privileges
        let (ack_scanner, fin_scanner, null_scanner, xmas_scanner) = if check_raw_socket_privileges() {
            (
                AckScanner::new(timing_config.clone()).ok(),
                FinScanner::new(timing_config.clone()).ok(),
                NullScanner::new(timing_config.clone()).ok(),
                XmasScanner::new(timing_config).ok(),
            )
        } else {
            (None, None, None, None)
        };

        Ok(Self {
            options: options.clone(),
            syn_scanner,
            connect_scanner,
            udp_scanner,
            ack_scanner,
            fin_scanner,
            null_scanner,
            xmas_scanner,
        })
    }
    
    pub async fn host_discovery(&self, targets: &[Host]) -> Result<Vec<Host>> {
        info!("Starting host discovery for {} targets", targets.len());

        let mut live_hosts = Vec::new();

        for target in targets {
            let mut host = target.clone();

            // Perform TCP connect scan on common ports to determine if host is up
            // This is more reliable than ICMP which may be blocked
            let test_ports = vec![80, 443, 22, 21, 25, 3389, 8080];
            let mut is_up = false;

            for &port in &test_ports {
                let addr = std::net::SocketAddr::new(target.address, port);
                match tokio::time::timeout(
                    Duration::from_millis(200),
                    tokio::net::TcpStream::connect(addr)
                ).await {
                    Ok(Ok(_)) => {
                        // Port is open, host is definitely up
                        is_up = true;
                        break;
                    }
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                        // Connection refused means host is up but port is closed
                        is_up = true;
                        break;
                    }
                    _ => {
                        // Timeout or other error, continue to next port
                        continue;
                    }
                }
            }

            if is_up {
                host.state = HostState::Up;
                live_hosts.push(host);
                debug!("Host {} is up", target.address);
            } else {
                debug!("Host {} appears to be down or all test ports filtered", target.address);
            }
        }

        info!("Host discovery completed, {} out of {} hosts up", live_hosts.len(), targets.len());
        Ok(live_hosts)
    }
    
    pub async fn port_scan(&self, targets: &[Host]) -> Result<Vec<Host>> {
        info!("Starting port scan for {} targets", targets.len());
        
        let mut results = targets.to_vec();
        
        // Get ports to scan
        let ports: Vec<u16> = self.options.port_specs
            .iter()
            .flat_map(|spec| spec.get_ports())
            .collect();
        
        if ports.is_empty() {
            warn!("No ports specified for scanning");
            return Ok(results);
        }
        
        // Determine scan type and execute
        let scan_type = self.options.scan_types.first().unwrap_or(&ScanType::Syn);

        match scan_type {
            ScanType::Syn => {
                if let Some(ref syn_scanner) = self.syn_scanner {
                    syn_scanner.scan_hosts(&mut results, &ports).await?;
                } else {
                    info!("SYN scan requested but no raw socket available, using connect scan");
                    self.connect_scanner.scan_hosts(&mut results, &ports).await?;
                }
            }
            ScanType::Connect => {
                self.connect_scanner.scan_hosts(&mut results, &ports).await?;
            }
            ScanType::Udp => {
                info!("Starting UDP scan");
                self.udp_scanner.scan_hosts(&mut results, &ports).await?;
            }
            ScanType::Ack => {
                if let Some(ref ack_scanner) = self.ack_scanner {
                    info!("Starting ACK scan for firewall rule detection");
                    ack_scanner.scan_hosts(&mut results, &ports).await?;
                } else {
                    warn!("ACK scan requested but no raw socket available, using connect scan");
                    self.connect_scanner.scan_hosts(&mut results, &ports).await?;
                }
            }
            ScanType::Fin => {
                if let Some(ref fin_scanner) = self.fin_scanner {
                    info!("Starting FIN scan (stealth)");
                    fin_scanner.scan_hosts(&mut results, &ports).await?;
                } else {
                    warn!("FIN scan requested but no raw socket available, using connect scan");
                    self.connect_scanner.scan_hosts(&mut results, &ports).await?;
                }
            }
            ScanType::Null => {
                if let Some(ref null_scanner) = self.null_scanner {
                    info!("Starting NULL scan (all flags off)");
                    null_scanner.scan_hosts(&mut results, &ports).await?;
                } else {
                    warn!("NULL scan requested but no raw socket available, using connect scan");
                    self.connect_scanner.scan_hosts(&mut results, &ports).await?;
                }
            }
            ScanType::Xmas => {
                if let Some(ref xmas_scanner) = self.xmas_scanner {
                    info!("Starting Xmas scan (FIN+PSH+URG)");
                    xmas_scanner.scan_hosts(&mut results, &ports).await?;
                } else {
                    warn!("Xmas scan requested but no raw socket available, using connect scan");
                    self.connect_scanner.scan_hosts(&mut results, &ports).await?;
                }
            }
            _ => {
                warn!("Scan type {:?} not yet implemented, using connect scan", scan_type);
                self.connect_scanner.scan_hosts(&mut results, &ports).await?;
            }
        }
        
        debug!("Port scan completed");
        Ok(results)
    }
    
    pub async fn service_detection(&self, targets: &[Host]) -> Result<Vec<Host>> {
        info!("Starting service detection for {} targets", targets.len());

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;

        let mut results = targets.to_vec();

        for host in &mut results {
            for port in &mut host.ports {
                if port.state != nmap_net::PortState::Open {
                    continue;
                }

                // Try to connect and grab banner
                let addr = std::net::SocketAddr::new(host.address, port.number);

                match timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(addr)).await {
                    Ok(Ok(mut stream)) => {
                        // Try banner grabbing based on port
                        match port.number {
                            22 => {
                                // SSH banner
                                let mut buffer = [0; 1024];
                                if let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                                    if n > 0 {
                                        let banner = String::from_utf8_lossy(&buffer[..n]);
                                        if banner.starts_with("SSH-") {
                                            port.service = Some("ssh".to_string());
                                            // Security: Sanitize banner to prevent injection attacks
                                            port.version = Some(sanitize_banner(&banner));
                                        }
                                    }
                                }
                            }
                            21 => {
                                // FTP banner
                                let mut buffer = [0; 1024];
                                if let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                                    if n > 0 {
                                        let banner = String::from_utf8_lossy(&buffer[..n]);
                                        if banner.starts_with("220") {
                                            port.service = Some("ftp".to_string());
                                            // Security: Sanitize banner to prevent injection attacks
                                            port.version = Some(sanitize_banner(&banner));
                                        }
                                    }
                                }
                            }
                            25 => {
                                // SMTP banner
                                let mut buffer = [0; 1024];
                                if let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                                    if n > 0 {
                                        let banner = String::from_utf8_lossy(&buffer[..n]);
                                        if banner.starts_with("220") {
                                            port.service = Some("smtp".to_string());
                                            // Security: Sanitize banner to prevent injection attacks
                                            port.version = Some(sanitize_banner(&banner));
                                        }
                                    }
                                }
                            }
                            80 | 8080 => {
                                // HTTP banner
                                let request = b"GET / HTTP/1.0\r\n\r\n";
                                if let Ok(_) = stream.write_all(request).await {
                                    let mut buffer = [0; 2048];
                                    if let Ok(Ok(n)) = timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                                        if n > 0 {
                                            let response = String::from_utf8_lossy(&buffer[..n]);
                                            port.service = Some("http".to_string());
                                            if let Some(server_line) = response.lines().find(|line| line.to_lowercase().starts_with("server:")) {
                                                let server = server_line.split(':').nth(1).unwrap_or("").trim();
                                                // Security: Sanitize server banner to prevent injection attacks
                                                port.version = Some(sanitize_banner(server));
                                            }
                                        }
                                    }
                                }
                            }
                            443 => {
                                port.service = Some("https".to_string());
                            }
                            _ => {
                                // Try to guess service name based on port
                                port.service = Some(guess_service(port.number));
                            }
                        }
                    }
                    _ => {
                        // Connection failed, just guess service
                        port.service = Some(guess_service(port.number));
                    }
                }
            }
        }

        debug!("Service detection completed");
        Ok(results)
    }
    
    pub async fn os_detection(&self, targets: &[Host]) -> Result<Vec<Host>> {
        info!("Starting OS detection for {} targets", targets.len());
        warn!("OS detection requires advanced TCP/IP stack fingerprinting - not yet implemented");
        // OS detection would require analyzing TCP window sizes, TTL values,
        // TCP options, ICMP responses, and other OS-specific behavior
        Ok(targets.to_vec())
    }

    pub async fn script_scan(&self, targets: &[Host]) -> Result<Vec<Host>> {
        use nmap_scripting::{ScriptEngine, ScriptContext, ScriptTiming, register_all_scripts};
        use std::collections::HashMap;

        info!("Starting script scan for {} targets", targets.len());

        // Initialize script engine
        let engine = ScriptEngine::new();

        // Register all vulnerability scripts
        if let Err(e) = register_all_scripts(&engine).await {
            warn!("Failed to register scripts: {}", e);
            return Ok(targets.to_vec());
        }

        let mut results = targets.to_vec();

        // Run scripts for each target/port combination
        for host in &mut results {
            for port in &mut host.ports {
                if port.state != nmap_net::PortState::Open {
                    continue;
                }

                // Build script context
                let context = ScriptContext {
                    target_ip: host.address,
                    target_port: Some(port.number),
                    protocol: Some(format!("{:?}", port.protocol)),
                    service: port.service.clone(),
                    version: port.version.clone(),
                    os_info: host.os_info.as_ref().map(|os| os.name.clone()),
                    timing: ScriptTiming::default(),
                    user_args: HashMap::new(),
                };

                // Execute scripts based on service type
                if let Some(ref service) = port.service {
                    info!("Running scripts for {}:{} ({})", host.address, port.number, service);

                    match engine.execute_for_service(service, &context).await {
                        Ok(script_results) => {
                            for result in script_results {
                                if !result.vulnerabilities.is_empty() {
                                    for vuln in &result.vulnerabilities {
                                        info!("VULNERABILITY FOUND on {}:{} - {} ({})",
                                              host.address, port.number,
                                              vuln.title, vuln.severity);
                                    }
                                }
                                debug!("Script result: {}", result.output);
                            }
                        }
                        Err(e) => {
                            warn!("Script execution failed for {}: {}", service, e);
                        }
                    }
                }
            }
        }

        info!("Script scan completed");
        Ok(results)
    }

    pub async fn traceroute(&self, targets: &[Host]) -> Result<()> {
        info!("Starting traceroute for {} targets", targets.len());
        warn!("Traceroute not yet implemented");
        // Traceroute would send packets with incrementing TTL to map network path
        Ok(())
    }
}

/// Guess service name based on well-known port numbers
fn guess_service(port: u16) -> String {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "microsoft-ds",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        5432 => "postgresql",
        8080 => "http-proxy",
        _ => "unknown",
    }.to_string()
}