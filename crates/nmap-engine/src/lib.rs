pub mod syn_scanner;

// Re-export scanners for external use
pub use syn_scanner::{SynScanner, ConnectScanner};

use anyhow::Result;
use nmap_net::{Host, HostState, ScanType, check_raw_socket_privileges};
use tokio::time::{sleep, Duration};
use tracing::{info, debug, warn};

pub struct ScanEngine {
    options: nmap_core::NmapOptions,
    syn_scanner: Option<SynScanner>,
    connect_scanner: ConnectScanner,
}

impl ScanEngine {
    pub fn new(options: &nmap_core::NmapOptions) -> Result<Self> {
        let timing_config = options.timing_template.config();
        
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
        
        let connect_scanner = ConnectScanner::new(timing_config);
        
        Ok(Self {
            options: options.clone(),
            syn_scanner,
            connect_scanner,
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
                                            port.version = Some(banner.trim().to_string());
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
                                            port.version = Some(banner.trim().to_string());
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
                                            port.version = Some(banner.trim().to_string());
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
                                                port.version = Some(server.to_string());
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
        info!("Starting script scan for {} targets", targets.len());
        warn!("Script scanning (RSE) not yet implemented");
        // Script scanning would execute vulnerability checks and additional probes
        Ok(targets.to_vec())
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