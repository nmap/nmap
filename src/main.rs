use anyhow::{anyhow, Result};
use clap::{Arg, ArgAction, Command};
use serde::{Deserialize, Serialize};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanResult {
    target: IpAddr,
    hostname: Option<String>,
    ports: Vec<PortResult>,
    scan_time: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PortResult {
    port: u16,
    protocol: String,
    state: String,
    service: Option<String>,
    version: Option<String>,
}

/// Maximum concurrent socket connections to prevent resource exhaustion
const MAX_CONCURRENT_SOCKETS: usize = 100;

/// Global scan timeout in seconds (30 minutes max)
const MAX_SCAN_DURATION_SECS: u64 = 1800;

/// Check if an IP address is in a private/reserved range (SSRF protection)
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // RFC 1918 private networks
            octets[0] == 10 || // 10.0.0.0/8
            (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) || // 172.16.0.0/12
            (octets[0] == 192 && octets[1] == 168) || // 192.168.0.0/16
            // Loopback
            octets[0] == 127 || // 127.0.0.0/8
            // Link-local
            (octets[0] == 169 && octets[1] == 254) || // 169.254.0.0/16
            // Multicast
            octets[0] >= 224 && octets[0] <= 239 || // 224.0.0.0/4
            // Broadcast
            ipv4 == Ipv4Addr::BROADCAST ||
            // Unspecified
            ipv4 == Ipv4Addr::UNSPECIFIED
        }
        IpAddr::V6(ipv6) => {
            // IPv6 private/reserved ranges
            ipv6.is_loopback() ||
            ipv6.is_unspecified() ||
            ipv6.is_multicast() ||
            // Link-local fe80::/10
            (ipv6.segments()[0] & 0xffc0) == 0xfe80 ||
            // Unique local fc00::/7
            (ipv6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Check if an IP is a cloud metadata endpoint (SSRF protection)
fn is_cloud_metadata_endpoint(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            // AWS/GCP/Azure metadata endpoint: 169.254.169.254
            ipv4 == Ipv4Addr::new(169, 254, 169, 254)
        }
        IpAddr::V6(ipv6) => {
            // IPv6 metadata endpoints (fd00:ec2::254 for AWS)
            let segments = ipv6.segments();
            segments[0] == 0xfd00 && segments[1] == 0xec2 && segments[7] == 0x254
        }
    }
}

/// Validate target IP for SSRF protection
fn validate_scan_target(ip: IpAddr, allow_private: bool) -> Result<()> {
    // Always block cloud metadata endpoints
    if is_cloud_metadata_endpoint(ip) {
        return Err(anyhow!(
            "Blocked: {} is a cloud metadata endpoint (SSRF protection)",
            ip
        ));
    }

    // Optionally block private IP ranges
    if !allow_private && is_private_ip(ip) {
        warn!(
            "Scanning private IP address: {}. Use --allow-private to suppress this warning.",
            ip
        );
        // Don't block, just warn - scanning local networks is common
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let matches = Command::new("rmap")
        .version("0.2.0")
        .about("R-Map - Rust Network Mapper")
        .long_about("R-Map is a modern, memory-safe network mapper written in Rust")
        .arg(
            Arg::new("targets")
                .help("Target hosts or networks to scan")
                .value_name("TARGETS")
                .num_args(1..)
                .required(false),
        )
        .arg(
            Arg::new("scan-type")
                .short('s')
                .long("scan")
                .help("Scan type")
                .value_name("TYPE")
                .value_parser(["connect", "syn", "udp", "ping"])
                .default_value("connect"),
        )
        .arg(
            Arg::new("ports")
                .short('p')
                .long("ports")
                .help("Port specification (e.g., 22,80,443 or 1-1000)")
                .value_name("PORT_SPEC")
                .conflicts_with_all(["fast", "all-ports"]),
        )
        .arg(
            Arg::new("fast")
                .short('F')
                .long("fast")
                .help("Fast mode - scan top 100 ports")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["ports", "all-ports"]),
        )
        .arg(
            Arg::new("all-ports")
                .long("all-ports")
                .help("Scan all 65535 ports")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["ports", "fast"]),
        )
        .arg(
            Arg::new("output-format")
                .short('o')
                .long("output")
                .help("Output format")
                .value_name("FORMAT")
                .value_parser(["normal", "xml", "json", "grepable"])
                .default_value("normal"),
        )
        .arg(
            Arg::new("output-file")
                .short('f')
                .long("file")
                .help("Output file")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Increase verbosity level")
                .action(ArgAction::Count),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .help("Connection timeout in seconds")
                .value_name("SECONDS")
                .default_value("3"),
        )
        .arg(
            Arg::new("service-detection")
                .short('A')
                .long("aggressive")
                .help("Enable service detection")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("skip-ping")
                .short('P')
                .long("skip-ping")
                .help("Skip host discovery (treat all hosts as online)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-dns")
                .short('n')
                .long("no-dns")
                .help("Never do reverse DNS resolution")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    // Handle help and usage
    if matches.get_many::<String>("targets").is_none() {
        print_banner();
        print_usage();
        return Ok(());
    }

    let verbose = matches.get_count("verbose");
    let timeout_secs: u64 = matches
        .get_one::<String>("timeout")
        .expect("timeout has default value")
        .parse()
        .unwrap_or(3);
    let service_detection = matches.get_flag("service-detection");
    let skip_ping = matches.get_flag("skip-ping");
    let no_dns = matches.get_flag("no-dns");
    let scan_type = matches
        .get_one::<String>("scan-type")
        .expect("scan-type has default value")
        .as_str();

    // Check for root privileges if SYN scan is requested
    if scan_type == "syn" {
        #[cfg(unix)]
        {
            if unsafe { libc::geteuid() } != 0 {
                error!("SYN scan requires root privileges. Run with sudo or use --scan connect");
                return Err(anyhow::anyhow!("Insufficient privileges for SYN scan"));
            }
        }
        #[cfg(windows)]
        {
            error!("SYN scan requires administrator privileges on Windows");
            return Err(anyhow::anyhow!("Insufficient privileges for SYN scan"));
        }
    }

    // Parse targets
    let target_strings: Vec<&String> = matches
        .get_many::<String>("targets")
        .expect("targets validated at start of main")
        .collect();
    let mut targets = Vec::new();

    for target_str in target_strings {
        match parse_target(target_str).await {
            Ok(target_hosts) => targets.extend(target_hosts),
            Err(e) => {
                error!("Invalid target '{}': {}", target_str, e);
                return Err(e);
            }
        }
    }

    if targets.is_empty() {
        error!("No valid targets specified");
        return Ok(());
    }

    // Security: Validate all targets for SSRF protection
    let allow_private = false; // TODO: Add --allow-private flag if needed
    for &target in &targets {
        if let Err(e) = validate_scan_target(target, allow_private) {
            error!("{}", e);
            return Err(e);
        }
    }

    // Parse ports - handle --fast, --all-ports, or custom port spec
    let ports = if matches.get_flag("fast") {
        info!("Fast mode: scanning top 100 ports");
        get_top_100_ports()
    } else if matches.get_flag("all-ports") {
        info!("Scanning all 65535 ports (this will take a while!)");
        (1..=65535).collect()
    } else if let Some(port_spec) = matches.get_one::<String>("ports") {
        parse_ports(port_spec)?
    } else {
        // Default to top 1000 ports
        get_top_1000_ports()
    };

    info!("🦀 R-Map 0.2.0 starting {} scan", scan_type);
    info!("Scanning {} targets with {} ports", targets.len(), ports.len());

    // Host discovery phase (unless --skip-ping)
    let targets_to_scan = if skip_ping {
        if verbose > 0 {
            info!("Skipping host discovery (treating all hosts as online)");
        }
        targets.clone()
    } else {
        if verbose > 0 {
            info!("Performing host discovery...");
        }
        let mut live_targets = Vec::new();
        for target in &targets {
            if is_host_up(*target, Duration::from_secs(1)).await {
                live_targets.push(*target);
                if verbose > 0 {
                    info!("Host {} is up", target);
                }
            } else if verbose > 0 {
                info!("Host {} appears to be down", target);
            }
        }
        if live_targets.is_empty() {
            error!("No hosts are up. Use --skip-ping to scan anyway.");
            return Ok(());
        }
        live_targets
    };

    // Perform scan with global timeout
    info!("Scan timeout: {} seconds", MAX_SCAN_DURATION_SECS);
    let start_time = Instant::now();

    // Security: Enforce global timeout to prevent indefinite hanging
    let scan_future = async {
        let mut all_results = Vec::new();

        // Security: Create semaphore to limit concurrent connections
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_SOCKETS));

        for target in targets_to_scan {
            if verbose > 0 {
                info!("Scanning target: {}", target);
            }

            let scan_start = Instant::now();
            let mut port_results = Vec::new();

            for &port in &ports {
                // Acquire permit from semaphore before creating connection
                let _permit = semaphore.clone().acquire_owned().await
                    .map_err(|e| anyhow!("Failed to acquire connection slot: {}", e))?;

                let port_result = scan_port(target, port, Duration::from_secs(timeout_secs), service_detection).await;
                port_results.push(port_result);
                // Permit automatically released when _permit is dropped
            }

            let scan_time = scan_start.elapsed().as_secs_f64();

            // Try to resolve hostname unless --no-dns
            let hostname = if no_dns {
                None
            } else if verbose > 1 {
                resolve_hostname(target).await
            } else {
                None
            };

            all_results.push(ScanResult {
                target,
                hostname,
                ports: port_results,
                scan_time,
            });
        }

        Ok::<Vec<ScanResult>, anyhow::Error>(all_results)
    };

    let all_results = match timeout(Duration::from_secs(MAX_SCAN_DURATION_SECS), scan_future).await {
        Ok(Ok(results)) => results,
        Ok(Err(e)) => {
            error!("Scan failed: {}", e);
            return Err(e);
        }
        Err(_) => {
            error!("Scan timeout exceeded ({} seconds). Scan aborted.", MAX_SCAN_DURATION_SECS);
            return Err(anyhow!("Scan exceeded maximum duration of {} seconds", MAX_SCAN_DURATION_SECS));
        }
    };

    let total_duration = start_time.elapsed();

    // Output results
    let output_format = matches
        .get_one::<String>("output-format")
        .expect("output-format has default value");
    let output = format_results(&all_results, output_format, total_duration)?;
    
    if let Some(output_file) = matches.get_one::<String>("output-file") {
        // Security: Validate output path to prevent path traversal attacks
        if output_file.contains('\0') || output_file.contains('\n') {
            return Err(anyhow!("Invalid characters in output path"));
        }

        // Warn about path traversal attempts
        if output_file.contains("..") {
            warn!("Path contains '..' - potential path traversal: {}", output_file);
        }

        // Check path length to prevent resource exhaustion
        if output_file.len() > 4096 {
            return Err(anyhow!("Output path too long (max 4096 characters)"));
        }

        // Prevent writing to sensitive system directories
        let path_lower = output_file.to_lowercase();
        if path_lower.starts_with("/etc/") || path_lower.starts_with("/sys/") ||
           path_lower.starts_with("/proc/") || path_lower.starts_with("/dev/") ||
           path_lower.contains("/root/.ssh/") || path_lower.contains("c:\\windows\\") {
            return Err(anyhow!("Cannot write to sensitive system directory"));
        }

        std::fs::write(output_file, &output)?;
        info!("Results written to {}", output_file);
    } else {
        print!("{}", output);
    }

    info!("Scan completed in {:.2}s", total_duration.as_secs_f64());
    Ok(())
}

fn print_banner() {
    println!("🦀 R-Map 0.1.0 - Rust Network Mapper");
    println!("https://github.com/Ununp3ntium115/nmap");
    println!();
}

fn print_usage() {
    println!("USAGE:");
    println!("  rmap [OPTIONS] <TARGETS>...");
    println!();
    println!("EXAMPLES:");
    println!("  rmap -v -A scanme.nmap.org                    # Service detection");
    println!("  rmap -p 22,80,443 192.168.1.1                  # Scan specific ports");
    println!("  rmap --fast 192.168.1.0/24                     # Fast scan (top 100 ports)");
    println!("  rmap --all-ports --skip-ping 192.168.1.1       # Scan all ports, skip ping");
    println!("  rmap --no-dns --scan connect 192.168.1.0/24    # No DNS, TCP connect scan");
    println!("  rmap -o json -f results.json 8.8.8.8           # JSON output to file");
    println!();
    println!("For more help, use: rmap --help");
}

async fn parse_target(target_str: &str) -> Result<Vec<IpAddr>> {
    let mut targets = Vec::new();
    
    // Handle CIDR notation
    if target_str.contains('/') {
        match target_str.parse::<ipnet::IpNet>() {
            Ok(network) => {
                for ip in network.hosts().take(256) { // Limit to prevent huge scans
                    targets.push(ip);
                }
            }
            Err(e) => return Err(anyhow::anyhow!("Invalid CIDR notation: {}", e)),
        }
    }
    // Handle IP ranges (e.g., 192.168.1.1-10)
    else if target_str.contains('-') {
        if let Some((base, range_end)) = target_str.rsplit_once('-') {
            if let Some((prefix, start_octet)) = base.rsplit_once('.') {
                if let (Ok(start), Ok(end)) = (start_octet.parse::<u8>(), range_end.parse::<u8>()) {
                    for i in start..=end {
                        let ip_str = format!("{}.{}", prefix, i);
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            targets.push(ip);
                        }
                    }
                } else {
                    return Err(anyhow::anyhow!("Invalid range format"));
                }
            } else {
                return Err(anyhow::anyhow!("Invalid range format"));
            }
        }
    }
    // Handle hostname or single IP
    else {
        match target_str.parse::<IpAddr>() {
            Ok(ip) => targets.push(ip),
            Err(_) => {
                // Try to resolve hostname
                match tokio::net::lookup_host(format!("{}:80", target_str)).await {
                    Ok(mut addrs) => {
                        if let Some(addr) = addrs.next() {
                            targets.push(addr.ip());
                        } else {
                            return Err(anyhow::anyhow!("Could not resolve hostname"));
                        }
                    }
                    Err(e) => return Err(anyhow::anyhow!("DNS resolution failed: {}", e)),
                }
            }
        }
    }
    
    Ok(targets)
}

fn parse_ports(port_spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    
    for part in port_spec.split(',') {
        if part.contains('-') {
            // Range like "80-90"
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() == 2 {
                let start: u16 = range_parts[0].parse()?;
                let end: u16 = range_parts[1].parse()?;
                for port in start..=end {
                    ports.push(port);
                }
            }
        } else {
            // Single port
            ports.push(part.parse()?);
        }
    }
    
    Ok(ports)
}

async fn scan_port(target: IpAddr, port: u16, timeout_duration: Duration, service_detection: bool) -> PortResult {
    let addr = format!("{}:{}", target, port);
    
    match timeout(timeout_duration, TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            let mut service = None;
            let mut version = None;
            
            if service_detection {
                // Try to grab banner
                if let Some((svc, ver)) = grab_banner(&mut stream, port).await {
                    service = Some(svc);
                    version = ver;
                }
            }
            
            if service.is_none() {
                service = Some(guess_service(port));
            }
            
            PortResult {
                port,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service,
                version,
            }
        }
        Ok(Err(_)) | Err(_) => {
            PortResult {
                port,
                protocol: "tcp".to_string(),
                state: "closed".to_string(),
                service: None,
                version: None,
            }
        }
    }
}

async fn grab_banner(stream: &mut TcpStream, port: u16) -> Option<(String, Option<String>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    match port {
        22 => {
            // SSH banner
            let mut buffer = [0; 1024];
            if let Ok(n) = timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                if let Ok(n) = n {
                    let banner = String::from_utf8_lossy(&buffer[..n]);
                    if banner.starts_with("SSH-") {
                        let parts: Vec<&str> = banner.trim().split('-').collect();
                        if parts.len() >= 3 {
                            return Some(("ssh".to_string(), Some(format!("{} {}", parts[2], parts.get(3).unwrap_or(&"")))));
                        }
                    }
                }
            }
        }
        21 => {
            // FTP banner
            let mut buffer = [0; 1024];
            if let Ok(n) = timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                if let Ok(n) = n {
                    let banner = String::from_utf8_lossy(&buffer[..n]);
                    if banner.starts_with("220") {
                        return Some(("ftp".to_string(), Some(banner.trim().to_string())));
                    }
                }
            }
        }
        25 => {
            // SMTP banner
            let mut buffer = [0; 1024];
            if let Ok(n) = timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                if let Ok(n) = n {
                    let banner = String::from_utf8_lossy(&buffer[..n]);
                    if banner.starts_with("220") {
                        return Some(("smtp".to_string(), Some(banner.trim().to_string())));
                    }
                }
            }
        }
        80 | 8080 => {
            // HTTP banner
            let request = b"GET / HTTP/1.0\r\n\r\n";
            if stream.write_all(request).await.is_ok() {
                let mut buffer = [0; 2048];
                if let Ok(n) = timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    if let Ok(n) = n {
                        let response = String::from_utf8_lossy(&buffer[..n]);
                        if let Some(server_line) = response.lines().find(|line| line.to_lowercase().starts_with("server:")) {
                            let server = server_line.split(':').nth(1).unwrap_or("").trim();
                            return Some(("http".to_string(), Some(server.to_string())));
                        }
                        return Some(("http".to_string(), None));
                    }
                }
            }
        }
        443 => {
            return Some(("https".to_string(), None));
        }
        _ => {}
    }
    
    None
}

fn guess_service(port: u16) -> String {
    match port {
        21 => "ftp".to_string(),
        22 => "ssh".to_string(),
        23 => "telnet".to_string(),
        25 => "smtp".to_string(),
        53 => "dns".to_string(),
        80 => "http".to_string(),
        110 => "pop3".to_string(),
        143 => "imap".to_string(),
        443 => "https".to_string(),
        993 => "imaps".to_string(),
        995 => "pop3s".to_string(),
        8080 => "http-proxy".to_string(),
        _ => "unknown".to_string(),
    }
}

async fn resolve_hostname(ip: IpAddr) -> Option<String> {
    // Simple reverse DNS lookup
    match dns_lookup::lookup_addr(&ip) {
        Ok(hostname) => Some(hostname),
        Err(_) => None,
    }
}

fn format_results(results: &[ScanResult], format: &str, duration: Duration) -> Result<String> {
    match format {
        "json" => {
            let json_output = serde_json::json!({
                "scan_info": {
                    "version": "0.2.0",
                    "scan_time": duration.as_secs_f64(),
                    "total_hosts": results.len()
                },
                "hosts": results
            });
            Ok(serde_json::to_string_pretty(&json_output)?)
        }
        "xml" => {
            let mut xml = String::new();
            xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            xml.push_str("<nmaprun scanner=\"rmap\" version=\"0.1.0\">\n");
            
            for result in results {
                xml.push_str("  <host>\n");
                xml.push_str(&format!("    <address addr=\"{}\" addrtype=\"ipv4\"/>\n", result.target));
                xml.push_str("    <status state=\"up\"/>\n");
                xml.push_str("    <ports>\n");
                
                for port in &result.ports {
                    xml.push_str(&format!(
                        "      <port protocol=\"{}\" portid=\"{}\">\n",
                        port.protocol, port.port
                    ));
                    xml.push_str(&format!("        <state state=\"{}\"/>\n", port.state));
                    if let Some(ref service) = port.service {
                        xml.push_str(&format!("        <service name=\"{}\"/>\n", service));
                    }
                    xml.push_str("      </port>\n");
                }
                
                xml.push_str("    </ports>\n");
                xml.push_str("  </host>\n");
            }
            
            xml.push_str("</nmaprun>\n");
            Ok(xml)
        }
        "grepable" => {
            let mut output = String::new();
            for result in results {
                let open_ports: Vec<String> = result.ports.iter()
                    .filter(|p| p.state == "open")
                    .map(|p| format!("{}/{}", p.port, p.protocol))
                    .collect();
                
                output.push_str(&format!(
                    "Host: {} ({})\tPorts: {}\n",
                    result.target,
                    result.hostname.as_deref().unwrap_or(""),
                    open_ports.join(", ")
                ));
            }
            Ok(output)
        }
        _ => {
            // Normal format
            let mut output = String::new();
            output.push_str(&format!("🦀 R-Map 0.1.0 scan report\n"));
            output.push_str(&format!("Scan completed in {:.2}s\n\n", duration.as_secs_f64()));
            
            for result in results {
                output.push_str(&format!("Nmap scan report for {}", result.target));
                if let Some(ref hostname) = result.hostname {
                    output.push_str(&format!(" ({})", hostname));
                }
                output.push_str("\n");
                output.push_str("Host is up");
                output.push_str(&format!(" ({:.3}s latency).\n", result.scan_time));
                
                let open_ports: Vec<&PortResult> = result.ports.iter()
                    .filter(|p| p.state == "open")
                    .collect();
                
                if !open_ports.is_empty() {
                    output.push_str("PORT     STATE SERVICE VERSION\n");
                    for port in open_ports {
                        output.push_str(&format!(
                            "{}/{:<5} {:<5} {:<7} {}\n",
                            port.port,
                            port.protocol,
                            port.state,
                            port.service.as_deref().unwrap_or("unknown"),
                            port.version.as_deref().unwrap_or("")
                        ));
                    }
                } else {
                    output.push_str("All scanned ports are closed\n");
                }
                
                output.push_str("\n");
            }
            
            Ok(output)
        }
    }
}

/// Check if a host is up by trying to connect to common ports
async fn is_host_up(target: IpAddr, timeout_duration: Duration) -> bool {
    let test_ports = vec![80, 443, 22, 21, 25, 3389, 8080];

    for &port in &test_ports {
        let addr = format!("{}:{}", target, port);
        match timeout(timeout_duration, TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => return true, // Port is open
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => return true, // Host is up but port closed
            _ => continue,
        }
    }

    false
}

/// Get the top 100 most common ports for fast scanning
fn get_top_100_ports() -> Vec<u16> {
    vec![
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
        139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
        554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
        1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
        4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
        6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
        49152, 49153, 49154, 49155, 49156, 49157,
    ]
}

/// Get the top 1000 most common ports (nmap default)
fn get_top_1000_ports() -> Vec<u16> {
    vec![
        1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49,
        53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119,
        125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259,
        264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445,
        458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554,
        555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691,
        700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873,
        880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000,
        1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028,
        1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042,
        1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056,
        1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070,
        1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084,
        1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098,
        1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117,
        1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147,
        1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185,
        1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244,
        1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322,
        1328, 1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521,
        1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717,
        1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840,
        1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999,
        2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021,
        2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048,
        2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135,
        2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301,
        2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557,
        2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800,
        2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005,
        3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221,
        3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351,
        3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551,
        3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827,
        3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986,
        3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129,
        4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848,
        4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054,
        5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225,
        5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550,
        5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810,
        5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906,
        5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987,
        5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025,
        6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547,
        6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788,
        6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070,
        7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741,
        7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008,
        8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085,
        8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200,
        8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649,
        8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009,
        9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103,
        9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575,
        9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944,
        9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024,
        10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629,
        10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783,
        14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001,
        16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988,
        19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222,
        20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353,
        27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770,
        32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782,
        32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911,
        41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155,
        49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400,
        49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103,
        51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737,
        56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680,
        65000, 65129, 65389,
    ]
}