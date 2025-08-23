use anyhow::Result;
use clap::{Arg, ArgAction, Command};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
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

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let matches = Command::new("rmap")
        .version("0.1.0")
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
            Arg::new("ports")
                .short('p')
                .long("ports")
                .help("Port specification (e.g., 22,80,443 or 1-1000)")
                .value_name("PORT_SPEC")
                .default_value("22,80,443,8080"),
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
        .get_matches();

    // Handle help and usage
    if matches.get_many::<String>("targets").is_none() {
        print_banner();
        print_usage();
        return Ok(());
    }

    let verbose = matches.get_count("verbose");
    let timeout_secs: u64 = matches.get_one::<String>("timeout").unwrap().parse().unwrap_or(3);
    let service_detection = matches.get_flag("service-detection");

    // Parse targets
    let target_strings: Vec<&String> = matches.get_many::<String>("targets").unwrap().collect();
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

    // Parse ports
    let ports = parse_ports(matches.get_one::<String>("ports").unwrap())?;

    info!("🦀 R-Map 0.1.0 starting scan");
    info!("Scanning {} targets with {} ports", targets.len(), ports.len());

    // Perform scan
    let start_time = Instant::now();
    let mut all_results = Vec::new();

    for target in targets {
        if verbose > 0 {
            info!("Scanning target: {}", target);
        }
        
        let scan_start = Instant::now();
        let mut port_results = Vec::new();

        for &port in &ports {
            let port_result = scan_port(target, port, Duration::from_secs(timeout_secs), service_detection).await;
            port_results.push(port_result);
        }

        let scan_time = scan_start.elapsed().as_secs_f64();
        
        // Try to resolve hostname
        let hostname = if verbose > 1 {
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

    let total_duration = start_time.elapsed();

    // Output results
    let output_format = matches.get_one::<String>("output-format").unwrap();
    let output = format_results(&all_results, output_format, total_duration)?;
    
    if let Some(output_file) = matches.get_one::<String>("output-file") {
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
    println!("  rmap -v -A scanme.nmap.org");
    println!("  rmap -p 22,80,443 192.168.1.1");
    println!("  rmap -o json -f results.json 8.8.8.8");
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
                    "version": "0.1.0",
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