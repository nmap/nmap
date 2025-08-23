// Advanced Nmap Rust demonstration with real TCP scanning

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy)]
enum ScanType {
    Connect,
    Syn, // Would require raw sockets
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PortState {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone)]
struct Port {
    number: u16,
    state: PortState,
    service: Option<String>,
    response_time: Option<Duration>,
}

#[derive(Debug, Clone)]
struct Host {
    address: IpAddr,
    hostname: Option<String>,
    ports: Vec<Port>,
    scan_time: Duration,
}

#[derive(Debug)]
struct ScanOptions {
    scan_type: ScanType,
    targets: Vec<String>,
    ports: Vec<u16>,
    timeout: Duration,
    verbosity: u8,
    max_concurrent: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            scan_type: ScanType::Connect,
            targets: Vec::new(),
            ports: vec![21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3389, 5900, 8080],
            timeout: Duration::from_millis(3000),
            verbosity: 1,
            max_concurrent: 100,
        }
    }
}

// Service detection based on common ports
fn detect_service(port: u16) -> Option<String> {
    match port {
        21 => Some("ftp".to_string()),
        22 => Some("ssh".to_string()),
        23 => Some("telnet".to_string()),
        25 => Some("smtp".to_string()),
        53 => Some("dns".to_string()),
        80 => Some("http".to_string()),
        110 => Some("pop3".to_string()),
        135 => Some("msrpc".to_string()),
        139 => Some("netbios-ssn".to_string()),
        143 => Some("imap".to_string()),
        443 => Some("https".to_string()),
        993 => Some("imaps".to_string()),
        995 => Some("pop3s".to_string()),
        1723 => Some("pptp".to_string()),
        3389 => Some("ms-wbt-server".to_string()),
        5900 => Some("vnc".to_string()),
        8080 => Some("http-proxy".to_string()),
        _ => None,
    }
}

// Parse command line arguments
fn parse_args(args: &[String]) -> ScanOptions {
    let mut options = ScanOptions::default();
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-sT" => options.scan_type = ScanType::Connect,
            "-sS" => options.scan_type = ScanType::Syn,
            "-v" => options.verbosity += 1,
            "-vv" => options.verbosity += 2,
            arg if arg.starts_with("-p") => {
                let port_spec = if arg.len() > 2 {
                    &arg[2..]
                } else if i + 1 < args.len() {
                    i += 1;
                    &args[i]
                } else {
                    continue;
                };
                
                if let Ok(ports) = parse_port_spec(port_spec) {
                    options.ports = ports;
                }
            }
            arg if arg.starts_with("--timeout=") => {
                if let Ok(ms) = arg[10..].parse::<u64>() {
                    options.timeout = Duration::from_millis(ms);
                }
            }
            arg if !arg.starts_with('-') => {
                options.targets.push(arg.to_string());
            }
            _ => {}
        }
        i += 1;
    }
    
    options
}

// Parse port specification (e.g., "80,443,1000-2000")
fn parse_port_spec(spec: &str) -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    let mut ports = Vec::new();
    
    for part in spec.split(',') {
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                let start: u16 = range[0].parse()?;
                let end: u16 = range[1].parse()?;
                for port in start..=end {
                    ports.push(port);
                }
            }
        } else {
            ports.push(part.parse()?);
        }
    }
    
    Ok(ports)
}

// Parse target specifications
async fn parse_targets(target_specs: &[String]) -> Vec<Host> {
    let mut hosts = Vec::new();
    
    for spec in target_specs {
        // Try to parse as IP address
        if let Ok(ip) = spec.parse::<IpAddr>() {
            hosts.push(Host {
                address: ip,
                hostname: None,
                ports: Vec::new(),
                scan_time: Duration::from_secs(0),
            });
            continue;
        }
        
        // Try to resolve as hostname
        match tokio::net::lookup_host(format!("{}:80", spec)).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    hosts.push(Host {
                        address: addr.ip(),
                        hostname: Some(spec.clone()),
                        ports: Vec::new(),
                        scan_time: Duration::from_secs(0),
                    });
                }
            }
            Err(_) => {
                eprintln!("Warning: Could not resolve hostname: {}", spec);
            }
        }
    }
    
    hosts
}

// TCP Connect scanner
async fn tcp_connect_scan(host: &mut Host, ports: &[u16], options: &ScanOptions) {
    let start_time = Instant::now();
    
    if options.verbosity > 0 {
        println!("Scanning {} ({}) with TCP connect scan", 
                 host.hostname.as_deref().unwrap_or("unknown"),
                 host.address);
    }
    
    let mut tasks = Vec::new();
    
    // Create concurrent connection attempts
    for &port in ports {
        let addr = SocketAddr::new(host.address, port);
        let timeout_duration = options.timeout;
        
        let task = tokio::spawn(async move {
            let start = Instant::now();
            
            match timeout(timeout_duration, TcpStream::connect(addr)).await {
                Ok(Ok(_stream)) => {
                    let response_time = start.elapsed();
                    Port {
                        number: port,
                        state: PortState::Open,
                        service: detect_service(port),
                        response_time: Some(response_time),
                    }
                }
                Ok(Err(e)) => {
                    let state = match e.kind() {
                        std::io::ErrorKind::ConnectionRefused => PortState::Closed,
                        _ => PortState::Filtered,
                    };
                    Port {
                        number: port,
                        state,
                        service: detect_service(port),
                        response_time: None,
                    }
                }
                Err(_) => {
                    // Timeout
                    Port {
                        number: port,
                        state: PortState::Filtered,
                        service: detect_service(port),
                        response_time: None,
                    }
                }
            }
        });
        
        tasks.push(task);
        
        // Limit concurrent connections
        if tasks.len() >= options.max_concurrent {
            let results = futures::future::join_all(tasks).await;
            for result in results {
                if let Ok(port) = result {
                    host.ports.push(port);
                }
            }
            tasks.clear();
        }
    }
    
    // Handle remaining tasks
    if !tasks.is_empty() {
        let results = futures::future::join_all(tasks).await;
        for result in results {
            if let Ok(port) = result {
                host.ports.push(port);
            }
        }
    }
    
    // Sort ports by number
    host.ports.sort_by_key(|p| p.number);
    host.scan_time = start_time.elapsed();
}

// Output results in Nmap-like format
fn output_results(hosts: &[Host], options: &ScanOptions) {
    println!("Starting Nmap-rs scan at {}", chrono::Utc::now().format("%Y-%m-%d %H:%M UTC"));
    println!();
    
    for host in hosts {
        println!("Nmap scan report for {} ({})", 
                 host.hostname.as_deref().unwrap_or("unknown"),
                 host.address);
        
        let open_ports: Vec<_> = host.ports.iter().filter(|p| p.state == PortState::Open).collect();
        let closed_ports: Vec<_> = host.ports.iter().filter(|p| p.state == PortState::Closed).collect();
        let filtered_ports: Vec<_> = host.ports.iter().filter(|p| p.state == PortState::Filtered).collect();
        
        if !open_ports.is_empty() {
            println!("PORT     STATE SERVICE");
            for port in &open_ports {
                let response_info = if let Some(time) = port.response_time {
                    format!(" ({:.0}ms)", time.as_millis())
                } else {
                    String::new()
                };
                
                println!("{}/tcp   open  {}{}",
                         port.number,
                         port.service.as_deref().unwrap_or("unknown"),
                         response_info);
            }
        }
        
        if options.verbosity > 1 {
            if !closed_ports.is_empty() {
                println!("\nClosed ports:");
                for port in &closed_ports {
                    println!("{}/tcp   closed {}", 
                             port.number,
                             port.service.as_deref().unwrap_or("unknown"));
                }
            }
            
            if !filtered_ports.is_empty() {
                println!("\nFiltered ports:");
                for port in &filtered_ports {
                    println!("{}/tcp   filtered {}", 
                             port.number,
                             port.service.as_deref().unwrap_or("unknown"));
                }
            }
        } else {
            // Summary for non-verbose output
            if !closed_ports.is_empty() || !filtered_ports.is_empty() {
                let mut summary = Vec::new();
                if !closed_ports.is_empty() {
                    summary.push(format!("{} closed", closed_ports.len()));
                }
                if !filtered_ports.is_empty() {
                    summary.push(format!("{} filtered", filtered_ports.len()));
                }
                if !summary.is_empty() {
                    println!("Not shown: {} ports", summary.join(", "));
                }
            }
        }
        
        println!("\nNmap done: 1 IP address (1 host up) scanned in {:.2} seconds",
                 host.scan_time.as_secs_f64());
        println!();
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        println!("Nmap-rs - Advanced Rust Network Scanner Demo");
        println!();
        println!("Usage: {} [options] <target>", args[0]);
        println!();
        println!("Scan Types:");
        println!("  -sT                TCP connect() scan");
        println!("  -sS                TCP SYN scan (requires root - not implemented)");
        println!();
        println!("Port Specification:");
        println!("  -p <ports>         Port ranges: -p22,80,443 or -p1-1000");
        println!();
        println!("Output:");
        println!("  -v                 Increase verbosity");
        println!("  -vv                More verbose");
        println!();
        println!("Timing:");
        println!("  --timeout=<ms>     Connection timeout in milliseconds");
        println!();
        println!("Examples:");
        println!("  {} -sT -v scanme.nmap.org", args[0]);
        println!("  {} -p80,443,8080 google.com", args[0]);
        println!("  {} -p1-1000 -vv 127.0.0.1", args[0]);
        return;
    }
    
    let options = parse_args(&args);
    
    if options.targets.is_empty() {
        eprintln!("Error: No targets specified");
        return;
    }
    
    if options.verbosity > 0 {
        println!("Nmap-rs scan initiated with {} targets, {} ports",
                 options.targets.len(), options.ports.len());
        println!("Scan type: {:?}, Timeout: {:?}", options.scan_type, options.timeout);
        println!();
    }
    
    let mut hosts = parse_targets(&options.targets).await;
    
    if hosts.is_empty() {
        eprintln!("Error: No valid targets found");
        return;
    }
    
    // Perform scans
    for host in &mut hosts {
        match options.scan_type {
            ScanType::Connect => {
                tcp_connect_scan(host, &options.ports, &options).await;
            }
            ScanType::Syn => {
                println!("SYN scan requires raw socket privileges (not implemented in demo)");
                println!("Falling back to TCP connect scan...");
                tcp_connect_scan(host, &options.ports, &options).await;
            }
        }
    }
    
    // Output results
    output_results(&hosts, &options);
}

// Add required dependencies for this demo
// In Cargo.toml:
// [dependencies]
// tokio = { version = "1.0", features = ["full"] }
// futures = "0.3"
// chrono = "0.4"