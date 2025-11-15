use anyhow::Result;
use clap::{Arg, ArgAction, Command};
use nmap_net::{PortSpec, Host, HostState, Port, Protocol, PortState};
use std::net::IpAddr;
use tokio;
use tracing::{error, info, warn};

// Simple options structure for scanning
#[derive(Clone)]
struct ScanOptions {
    verbose: u8,
    timing_template: u8,
    service_detection: bool,
    os_detection: bool,
    version_detection: bool,
    skip_ping: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let matches = Command::new("rmap")
        .version(env!("CARGO_PKG_VERSION"))
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
                .default_value("1-1000"),
        )
        .arg(
            Arg::new("scan-type")
                .short('s')
                .long("scan-type")
                .help("Scan type")
                .value_name("TYPE")
                .value_parser(["tcp", "syn", "udp", "connect"])
                .default_value("tcp"),
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
            Arg::new("timing")
                .short('T')
                .long("timing")
                .help("Timing template (0-5)")
                .value_name("LEVEL")
                .value_parser(["0", "1", "2", "3", "4", "5"])
                .default_value("3"),
        )
        .arg(
            Arg::new("service-detection")
                .short('A')
                .long("aggressive")
                .help("Enable aggressive scan (service detection, OS detection)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("os-detection")
                .short('O')
                .long("os-detect")
                .help("Enable OS detection")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("version-detection")
                .short('V')
                .long("version-detect")
                .help("Enable version detection")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("ping-scan")
                .short('n')
                .long("no-ping")
                .help("Skip host discovery")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    // Handle help and usage
    if matches.get_many::<String>("targets").is_none() {
        print_banner();
        print_usage();
        return Ok(());
    }

    // Parse arguments
    let mut options = ScanOptions {
        verbose: matches.get_count("verbose") as u8,
        timing_template: matches.get_one::<String>("timing")
            .unwrap()
            .parse::<u8>()
            .unwrap_or(3),
        service_detection: false,
        os_detection: false,
        version_detection: false,
        skip_ping: false,
    };

    if matches.get_flag("service-detection") {
        options.service_detection = true;
        options.os_detection = true;
        options.version_detection = true;
    }

    if matches.get_flag("os-detection") {
        options.os_detection = true;
    }

    if matches.get_flag("version-detection") {
        options.version_detection = true;
    }

    options.skip_ping = matches.get_flag("ping-scan");

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
    let port_spec = PortSpec::parse(matches.get_one::<String>("ports").unwrap())?;

    info!("R-Map {} starting scan", env!("CARGO_PKG_VERSION"));
    info!("Scanning {} targets with {} ports", targets.len(), port_spec.count());

    // Perform scan
    let start_time = std::time::Instant::now();

    // Get scan type from arguments
    let scan_type = matches.get_one::<String>("scan-type").unwrap().as_str();

    info!("R-Map {} starting {} scan", env!("CARGO_PKG_VERSION"), scan_type);
    info!("Scanning {} targets with {} ports", targets.len(), port_spec.count());

    // Perform actual network scanning
    let all_results = match scan_type {
        "syn" => {
            // Check for raw socket privileges
            use nmap_net::check_raw_socket_privileges;
            if !check_raw_socket_privileges() {
                error!("SYN scan requires root/administrator privileges");
                error!("Try running with sudo or use --scan-type connect instead");
                return Err(anyhow::anyhow!("Insufficient privileges for SYN scan"));
            }

            info!("Using TCP SYN scan (requires raw sockets)");
            scan_with_syn(targets, &port_spec, &options).await?
        }
        "tcp" | "connect" => {
            info!("Using TCP connect() scan");
            scan_with_connect(targets, &port_spec, &options).await?
        }
        "udp" => {
            warn!("UDP scanning not yet implemented, falling back to TCP connect");
            scan_with_connect(targets, &port_spec, &options).await?
        }
        _ => {
            error!("Unknown scan type: {}", scan_type);
            return Err(anyhow::anyhow!("Unknown scan type"));
        }
    };

    let scan_duration = start_time.elapsed();

    // Output results
    let output_format = matches.get_one::<String>("output-format").unwrap();
    let output = format_results(&all_results, output_format, scan_duration)?;
    
    if let Some(output_file) = matches.get_one::<String>("output-file") {
        std::fs::write(output_file, &output)?;
        info!("Results written to {}", output_file);
    } else {
        print!("{}", output);
    }

    info!("Scan completed in {:.2}s", scan_duration.as_secs_f64());
    Ok(())
}

fn print_banner() {
    println!("🦀 R-Map {} - Rust Network Mapper", env!("CARGO_PKG_VERSION"));
    println!("https://github.com/Ununp3ntium115/nmap");
    println!();
}

fn print_usage() {
    println!("USAGE:");
    println!("  rmap [OPTIONS] <TARGETS>...");
    println!();
    println!("EXAMPLES:");
    println!("  rmap -v -A scanme.nmap.org");
    println!("  rmap -v -sn 192.168.0.0/16 10.0.0.0/8");
    println!("  rmap -v -iR 10000 -Pn -p 80");
    println!();
    println!("For more help, use: rmap --help");
}

/// Perform SYN scan using raw sockets
async fn scan_with_syn(mut targets: Vec<Host>, port_spec: &PortSpec, options: &NmapOptions) -> Result<Vec<Host>> {
    use nmap_engine::{SynScanner};
    use nmap_timing::TimingConfig;

    // Create timing configuration
    let timing = TimingConfig::from_template(options.timing_template);

    // Create SYN scanner
    let scanner = SynScanner::new(timing)?;

    // Collect ports to scan
    let ports: Vec<u16> = port_spec.ports().collect();

    // Scan all hosts
    scanner.scan_hosts(&mut targets, &ports).await?;

    Ok(targets)
}

/// Perform TCP connect scan (doesn't require raw sockets)
async fn scan_with_connect(mut targets: Vec<Host>, port_spec: &PortSpec, options: &NmapOptions) -> Result<Vec<Host>> {
    use nmap_engine::ConnectScanner;
    use nmap_timing::TimingConfig;

    // Create timing configuration
    let timing = TimingConfig::from_template(options.timing_template);

    // Create connect scanner
    let scanner = ConnectScanner::new(timing);

    // Collect ports to scan
    let ports: Vec<u16> = port_spec.ports().collect();

    // Scan all hosts
    scanner.scan_hosts(&mut targets, &ports).await?;

    Ok(targets)
}

async fn parse_target(target_str: &str) -> Result<Vec<Host>> {
    let mut targets = Vec::new();
    
    // Handle CIDR notation
    if target_str.contains('/') {
        match target_str.parse::<ipnet::IpNet>() {
            Ok(network) => {
                for ip in network.hosts().take(256) { // Limit to prevent huge scans
                    targets.push(Host::new(ip));
                }
            }
            Err(e) => return Err(anyhow::anyhow!("Invalid CIDR notation: {}", e)),
        }
    }
    // Handle IP ranges (e.g., 192.168.1.1-10)
    else if target_str.contains('-') {
        // Simple range parsing for last octet
        if let Some((base, range_end)) = target_str.rsplit_once('-') {
            if let Some((prefix, start_octet)) = base.rsplit_once('.') {
                if let (Ok(start), Ok(end)) = (start_octet.parse::<u8>(), range_end.parse::<u8>()) {
                    for i in start..=end {
                        let ip_str = format!("{}.{}", prefix, i);
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            targets.push(Host::new(ip));
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
            Ok(ip) => targets.push(Host::new(ip)),
            Err(_) => {
                // Try to resolve hostname
                match tokio::net::lookup_host(format!("{}:80", target_str)).await {
                    Ok(mut addrs) => {
                        if let Some(addr) = addrs.next() {
                            targets.push(Host::new(addr.ip()));
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

fn format_results(results: &[Host], format: &str, duration: std::time::Duration) -> Result<String> {
    match format {
        "json" => {
            let json_output = serde_json::json!({
                "scan_info": {
                    "version": env!("CARGO_PKG_VERSION"),
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
            xml.push_str(&format!("<nmaprun scanner=\"rmap\" version=\"{}\">\n", env!("CARGO_PKG_VERSION")));
            
            for host in results {
                xml.push_str(&format!("  <host>\n"));
                xml.push_str(&format!("    <address addr=\"{}\" addrtype=\"ipv4\"/>\n", host.address));
                xml.push_str(&format!("    <status state=\"{:?}\"/>\n", host.state));
                xml.push_str("    <ports>\n");
                
                for port in &host.ports {
                    xml.push_str(&format!(
                        "      <port protocol=\"{:?}\" portid=\"{}\">\n",
                        port.protocol, port.number
                    ));
                    xml.push_str(&format!("        <state state=\"{:?}\"/>\n", port.state));
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
            for host in results {
                let open_ports: Vec<String> = host.ports.iter()
                    .filter(|p| p.state == PortState::Open)
                    .map(|p| format!("{}/{:?}", p.number, p.protocol))
                    .collect();
                
                output.push_str(&format!(
                    "Host: {} ({:?})\tPorts: {}\n",
                    host.address,
                    host.state,
                    open_ports.join(", ")
                ));
            }
            Ok(output)
        }
        _ => {
            // Normal format
            let mut output = String::new();
            output.push_str(&format!("🦀 R-Map {} scan report\n", env!("CARGO_PKG_VERSION")));
            output.push_str(&format!("Scan completed in {:.2}s\n\n", duration.as_secs_f64()));
            
            for host in results {
                output.push_str(&format!("Nmap scan report for {}\n", host.address));
                output.push_str(&format!("Host is {:?}\n", host.state));
                
                let open_ports: Vec<&Port> = host.ports.iter()
                    .filter(|p| p.state == PortState::Open)
                    .collect();
                
                if !open_ports.is_empty() {
                    output.push_str("PORT     STATE SERVICE\n");
                    for port in open_ports {
                        output.push_str(&format!(
                            "{}/{:<5} open  {}\n",
                            port.number,
                            format!("{:?}", port.protocol).to_lowercase(),
                            port.service.as_deref().unwrap_or("unknown")
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