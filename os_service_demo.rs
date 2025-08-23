use nmap_core::{NmapOptions, NmapError};
use nmap_engine::{ScanEngine, ScanType};
use nmap_net::{TargetHost, PortSpec};
use nmap_os_detect::{OsDetector, OsDetectionResult};
use nmap_service_detect::{ServiceDetector, ServiceDetectionOptions, VersionDetector};
use nmap_output::{OutputManager, OutputFormat};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use tokio::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    println!("🔍 R-Map - OS Detection and Service Detection Demo");
    println!("====================================================\n");

    // Demo targets - using localhost and common test addresses
    let targets = vec![
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), // localhost
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),   // Google DNS
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),   // Cloudflare DNS
    ];

    for target_ip in targets {
        println!("🎯 Scanning target: {}", target_ip);
        println!("─".repeat(50));
        
        let target = TargetHost::new(target_ip);
        
        // Step 1: Port Discovery
        println!("📡 Step 1: Port Discovery");
        let open_ports = discover_open_ports(&target).await?;
        
        if open_ports.is_empty() {
            println!("   No open ports found on {}\n", target_ip);
            continue;
        }
        
        println!("   Found {} open ports:", open_ports.len());
        for (port, protocol) in &open_ports {
            println!("     {}/{} - open", port, protocol);
        }
        println!();

        // Step 2: Service Detection
        println!("🔧 Step 2: Service Detection");
        let service_results = detect_services(&target, &open_ports).await?;
        println!();

        // Step 3: Version Detection
        println!("📋 Step 3: Version Detection");
        let version_results = detect_versions(&target, &open_ports).await?;
        println!();

        // Step 4: OS Detection
        println!("🖥️  Step 4: OS Detection");
        let os_results = detect_os(&target).await?;
        println!();

        // Step 5: Generate Comprehensive Report
        println!("📊 Step 5: Comprehensive Report");
        generate_report(&target, &open_ports, &service_results, &version_results, &os_results).await?;
        
        println!("\n{}\n", "=".repeat(60));
    }

    println!("✅ Demo completed successfully!");
    Ok(())
}

async fn discover_open_ports(target: &TargetHost) -> Result<Vec<(u16, String)>, Box<dyn std::error::Error>> {
    let start = Instant::now();
    
    // Configure scan options
    let mut options = NmapOptions::default();
    options.scan_type = ScanType::Connect; // Use connect scan for demo
    options.timing_template = 4; // Aggressive timing
    
    // Scan common ports
    let port_spec = PortSpec::parse("22,23,25,53,80,110,143,443,993,995,8080")?;
    let mut engine = ScanEngine::new(options);
    
    let results = engine.scan_ports(target, &port_spec).await?;
    let duration = start.elapsed();
    
    let mut open_ports = Vec::new();
    for result in results {
        if result.state == "open" {
            open_ports.push((result.port, "tcp".to_string()));
        }
    }
    
    println!("   Port scan completed in {:.2}s", duration.as_secs_f64());
    Ok(open_ports)
}

async fn detect_services(
    target: &TargetHost, 
    open_ports: &[(u16, String)]
) -> Result<Vec<nmap_service_detect::ServiceDetectionResult>, Box<dyn std::error::Error>> {
    let start = Instant::now();
    
    let detector = ServiceDetector::new()?;
    let mut results = Vec::new();
    
    for (port, protocol) in open_ports {
        match detector.detect_service(target, *port, protocol).await {
            Ok(result) => {
                if let Some(ref service) = result.service {
                    println!("   {}/{} - {} detected", port, protocol, service.name);
                    if let Some(ref product) = service.product {
                        println!("     Product: {}", product);
                    }
                    if let Some(ref banner) = result.banner {
                        let truncated = if banner.len() > 60 {
                            format!("{}...", &banner[..60])
                        } else {
                            banner.clone()
                        };
                        println!("     Banner: {}", truncated.replace('\n', "\\n"));
                    }
                } else {
                    println!("   {}/{} - service detection failed", port, protocol);
                }
                results.push(result);
            }
            Err(e) => {
                println!("   {}/{} - error: {:?}", port, protocol, e);
            }
        }
    }
    
    let duration = start.elapsed();
    println!("   Service detection completed in {:.2}s", duration.as_secs_f64());
    
    Ok(results)
}

async fn detect_versions(
    target: &TargetHost,
    open_ports: &[(u16, String)]
) -> Result<nmap_service_detect::VersionScanResult, Box<dyn std::error::Error>> {
    let start = Instant::now();
    
    // Configure version detection options
    let options = ServiceDetectionOptions {
        version_intensity: 7,
        version_light: false,
        version_all: false,
        version_trace: false,
        rpc_scan: false,
        timeout: Duration::from_secs(5),
    };
    
    let detector = VersionDetector::new()?.with_options(options);
    let result = detector.scan_version(target, open_ports).await?;
    
    println!("   Detected {} services with version info:", result.detected_services);
    for (port, service) in &result.services {
        print!("     {}/tcp - {}", port, service.name);
        if let Some(ref product) = service.product {
            print!(" {}", product);
            if let Some(ref version) = service.version {
                print!(" {}", version);
            }
        }
        println!(" (confidence: {}%)", service.confidence);
        
        if !service.cpe.is_empty() {
            println!("       CPE: {}", service.cpe.join(", "));
        }
    }
    
    let duration = start.elapsed();
    println!("   Version detection completed in {:.2}s", duration.as_secs_f64());
    
    Ok(result)
}

async fn detect_os(target: &TargetHost) -> Result<Option<OsDetectionResult>, Box<dyn std::error::Error>> {
    let start = Instant::now();
    
    let detector = OsDetector::new()?.with_timeout(Duration::from_secs(10));
    
    match detector.detect_os(target).await {
        Ok(result) => {
            println!("   OS detection successful:");
            
            if result.matches.is_empty() {
                println!("     No OS matches found");
            } else {
                println!("     Top OS matches:");
                for (i, os_match) in result.matches.iter().take(3).enumerate() {
                    println!("       {}. {} ({}% accuracy)", i + 1, os_match.name, os_match.accuracy);
                    
                    if !os_match.os_class.is_empty() {
                        let class = &os_match.os_class[0];
                        println!("          Vendor: {}, Type: {}", class.vendor, class.os_type);
                        if !class.cpe.is_empty() {
                            println!("          CPE: {}", class.cpe[0]);
                        }
                    }
                }
            }
            
            if let Some(ref tcp_seq) = result.tcp_sequence {
                println!("     TCP Sequence: {} ({})", tcp_seq.index, tcp_seq.difficulty);
            }
            
            if let Some(ref ip_id) = result.ip_id_sequence {
                println!("     IP ID Sequence: {}", ip_id.class);
            }
            
            if let Some(uptime) = result.uptime {
                println!("     Uptime: {} seconds", uptime);
            }
            
            let duration = start.elapsed();
            println!("   OS detection completed in {:.2}s", duration.as_secs_f64());
            
            Ok(Some(result))
        }
        Err(e) => {
            println!("   OS detection failed: {:?}", e);
            let duration = start.elapsed();
            println!("   OS detection attempted in {:.2}s", duration.as_secs_f64());
            Ok(None)
        }
    }
}

async fn generate_report(
    target: &TargetHost,
    open_ports: &[(u16, String)],
    _service_results: &[nmap_service_detect::ServiceDetectionResult],
    version_results: &nmap_service_detect::VersionScanResult,
    os_results: &Option<OsDetectionResult>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("   Generating comprehensive scan report...");
    
    // Create output manager
    let mut output_manager = OutputManager::new();
    
    // Generate different output formats
    let formats = vec![
        OutputFormat::Normal,
        OutputFormat::Json,
        OutputFormat::Xml,
    ];
    
    for format in formats {
        let filename = match format {
            OutputFormat::Normal => format!("scan_report_{}.txt", target.ip()),
            OutputFormat::Json => format!("scan_report_{}.json", target.ip()),
            OutputFormat::Xml => format!("scan_report_{}.xml", target.ip()),
            OutputFormat::Grepable => format!("scan_report_{}.gnmap", target.ip()),
        };
        
        // Create mock scan results for output
        let scan_summary = create_scan_summary(target, open_ports, version_results, os_results);
        
        match output_manager.write_results(&scan_summary, &format, &filename).await {
            Ok(_) => println!("     ✓ {} report saved to {}", format_name(&format), filename),
            Err(e) => println!("     ✗ Failed to save {} report: {:?}", format_name(&format), e),
        }
    }
    
    // Display summary statistics
    println!("\n   📈 Scan Summary:");
    println!("     Target: {}", target.ip());
    println!("     Open ports: {}", open_ports.len());
    println!("     Services detected: {}", version_results.detected_services);
    println!("     OS detection: {}", if os_results.is_some() { "Success" } else { "Failed" });
    println!("     Total scan time: {:.2}s", version_results.scan_time.as_secs_f64());
    
    Ok(())
}

fn create_scan_summary(
    target: &TargetHost,
    open_ports: &[(u16, String)],
    version_results: &nmap_service_detect::VersionScanResult,
    os_results: &Option<OsDetectionResult>,
) -> String {
    let mut summary = String::new();
    
    summary.push_str(&format!("R-Map Scan Report for {}\n", target.ip()));
    summary.push_str(&format!("Scan completed at {}\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    
    summary.push_str("PORT STATE SERVICE VERSION\n");
    for (port, protocol) in open_ports {
        summary.push_str(&format!("{}/{} open ", port, protocol));
        
        if let Some(service) = version_results.services.get(port) {
            summary.push_str(&service.name);
            if let Some(ref product) = service.product {
                summary.push_str(&format!(" {}", product));
                if let Some(ref version) = service.version {
                    summary.push_str(&format!(" {}", version));
                }
            }
        } else {
            summary.push_str("unknown");
        }
        summary.push('\n');
    }
    
    if let Some(ref os_result) = os_results {
        summary.push_str("\nOS DETECTION:\n");
        for os_match in &os_result.matches {
            summary.push_str(&format!("  {} ({}% accuracy)\n", os_match.name, os_match.accuracy));
        }
    }
    
    summary.push_str(&format!("\nScan Statistics:\n"));
    summary.push_str(&format!("  Ports scanned: {}\n", open_ports.len()));
    summary.push_str(&format!("  Services detected: {}\n", version_results.detected_services));
    summary.push_str(&format!("  Scan time: {:.2}s\n", version_results.scan_time.as_secs_f64()));
    
    summary
}

fn format_name(format: &OutputFormat) -> &str {
    match format {
        OutputFormat::Normal => "Normal",
        OutputFormat::Json => "JSON",
        OutputFormat::Xml => "XML",
        OutputFormat::Grepable => "Grepable",
    }
}