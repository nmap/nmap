use anyhow::Result;
use nmap_net::Host;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

// Export new modules
pub mod html;
pub mod pdf;
pub mod markdown;
pub mod csv;
pub mod sqlite;

// Re-export public functions
pub use html::generate_html_report;
pub use pdf::generate_pdf_report;
pub use markdown::generate_markdown_report;
pub use csv::{generate_csv_report, generate_csv_summary_report, generate_csv_port_analysis};
pub use sqlite::{generate_sqlite_database, query_scan_summary, query_hosts_by_scan, query_ports_by_host, query_service_stats};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    Normal,
    Xml,
    Grepable,
    Json,
    Html,
    Pdf,
    Markdown,
    Csv,
    CsvSummary,
    CsvPortAnalysis,
    Sqlite,
}

pub struct OutputManager {
    formats: Vec<OutputFormat>,
}

impl OutputManager {
    pub fn new(options: &nmap_core::NmapOptions) -> Result<Self> {
        // Parse output format from options
        let format = match options.output_format.as_str() {
            "xml" => OutputFormat::Xml,
            "json" => OutputFormat::Json,
            "grepable" | "gnmap" => OutputFormat::Grepable,
            "html" => OutputFormat::Html,
            "pdf" => OutputFormat::Pdf,
            "markdown" | "md" => OutputFormat::Markdown,
            "csv" => OutputFormat::Csv,
            "csv-summary" => OutputFormat::CsvSummary,
            "csv-ports" => OutputFormat::CsvPortAnalysis,
            "sqlite" | "db" => OutputFormat::Sqlite,
            _ => OutputFormat::Normal,
        };

        Ok(Self {
            formats: vec![format],
        })
    }

    pub fn with_formats(formats: Vec<OutputFormat>) -> Self {
        Self { formats }
    }
    
    pub async fn start_scan(&self, options: &nmap_core::NmapOptions) -> Result<()> {
        for format in &self.formats {
            match format {
                OutputFormat::Normal => {
                    println!("Starting {} {} ( {} ) at {} UTC",
                             nmap_core::RMAP_NAME,
                             nmap_core::RMAP_VERSION,
                             nmap_core::RMAP_URL,
                             chrono::Utc::now().format("%Y-%m-%d %H:%M"));
                }
                _ => {
                    // TODO: Implement other output formats
                }
            }
        }
        Ok(())
    }
    
    pub async fn output_results(&self, results: &[Host]) -> Result<()> {
        self.output_results_with_duration(results, Duration::from_secs(0)).await
    }

    pub async fn output_results_with_duration(&self, results: &[Host], duration: Duration) -> Result<()> {
        for format in &self.formats {
            match format {
                OutputFormat::Normal => {
                    self.output_normal(results).await?;
                }
                OutputFormat::Xml => {
                    self.output_xml(results).await?;
                }
                OutputFormat::Json => {
                    self.output_json(results).await?;
                }
                OutputFormat::Grepable => {
                    self.output_grepable(results).await?;
                }
                OutputFormat::Html => {
                    let filename = format!("rmap-scan-{}.html", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
                    html::generate_html_report(results, &filename, duration).await?;
                    info!("HTML report generated: {}", filename);
                }
                OutputFormat::Pdf => {
                    let filename = format!("rmap-scan-{}.pdf", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
                    pdf::generate_pdf_report(results, &filename, duration).await?;
                    info!("PDF report generated: {}", filename);
                }
                OutputFormat::Markdown => {
                    let filename = format!("rmap-scan-{}.md", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
                    markdown::generate_markdown_report(results, &filename, duration).await?;
                    info!("Markdown report generated: {}", filename);
                }
                OutputFormat::Csv => {
                    let filename = format!("rmap-scan-{}.csv", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
                    csv::generate_csv_report(results, &filename).await?;
                    info!("CSV report generated: {}", filename);
                }
                OutputFormat::CsvSummary => {
                    let filename = format!("rmap-scan-summary-{}.csv", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
                    csv::generate_csv_summary_report(results, &filename).await?;
                    info!("CSV summary report generated: {}", filename);
                }
                OutputFormat::CsvPortAnalysis => {
                    let filename = format!("rmap-scan-ports-{}.csv", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
                    csv::generate_csv_port_analysis(results, &filename).await?;
                    info!("CSV port analysis generated: {}", filename);
                }
                OutputFormat::Sqlite => {
                    let filename = format!("rmap-scan-{}.db", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
                    sqlite::generate_sqlite_database(results, &filename, duration).await?;
                    info!("SQLite database generated: {}", filename);
                }
            }
        }
        Ok(())
    }
    
    pub async fn finish_scan(&self, duration: Duration) -> Result<()> {
        info!("Scan completed in {:.2} seconds", duration.as_secs_f64());
        Ok(())
    }
    
    async fn output_normal(&self, results: &[Host]) -> Result<()> {
        for host in results {
            println!("Nmap scan report for {} ({})", 
                     host.hostname.as_deref().unwrap_or("unknown"),
                     host.address);
            println!("Host is {:?}", host.state);
            
            if !host.ports.is_empty() {
                println!("PORT     STATE    SERVICE");
                for port in &host.ports {
                    println!("{}/{:<6} {:<8} {}", 
                             port.number,
                             format!("{:?}", port.protocol).to_lowercase(),
                             format!("{:?}", port.state).to_lowercase(),
                             port.service.as_deref().unwrap_or("unknown"));
                }
            }
            println!();
        }
        Ok(())
    }
    
    async fn output_xml(&self, results: &[Host]) -> Result<()> {
        // nmap-compatible XML output format
        println!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        println!("<!DOCTYPE nmaprun>");
        println!("<nmaprun scanner=\"{}\" args=\"{}\" start=\"{}\" version=\"{}\">",
                 nmap_core::RMAP_NAME,
                 std::env::args().collect::<Vec<_>>().join(" "),
                 chrono::Utc::now().timestamp(),
                 nmap_core::RMAP_VERSION);

        println!("  <scaninfo type=\"combined\" protocol=\"tcp\" numservices=\"{}\"/>",
                 results.iter().map(|h| h.ports.len()).sum::<usize>());

        for host in results {
            println!("  <host starttime=\"{}\" endtime=\"{}\">",
                     chrono::Utc::now().timestamp(),
                     chrono::Utc::now().timestamp());
            println!("    <status state=\"{:?}\" reason=\"{}\"/>",
                     host.state,
                     "echo-reply");
            println!("    <address addr=\"{}\" addrtype=\"ipv{}\"/>",
                     host.address,
                     if host.address.is_ipv4() { "4" } else { "6" });

            if let Some(hostname) = &host.hostname {
                println!("    <hostnames>");
                println!("      <hostname name=\"{}\" type=\"PTR\"/>", hostname);
                println!("    </hostnames>");
            }

            if !host.ports.is_empty() {
                println!("    <ports>");
                for port in &host.ports {
                    println!("      <port protocol=\"{:?}\" portid=\"{}\">",
                             format!("{:?}", port.protocol).to_lowercase(),
                             port.number);
                    println!("        <state state=\"{:?}\" reason=\"{}\"/>",
                             format!("{:?}", port.state).to_lowercase(),
                             port.reason.as_deref().unwrap_or("syn-ack"));
                    println!("        <service name=\"{}\" method=\"{}\">",
                             port.service.as_deref().unwrap_or("unknown"),
                             if port.version.is_some() { "probed" } else { "table" });
                    if let Some(version) = &port.version {
                        println!("          <version>{}</version>", version);
                    }
                    println!("        </service>");
                    println!("      </port>");
                }
                println!("    </ports>");
            }

            if let Some(os_info) = &host.os_info {
                println!("    <os>");
                println!("      <osmatch name=\"{}\" accuracy=\"{}\"/>", os_info.name, os_info.accuracy);
                println!("    </os>");
            }

            println!("  </host>");
        }

        println!("  <runstats>");
        println!("    <finished time=\"{}\" timestr=\"{}\" elapsed=\"0\"/>",
                 chrono::Utc::now().timestamp(),
                 chrono::Utc::now().format("%a %b %d %H:%M:%S %Y"));
        println!("    <hosts up=\"{}\" down=\"0\" total=\"{}\"/>",
                 results.len(), results.len());
        println!("  </runstats>");
        println!("</nmaprun>");
        Ok(())
    }
    
    async fn output_json(&self, results: &[Host]) -> Result<()> {
        let json = serde_json::to_string_pretty(results)?;
        println!("{}", json);
        Ok(())
    }
    
    async fn output_grepable(&self, results: &[Host]) -> Result<()> {
        // nmap-compatible grepable output format (-oG)
        println!("# {} {} scan initiated {} as: {}",
                 nmap_core::RMAP_NAME,
                 nmap_core::RMAP_VERSION,
                 chrono::Utc::now().format("%a %b %d %H:%M:%S %Y"),
                 std::env::args().collect::<Vec<_>>().join(" "));

        for host in results {
            let mut line = format!("Host: {} ({})\t",
                                  host.address,
                                  host.hostname.as_deref().unwrap_or(""));

            line.push_str(&format!("Status: {:?}\t", host.state));

            if !host.ports.is_empty() {
                let mut open_ports = Vec::new();
                let mut filtered_ports = Vec::new();
                let mut closed_ports = Vec::new();

                for port in &host.ports {
                    let port_str = format!("{}/{:?}//{}//",
                                          port.number,
                                          format!("{:?}", port.protocol).to_lowercase(),
                                          port.service.as_deref().unwrap_or(""));

                    match port.state {
                        nmap_net::PortState::Open => open_ports.push(port_str),
                        nmap_net::PortState::Filtered => filtered_ports.push(port_str),
                        nmap_net::PortState::Closed => closed_ports.push(port_str),
                        _ => {}
                    }
                }

                if !open_ports.is_empty() {
                    line.push_str(&format!("Ports: {}\t", open_ports.join(", ")));
                }
                if !filtered_ports.is_empty() {
                    line.push_str(&format!("Filtered Ports: {}\t", filtered_ports.join(", ")));
                }
                if !closed_ports.is_empty() {
                    line.push_str(&format!("Closed Ports: {}\t", closed_ports.join(", ")));
                }
            }

            if let Some(os_info) = &host.os_info {
                line.push_str(&format!("OS: {}\t", os_info.name));
            }

            println!("{}", line.trim_end_matches('\t'));
        }

        println!("# {} done at {}: {} IP address ({} host up) scanned",
                 nmap_core::RMAP_NAME,
                 chrono::Utc::now().format("%a %b %d %H:%M:%S %Y"),
                 results.len(),
                 results.len());
        Ok(())
    }
}