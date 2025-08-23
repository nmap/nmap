use anyhow::Result;
use nmap_net::Host;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    Normal,
    Xml,
    Grepable,
    Json,
}

pub struct OutputManager {
    formats: Vec<OutputFormat>,
}

impl OutputManager {
    pub fn new(options: &nmap_core::NmapOptions) -> Result<Self> {
        Ok(Self {
            formats: options.output_formats.clone(),
        })
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
        // TODO: Implement XML output
        println!("<!-- XML output not yet implemented -->");
        Ok(())
    }
    
    async fn output_json(&self, results: &[Host]) -> Result<()> {
        let json = serde_json::to_string_pretty(results)?;
        println!("{}", json);
        Ok(())
    }
    
    async fn output_grepable(&self, results: &[Host]) -> Result<()> {
        // TODO: Implement grepable output
        println!("# Grepable output not yet implemented");
        Ok(())
    }
}