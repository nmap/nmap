pub mod syn_scanner;

use anyhow::Result;
use nmap_net::{Host, HostState, ScanType, check_raw_socket_privileges};
use syn_scanner::{SynScanner, ConnectScanner};
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
        
        // Simplified host discovery - just mark all as up for now
        let mut live_hosts = Vec::new();
        for target in targets {
            let mut host = target.clone();
            host.state = HostState::Up;
            live_hosts.push(host);
            
            // Simulate some work
            sleep(Duration::from_millis(10)).await;
        }
        
        debug!("Host discovery completed, {} hosts up", live_hosts.len());
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
        
        // Simplified service detection
        let results = targets.to_vec();
        
        debug!("Service detection completed");
        Ok(results)
    }
    
    pub async fn os_detection(&self, targets: &[Host]) -> Result<Vec<Host>> {
        info!("Starting OS detection for {} targets", targets.len());
        
        // Simplified OS detection
        let results = targets.to_vec();
        
        debug!("OS detection completed");
        Ok(results)
    }
    
    pub async fn script_scan(&self, targets: &[Host]) -> Result<Vec<Host>> {
        info!("Starting script scan for {} targets", targets.len());
        
        // Simplified script scanning
        let results = targets.to_vec();
        
        debug!("Script scan completed");
        Ok(results)
    }
    
    pub async fn traceroute(&self, targets: &[Host]) -> Result<()> {
        info!("Starting traceroute for {} targets", targets.len());
        
        // Simplified traceroute
        sleep(Duration::from_millis(50)).await;
        
        debug!("Traceroute completed");
        Ok(())
    }
}