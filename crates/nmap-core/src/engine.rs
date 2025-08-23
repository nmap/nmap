use crate::{NmapOptions, Result};
// use nmap_engine::ScanEngine; // Removed to avoid circular dependency
use nmap_output::OutputManager;
use nmap_targets::TargetManager;
use tracing::{info, debug, error};
use tokio::time::Instant;

/// Main Nmap engine that orchestrates the scanning process
pub struct NmapEngine {
    options: NmapOptions,
    target_manager: TargetManager,
    scan_engine: ScanEngine,
    output_manager: OutputManager,
    start_time: Instant,
}

impl NmapEngine {
    pub fn new(mut options: NmapOptions) -> Result<Self> {
        // Validate and adjust options
        options.validate()?;
        
        info!("Starting {} {} ( {} )", 
              crate::NMAP_NAME, 
              crate::NMAP_VERSION, 
              crate::NMAP_URL);
        
        let target_manager = TargetManager::new(&options)?;
        let scan_engine = ScanEngine::new(&options)?;
        let output_manager = OutputManager::new(&options)?;
        
        Ok(Self {
            options,
            target_manager,
            scan_engine,
            output_manager,
            start_time: Instant::now(),
        })
    }
    
    pub async fn run(&mut self) -> Result<()> {
        debug!("Nmap engine starting scan");
        
        // Initialize output
        self.output_manager.start_scan(&self.options).await?;
        
        // Discover and prepare targets
        let targets = self.target_manager.discover_targets().await?;
        info!("Nmap scan report for {} targets", targets.len());
        
        if targets.is_empty() {
            error!("No targets specified or found");
            return Ok(());
        }
        
        // Perform host discovery if needed
        let live_targets = if self.options.ping_types.is_empty() {
            targets // Skip host discovery
        } else {
            self.scan_engine.host_discovery(&targets).await?
        };
        
        info!("Found {} live targets", live_targets.len());
        
        // Perform port scanning
        let scan_results = self.scan_engine.port_scan(&live_targets).await?;
        
        // Perform service detection if requested
        let service_results = if self.options.version_detection {
            self.scan_engine.service_detection(&scan_results).await?
        } else {
            scan_results
        };
        
        // Perform OS detection if requested
        let os_results = if self.options.os_detection {
            self.scan_engine.os_detection(&service_results).await?
        } else {
            service_results
        };
        
        // Run NSE scripts if requested
        let final_results = if self.options.script_scan {
            self.scan_engine.script_scan(&os_results).await?
        } else {
            os_results
        };
        
        // Perform traceroute if requested
        if self.options.traceroute {
            self.scan_engine.traceroute(&final_results).await?;
        }
        
        // Output results
        self.output_manager.output_results(&final_results).await?;
        
        // Finalize output
        self.output_manager.finish_scan(self.start_time.elapsed()).await?;
        
        info!("Nmap done: {} IP addresses ({} hosts up) scanned in {:.2} seconds",
              targets.len(),
              live_targets.len(),
              self.start_time.elapsed().as_secs_f64());
        
        Ok(())
    }
}