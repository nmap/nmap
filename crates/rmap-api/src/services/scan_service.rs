use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::net::IpAddr;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::models::{Host, Scan, ScanOptions, ScanType, Vulnerability};
use nmap_engine::ScanEngine;
use nmap_core::NmapOptions as CoreNmapOptions;
use nmap_net::{ScanType as CoreScanType, PortSpec, Host as CoreHost};
use nmap_timing::TimingTemplate;

/// Service for managing scans
pub struct ScanService {
    scans: Arc<RwLock<HashMap<Uuid, Scan>>>,
    hosts: Arc<RwLock<HashMap<Uuid, Host>>>,
    vulnerabilities: Arc<RwLock<HashMap<Uuid, Vulnerability>>>,
}

impl ScanService {
    pub fn new() -> Self {
        Self {
            scans: Arc::new(RwLock::new(HashMap::new())),
            hosts: Arc::new(RwLock::new(HashMap::new())),
            vulnerabilities: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new scan
    pub async fn create_scan(
        &self,
        targets: Vec<String>,
        options: ScanOptions,
    ) -> Result<Scan> {
        let scan = Scan::new(targets, options);
        let scan_id = scan.id;

        let mut scans = self.scans.write().await;
        scans.insert(scan_id, scan.clone());

        Ok(scan)
    }

    /// List all scans
    pub async fn list_scans(&self) -> Result<Vec<Scan>> {
        let scans = self.scans.read().await;
        Ok(scans.values().cloned().collect())
    }

    /// Get a specific scan
    pub async fn get_scan(&self, scan_id: Uuid) -> Result<Option<Scan>> {
        let scans = self.scans.read().await;
        Ok(scans.get(&scan_id).cloned())
    }

    /// Cancel a scan
    pub async fn cancel_scan(&self, scan_id: Uuid) -> Result<()> {
        let mut scans = self.scans.write().await;
        if let Some(scan) = scans.get_mut(&scan_id) {
            scan.cancel();
        }
        Ok(())
    }

    /// Start a scan with actual scanning engine
    pub async fn start_scan(&self, scan_id: Uuid) -> Result<()> {
        // Get scan info and mark as started
        let (targets, options) = {
            let mut scans = self.scans.write().await;
            if let Some(scan) = scans.get_mut(&scan_id) {
                scan.start();
                (scan.targets.clone(), scan.options.clone())
            } else {
                return Err(anyhow::anyhow!("Scan not found"));
            }
        };

        // Clone necessary Arc references for the async task
        let scans_clone = Arc::clone(&self.scans);
        let hosts_clone = Arc::clone(&self.hosts);

        // Spawn async task to run scan
        tokio::spawn(async move {
            // Convert API options to NmapOptions
            let nmap_options = convert_to_nmap_options(&options, &targets);

            // Parse targets to Host objects
            let target_hosts = match parse_targets(&targets).await {
                Ok(hosts) => hosts,
                Err(e) => {
                    tracing::error!("Failed to parse targets: {}", e);
                    let mut scans = scans_clone.write().await;
                    if let Some(scan) = scans.get_mut(&scan_id) {
                        scan.fail(format!("Failed to parse targets: {}", e));
                    }
                    return;
                }
            };

            // Create scan engine
            let engine = match ScanEngine::new(&nmap_options) {
                Ok(engine) => engine,
                Err(e) => {
                    tracing::error!("Failed to create scan engine: {}", e);
                    let mut scans = scans_clone.write().await;
                    if let Some(scan) = scans.get_mut(&scan_id) {
                        scan.fail(format!("Failed to create scan engine: {}", e));
                    }
                    return;
                }
            };

            // Run port scan
            let scanned_hosts = match engine.port_scan(&target_hosts).await {
                Ok(hosts) => hosts,
                Err(e) => {
                    tracing::error!("Port scan failed: {}", e);
                    let mut scans = scans_clone.write().await;
                    if let Some(scan) = scans.get_mut(&scan_id) {
                        scan.fail(format!("Port scan failed: {}", e));
                    }
                    return;
                }
            };

            // Run service detection if enabled
            let scanned_hosts = if options.service_detection {
                match engine.service_detection(&scanned_hosts).await {
                    Ok(hosts) => hosts,
                    Err(e) => {
                        tracing::warn!("Service detection failed: {}", e);
                        scanned_hosts // Continue with what we have
                    }
                }
            } else {
                scanned_hosts
            };

            // Run OS detection if enabled
            let scanned_hosts = if options.os_detection {
                match engine.os_detection(&scanned_hosts).await {
                    Ok(hosts) => hosts,
                    Err(e) => {
                        tracing::warn!("OS detection failed: {}", e);
                        scanned_hosts // Continue with what we have
                    }
                }
            } else {
                scanned_hosts
            };

            // Run vulnerability scripts if enabled
            let scanned_hosts = if !options.scripts.is_empty() {
                match engine.script_scan(&scanned_hosts).await {
                    Ok(hosts) => hosts,
                    Err(e) => {
                        tracing::warn!("Script scan failed: {}", e);
                        scanned_hosts // Continue with what we have
                    }
                }
            } else {
                scanned_hosts
            };

            // Store results and update scan status
            let mut scans = scans_clone.write().await;
            if let Some(scan) = scans.get_mut(&scan_id) {
                // Convert CoreHost to API Host and store
                // TODO: Emit events via EventBus for real-time updates

                scan.complete();
                tracing::info!("Scan {} completed successfully", scan_id);
            }
        });

        Ok(())
    }

    /// Get all hosts for a scan
    pub async fn get_scan_hosts(&self, scan_id: Uuid) -> Result<Vec<Host>> {
        let hosts = self.hosts.read().await;
        Ok(hosts
            .values()
            .filter(|h| h.scan_id == scan_id)
            .cloned()
            .collect())
    }

    /// Get a specific host
    pub async fn get_host(&self, host_id: Uuid) -> Result<Option<Host>> {
        let hosts = self.hosts.read().await;
        Ok(hosts.get(&host_id).cloned())
    }

    /// Get all vulnerabilities for a scan
    pub async fn get_scan_vulnerabilities(&self, scan_id: Uuid) -> Result<Vec<Vulnerability>> {
        let vulns = self.vulnerabilities.read().await;
        Ok(vulns
            .values()
            .filter(|v| v.scan_id == scan_id)
            .cloned()
            .collect())
    }

    /// Add a host to a scan
    pub async fn add_host(&self, host: Host) -> Result<()> {
        let mut hosts = self.hosts.write().await;
        hosts.insert(host.id, host);
        Ok(())
    }

    /// Add a vulnerability
    pub async fn add_vulnerability(&self, vulnerability: Vulnerability) -> Result<()> {
        let mut vulns = self.vulnerabilities.write().await;
        vulns.insert(vulnerability.id, vulnerability);
        Ok(())
    }
}

impl Default for ScanService {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert API ScanOptions to core NmapOptions
fn convert_to_nmap_options(options: &ScanOptions, targets: &[String]) -> CoreNmapOptions {
    let scan_type = match options.scan_type {
        ScanType::Stealth => CoreScanType::Syn,
        ScanType::Connect => CoreScanType::Connect,
        ScanType::Udp => CoreScanType::Udp,
        ScanType::Ack => CoreScanType::Ack,
        ScanType::Fin => CoreScanType::Fin,
        ScanType::Null => CoreScanType::Null,
        ScanType::Xmas => CoreScanType::Xmas,
        ScanType::Comprehensive => CoreScanType::Connect, // Default for comprehensive
    };

    let timing_template = match options.timing {
        0 => TimingTemplate::Paranoid,
        1 => TimingTemplate::Sneaky,
        2 => TimingTemplate::Polite,
        3 => TimingTemplate::Normal,
        4 => TimingTemplate::Aggressive,
        5 => TimingTemplate::Insane,
        _ => TimingTemplate::Normal,
    };

    // Parse port specification
    let port_specs = parse_port_spec(&options.ports);

    CoreNmapOptions {
        targets: targets.to_vec(),
        ports: options.ports.clone(),
        port_specs,
        tcp_scan: matches!(scan_type, CoreScanType::Connect | CoreScanType::Syn),
        syn_scan: matches!(scan_type, CoreScanType::Syn),
        udp_scan: matches!(scan_type, CoreScanType::Udp),
        connect_scan: matches!(scan_type, CoreScanType::Connect),
        scan_types: vec![scan_type],
        skip_ping: options.skip_ping,
        ping_types: vec![],
        service_detection: options.service_detection,
        version_detection: options.service_detection,
        os_detection: options.os_detection,
        verbose: 1,
        debug_level: 0,
        output_format: "normal".to_string(),
        output_file: None,
        timing_template_level: timing_template as u8,
        max_rate: None,
        min_rate: None,
        max_retries: options.max_retries.unwrap_or(2) as u32,
        host_timeout: std::time::Duration::from_secs(options.timeout.unwrap_or(300)),
        scan_delay: std::time::Duration::from_millis(0),
        source_ip: None,
        source_port: None,
        interface: None,
        spoof_mac: None,
        decoys: Vec::new(),
        fragment_packets: false,
        mtu_discovery: false,
        randomize_hosts: false,
        script_scan: !options.scripts.is_empty(),
        scripts: options.scripts.clone(),
        script_args: Vec::new(),
    }
}

/// Parse port specification string into PortSpec vec
fn parse_port_spec(ports: &str) -> Vec<PortSpec> {
    let mut specs = Vec::new();

    for part in ports.split(',') {
        if part.contains('-') {
            let parts: Vec<&str> = part.split('-').collect();
            if parts.len() == 2 {
                if let (Ok(start), Ok(end)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
                    specs.push(PortSpec::Range(start, end));
                }
            }
        } else if let Ok(port) = part.parse::<u16>() {
            specs.push(PortSpec::Single(port));
        }
    }

    if specs.is_empty() {
        specs.push(PortSpec::Range(1, 1000)); // Default
    }

    specs
}

/// Parse target strings to IP addresses
async fn parse_targets(targets: &[String]) -> Result<Vec<CoreHost>> {
    let mut hosts = Vec::new();

    for target in targets {
        // Try to parse as IP first
        if let Ok(ip) = target.parse::<IpAddr>() {
            hosts.push(CoreHost::new(ip));
        } else {
            // Try DNS resolution
            match tokio::net::lookup_host(format!("{}:80", target)).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        let mut host = CoreHost::new(addr.ip());
                        host.hostname = Some(target.clone());
                        hosts.push(host);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to resolve target {}: {}", target, e);
                }
            }
        }
    }

    Ok(hosts)
}
