use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::models::{Host, Scan, ScanOptions, Vulnerability};

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

    /// Start a scan (placeholder for actual implementation)
    pub async fn start_scan(&self, scan_id: Uuid) -> Result<()> {
        let mut scans = self.scans.write().await;
        if let Some(scan) = scans.get_mut(&scan_id) {
            scan.start();
            // TODO: Actually run the scan using nmap-engine
        }
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
