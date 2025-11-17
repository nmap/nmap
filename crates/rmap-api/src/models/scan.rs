use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Scan status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Scan type enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    Stealth,      // SYN scan
    Connect,      // TCP Connect
    Udp,          // UDP scan
    Ack,          // ACK scan
    Fin,          // FIN scan
    Null,         // NULL scan
    Xmas,         // Xmas scan
    Comprehensive, // All scan types
}

/// Timing template (T0-T5)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingTemplate {
    pub level: u8, // 0-5
    pub name: String,
}

/// Scan options configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub scan_type: ScanType,
    pub ports: String, // "1-65535", "80,443", "1-1000,8080"
    pub timing: u8,    // 0-5 (T0-T5)
    pub scripts: Vec<String>,
    pub service_detection: bool,
    pub os_detection: bool,
    pub skip_ping: bool,
    pub max_retries: Option<u8>,
    pub timeout: Option<u64>, // seconds
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            scan_type: ScanType::Stealth,
            ports: String::from("1-1000"),
            timing: 3, // T3 (Normal)
            scripts: Vec::new(),
            service_detection: false,
            os_detection: false,
            skip_ping: false,
            max_retries: Some(2),
            timeout: Some(300),
        }
    }
}

/// Scan statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanStats {
    pub hosts_total: usize,
    pub hosts_up: usize,
    pub hosts_down: usize,
    pub ports_scanned: usize,
    pub ports_open: usize,
    pub ports_filtered: usize,
    pub vulnerabilities: usize,
    pub duration: u64, // seconds
}

/// Main scan entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id: Uuid,
    pub status: ScanStatus,
    pub targets: Vec<String>,
    pub options: ScanOptions,
    pub progress: f64, // 0.0 - 100.0
    pub stats: ScanStats,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

impl Scan {
    pub fn new(targets: Vec<String>, options: ScanOptions) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            status: ScanStatus::Pending,
            targets,
            options,
            progress: 0.0,
            stats: ScanStats::default(),
            created_at: now,
            updated_at: now,
            started_at: None,
            completed_at: None,
            error: None,
        }
    }

    pub fn start(&mut self) {
        self.status = ScanStatus::Running;
        self.started_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    pub fn update_progress(&mut self, progress: f64, stats: ScanStats) {
        self.progress = progress.min(100.0).max(0.0);
        self.stats = stats;
        self.updated_at = Utc::now();
    }

    pub fn complete(&mut self) {
        self.status = ScanStatus::Completed;
        self.progress = 100.0;
        self.completed_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    pub fn fail(&mut self, error: String) {
        self.status = ScanStatus::Failed;
        self.error = Some(error);
        self.completed_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    pub fn cancel(&mut self) {
        self.status = ScanStatus::Cancelled;
        self.completed_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }
}

/// Request body for creating a new scan
#[derive(Debug, Deserialize)]
pub struct CreateScanRequest {
    pub targets: Vec<String>,
    #[serde(default)]
    pub options: ScanOptions,
}

/// Response body for scan creation
#[derive(Debug, Serialize)]
pub struct CreateScanResponse {
    pub scan_id: Uuid,
    pub status: ScanStatus,
    pub created_at: DateTime<Utc>,
}

/// Response for listing scans
#[derive(Debug, Serialize)]
pub struct ListScansResponse {
    pub scans: Vec<ScanSummary>,
    pub total: usize,
}

/// Summary of a scan (for list view)
#[derive(Debug, Serialize)]
pub struct ScanSummary {
    pub id: Uuid,
    pub status: ScanStatus,
    pub targets: Vec<String>,
    pub progress: f64,
    pub created_at: DateTime<Utc>,
    pub duration: Option<u64>,
}

impl From<&Scan> for ScanSummary {
    fn from(scan: &Scan) -> Self {
        let duration = match (scan.started_at, scan.completed_at) {
            (Some(start), Some(end)) => Some((end - start).num_seconds() as u64),
            (Some(start), None) => Some((Utc::now() - start).num_seconds() as u64),
            _ => None,
        };

        Self {
            id: scan.id,
            status: scan.status.clone(),
            targets: scan.targets.clone(),
            progress: scan.progress,
            created_at: scan.created_at,
            duration,
        }
    }
}
