use serde::{Deserialize, Serialize};
use uuid::Uuid;
use super::{Host, Port, Vulnerability, ScanStats, ScanStatus};

/// WebSocket event types for real-time updates
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanEvent {
    /// Scan has started
    ScanStarted {
        scan_id: Uuid,
        targets: Vec<String>,
    },

    /// Scan progress update
    ScanProgress {
        scan_id: Uuid,
        progress: f64,
        stats: ScanStats,
    },

    /// Host discovered
    HostDiscovered {
        scan_id: Uuid,
        host: Host,
    },

    /// Port found open
    PortOpen {
        scan_id: Uuid,
        host: String,
        port: Port,
    },

    /// Service identified
    ServiceIdentified {
        scan_id: Uuid,
        host: String,
        port: u16,
        service: String,
        version: Option<String>,
    },

    /// Vulnerability found
    VulnerabilityFound {
        scan_id: Uuid,
        vulnerability: Vulnerability,
    },

    /// Scan completed
    ScanCompleted {
        scan_id: Uuid,
        stats: ScanStats,
        duration: u64,
    },

    /// Scan failed
    ScanFailed {
        scan_id: Uuid,
        error: String,
    },

    /// Scan cancelled
    ScanCancelled {
        scan_id: Uuid,
    },

    /// Status update message
    StatusUpdate {
        scan_id: Uuid,
        status: ScanStatus,
        message: String,
    },
}

/// WebSocket client message (commands from client)
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Subscribe to scan events
    Subscribe {
        scan_id: Uuid,
    },

    /// Unsubscribe from scan events
    Unsubscribe {
        scan_id: Uuid,
    },

    /// Subscribe to all scans
    SubscribeAll,

    /// Pause a running scan
    PauseScan {
        scan_id: Uuid,
    },

    /// Resume a paused scan
    ResumeScan {
        scan_id: Uuid,
    },

    /// Cancel a scan
    CancelScan {
        scan_id: Uuid,
    },

    /// Ping to keep connection alive
    Ping,
}

/// WebSocket server response
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Event from scan
    Event(ScanEvent),

    /// Acknowledgment of subscription
    Subscribed {
        scan_id: Option<Uuid>,
    },

    /// Acknowledgment of unsubscribe
    Unsubscribed {
        scan_id: Uuid,
    },

    /// Pong response
    Pong,

    /// Error message
    Error {
        message: String,
    },
}
