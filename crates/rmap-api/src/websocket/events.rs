// Event utilities and helpers
use crate::models::ScanEvent;

/// Helper to create scan started event
pub fn scan_started_event(scan_id: uuid::Uuid, targets: Vec<String>) -> ScanEvent {
    ScanEvent::ScanStarted { scan_id, targets }
}

/// Helper to create scan completed event
pub fn scan_completed_event(
    scan_id: uuid::Uuid,
    stats: crate::models::ScanStats,
    duration: u64,
) -> ScanEvent {
    ScanEvent::ScanCompleted {
        scan_id,
        stats,
        duration,
    }
}
