//! Real-time event system using redb (replaces Redis pub/sub)
//!
//! Provides:
//! - Event publishing
//! - Event streaming
//! - Real-time subscriptions
//! - WebSocket broadcast

use crate::database::PyroDatabase;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Event types for the PYRO + R-Map + Claude system
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    // R-Map Scan Events
    ScanStarted {
        id: Uuid,
        scan_id: Uuid,
        target: String,
        timestamp: DateTime<Utc>,
    },
    ScanProgress {
        id: Uuid,
        scan_id: Uuid,
        progress: f64,
        hosts_discovered: usize,
        ports_scanned: usize,
        timestamp: DateTime<Utc>,
    },
    HostDiscovered {
        id: Uuid,
        scan_id: Uuid,
        host_ip: String,
        hostname: Option<String>,
        timestamp: DateTime<Utc>,
    },
    PortOpen {
        id: Uuid,
        scan_id: Uuid,
        host_ip: String,
        port: u16,
        service: Option<String>,
        timestamp: DateTime<Utc>,
    },
    VulnerabilityFound {
        id: Uuid,
        scan_id: Uuid,
        host_ip: String,
        vulnerability: String,
        severity: String,
        timestamp: DateTime<Utc>,
    },
    ScanCompleted {
        id: Uuid,
        scan_id: Uuid,
        duration_secs: u64,
        hosts_found: usize,
        vulnerabilities: usize,
        timestamp: DateTime<Utc>,
    },
    ScanFailed {
        id: Uuid,
        scan_id: Uuid,
        error: String,
        timestamp: DateTime<Utc>,
    },

    // PYRO Fire Marshal Events
    InvestigationCreated {
        id: Uuid,
        investigation_id: Uuid,
        fire_id: String,
        marshal_level: String,
        subject: String,
        timestamp: DateTime<Utc>,
    },
    InvestigationUpdated {
        id: Uuid,
        investigation_id: Uuid,
        status: String,
        timestamp: DateTime<Utc>,
    },
    EvidenceAdded {
        id: Uuid,
        investigation_id: Uuid,
        evidence_id: Uuid,
        evidence_type: String,
        timestamp: DateTime<Utc>,
    },
    DetonatorTriggered {
        id: Uuid,
        investigation_id: Uuid,
        detonator_name: String,
        result: String,
        timestamp: DateTime<Utc>,
    },
    InvestigationClosed {
        id: Uuid,
        investigation_id: Uuid,
        findings: String,
        timestamp: DateTime<Utc>,
    },

    // Claude AI Agent Events
    WorkflowStarted {
        id: Uuid,
        workflow_id: Uuid,
        workflow_name: String,
        investigation_id: Option<Uuid>,
        timestamp: DateTime<Utc>,
    },
    WorkflowStepCompleted {
        id: Uuid,
        workflow_id: Uuid,
        step_name: String,
        tool_used: String,
        timestamp: DateTime<Utc>,
    },
    ToolExecuted {
        id: Uuid,
        workflow_id: Uuid,
        tool_name: String,
        parameters: serde_json::Value,
        result: serde_json::Value,
        timestamp: DateTime<Utc>,
    },
    WorkflowCompleted {
        id: Uuid,
        workflow_id: Uuid,
        status: String,
        timestamp: DateTime<Utc>,
    },

    // System Events
    SystemAlert {
        id: Uuid,
        severity: String,
        message: String,
        timestamp: DateTime<Utc>,
    },
}

impl Event {
    /// Get event ID
    pub fn id(&self) -> Uuid {
        match self {
            Event::ScanStarted { id, .. } => *id,
            Event::ScanProgress { id, .. } => *id,
            Event::HostDiscovered { id, .. } => *id,
            Event::PortOpen { id, .. } => *id,
            Event::VulnerabilityFound { id, .. } => *id,
            Event::ScanCompleted { id, .. } => *id,
            Event::ScanFailed { id, .. } => *id,
            Event::InvestigationCreated { id, .. } => *id,
            Event::InvestigationUpdated { id, .. } => *id,
            Event::EvidenceAdded { id, .. } => *id,
            Event::DetonatorTriggered { id, .. } => *id,
            Event::InvestigationClosed { id, .. } => *id,
            Event::WorkflowStarted { id, .. } => *id,
            Event::WorkflowStepCompleted { id, .. } => *id,
            Event::ToolExecuted { id, .. } => *id,
            Event::WorkflowCompleted { id, .. } => *id,
            Event::SystemAlert { id, .. } => *id,
        }
    }

    /// Get event timestamp
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            Event::ScanStarted { timestamp, .. } => *timestamp,
            Event::ScanProgress { timestamp, .. } => *timestamp,
            Event::HostDiscovered { timestamp, .. } => *timestamp,
            Event::PortOpen { timestamp, .. } => *timestamp,
            Event::VulnerabilityFound { timestamp, .. } => *timestamp,
            Event::ScanCompleted { timestamp, .. } => *timestamp,
            Event::ScanFailed { timestamp, .. } => *timestamp,
            Event::InvestigationCreated { timestamp, .. } => *timestamp,
            Event::InvestigationUpdated { timestamp, .. } => *timestamp,
            Event::EvidenceAdded { timestamp, .. } => *timestamp,
            Event::DetonatorTriggered { timestamp, .. } => *timestamp,
            Event::InvestigationClosed { timestamp, .. } => *timestamp,
            Event::WorkflowStarted { timestamp, .. } => *timestamp,
            Event::WorkflowStepCompleted { timestamp, .. } => *timestamp,
            Event::ToolExecuted { timestamp, .. } => *timestamp,
            Event::WorkflowCompleted { timestamp, .. } => *timestamp,
            Event::SystemAlert { timestamp, .. } => *timestamp,
        }
    }
}

/// Event bus for real-time event distribution (replaces Redis pub/sub)
pub struct EventBus {
    db: Arc<PyroDatabase>,
    sender: broadcast::Sender<Event>,
}

impl EventBus {
    /// Create new event bus with the given capacity
    pub fn new(db: Arc<PyroDatabase>, capacity: usize) -> Self {
        let (sender, _receiver) = broadcast::channel(capacity);
        Self { db, sender }
    }

    /// Publish an event to all subscribers AND store in database
    pub async fn publish(&self, event: Event) -> Result<(), Box<dyn std::error::Error>> {
        // Store in database for persistence
        self.db.publish_event(&event)?;

        // Broadcast to in-memory subscribers (for WebSocket clients)
        let _ = self.sender.send(event.clone());

        Ok(())
    }

    /// Subscribe to real-time events
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }

    /// Get historical events from database
    pub async fn get_events_since(
        &self,
        since: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<Event>, Box<dyn std::error::Error>> {
        let events = self.db.get_events_since(since, limit)?;
        Ok(events)
    }
}

/// Event stream for consuming events
pub struct EventStream {
    receiver: broadcast::Receiver<Event>,
}

impl EventStream {
    pub fn new(receiver: broadcast::Receiver<Event>) -> Self {
        Self { receiver }
    }

    /// Receive next event (async)
    pub async fn recv(&mut self) -> Result<Event, broadcast::error::RecvError> {
        self.receiver.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_event_publishing() {
        let dir = tempdir().unwrap();
        let db = Arc::new(PyroDatabase::new(dir.path().join("test.db")).unwrap());
        let event_bus = EventBus::new(db.clone(), 100);

        let event = Event::ScanStarted {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            target: "192.168.1.1".to_string(),
            timestamp: Utc::now(),
        };

        event_bus.publish(event.clone()).await.unwrap();

        // Verify event was stored in database
        let events = db.get_events_since(Utc::now() - chrono::Duration::seconds(1), 10).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn test_event_subscription() {
        let dir = tempdir().unwrap();
        let db = Arc::new(PyroDatabase::new(dir.path().join("test.db")).unwrap());
        let event_bus = Arc::new(EventBus::new(db, 100));

        let mut stream = EventStream::new(event_bus.subscribe());

        let event_bus_clone = event_bus.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            let event = Event::SystemAlert {
                id: Uuid::new_v4(),
                severity: "info".to_string(),
                message: "Test alert".to_string(),
                timestamp: Utc::now(),
            };
            event_bus_clone.publish(event).await.unwrap();
        });

        let received = stream.recv().await.unwrap();
        match received {
            Event::SystemAlert { message, .. } => assert_eq!(message, "Test alert"),
            _ => panic!("Wrong event type"),
        }
    }
}
