//! Unified redb database for PYRO + R-Map + Claude integration
//!
//! Replaces Redis + RethinkDB with a single embedded database.
//!
//! Schema Design:
//! - **scans**: R-Map scan results (UUID → JSON)
//! - **investigations**: PYRO Fire Marshal investigations (UUID → JSON)
//! - **events**: Event stream for real-time updates (Timestamp+UUID → JSON)
//! - **claude_state**: Claude AI agent workflow state (UUID → JSON)
//! - **workflows**: Multi-agent orchestration definitions (UUID → JSON)
//! - **metadata**: Quick lookups and indexes (String → JSON)

use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use thiserror::Error;

/// Database table definitions
const SCANS_TABLE: TableDefinition<&[u8; 16], &str> = TableDefinition::new("scans");
const INVESTIGATIONS_TABLE: TableDefinition<&[u8; 16], &str> = TableDefinition::new("investigations");
const EVENTS_TABLE: TableDefinition<&[u8; 24], &str> = TableDefinition::new("events"); // timestamp(8) + uuid(16)
const CLAUDE_STATE_TABLE: TableDefinition<&[u8; 16], &str> = TableDefinition::new("claude_state");
const WORKFLOWS_TABLE: TableDefinition<&[u8; 16], &str> = TableDefinition::new("workflows");
const METADATA_TABLE: TableDefinition<&str, &str> = TableDefinition::new("metadata");

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Database error: {0}")]
    Redb(#[from] redb::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),
}

pub type Result<T> = std::result::Result<T, DatabaseError>;

/// Unified PYRO + R-Map + Claude database
pub struct PyroDatabase {
    db: Arc<Database>,
}

impl PyroDatabase {
    /// Create or open database at the given path
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = Database::create(path)?;

        // Initialize all tables
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(SCANS_TABLE)?;
            write_txn.open_table(INVESTIGATIONS_TABLE)?;
            write_txn.open_table(EVENTS_TABLE)?;
            write_txn.open_table(CLAUDE_STATE_TABLE)?;
            write_txn.open_table(WORKFLOWS_TABLE)?;
            write_txn.open_table(METADATA_TABLE)?;
        }
        write_txn.commit()?;

        Ok(Self {
            db: Arc::new(db),
        })
    }

    /// Store R-Map scan result
    pub fn store_scan(&self, scan: &ScanRecord) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SCANS_TABLE)?;
            let json = serde_json::to_string(scan)?;
            table.insert(scan.id.as_bytes(), json.as_str())?;

            // Update metadata index
            let mut meta_table = write_txn.open_table(METADATA_TABLE)?;
            let meta_key = format!("scan:{}:target", scan.id);
            meta_table.insert(meta_key.as_str(), scan.target.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieve scan by ID
    pub fn get_scan(&self, id: &Uuid) -> Result<ScanRecord> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SCANS_TABLE)?;

        match table.get(id.as_bytes())? {
            Some(json) => {
                let scan: ScanRecord = serde_json::from_str(json.value())?;
                Ok(scan)
            }
            None => Err(DatabaseError::NotFound(format!("Scan {}", id))),
        }
    }

    /// Store PYRO Fire Marshal investigation
    pub fn store_investigation(&self, investigation: &Investigation) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(INVESTIGATIONS_TABLE)?;
            let json = serde_json::to_string(investigation)?;
            table.insert(investigation.id.as_bytes(), json.as_str())?;

            // Update metadata
            let mut meta_table = write_txn.open_table(METADATA_TABLE)?;
            let meta_key = format!("investigation:{}:level", investigation.id);
            meta_table.insert(meta_key.as_str(), investigation.marshal_level.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieve investigation by ID
    pub fn get_investigation(&self, id: &Uuid) -> Result<Investigation> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(INVESTIGATIONS_TABLE)?;

        match table.get(id.as_bytes())? {
            Some(json) => {
                let inv: Investigation = serde_json::from_str(json.value())?;
                Ok(inv)
            }
            None => Err(DatabaseError::NotFound(format!("Investigation {}", id))),
        }
    }

    /// Publish event to the event stream (replaces Redis pub/sub)
    pub fn publish_event(&self, event: &Event) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(EVENTS_TABLE)?;

            // Create compound key: timestamp(8 bytes) + uuid(16 bytes)
            let mut key = [0u8; 24];
            key[0..8].copy_from_slice(&event.timestamp.timestamp_millis().to_be_bytes());
            key[8..24].copy_from_slice(event.id.as_bytes());

            let json = serde_json::to_string(event)?;
            table.insert(&key, json.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Subscribe to events since a given timestamp (replaces Redis pub/sub)
    pub fn get_events_since(&self, since: DateTime<Utc>, limit: usize) -> Result<Vec<Event>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(EVENTS_TABLE)?;

        let since_millis = since.timestamp_millis();
        let mut events = Vec::new();

        // Iterate through events starting from the timestamp
        for result in table.iter()? {
            let (key, value) = result?;

            // Extract timestamp from key
            let key_bytes = key.value();
            let timestamp_bytes: [u8; 8] = key_bytes[0..8].try_into()
                .map_err(|_| DatabaseError::InvalidData("Invalid event key".into()))?;
            let timestamp = i64::from_be_bytes(timestamp_bytes);

            if timestamp >= since_millis {
                let event: Event = serde_json::from_str(value.value())?;
                events.push(event);

                if events.len() >= limit {
                    break;
                }
            }
        }

        Ok(events)
    }

    /// Store Claude AI agent workflow state
    pub fn store_claude_state(&self, state: &ClaudeWorkflowState) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(CLAUDE_STATE_TABLE)?;
            let json = serde_json::to_string(state)?;
            table.insert(state.workflow_id.as_bytes(), json.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieve Claude workflow state
    pub fn get_claude_state(&self, workflow_id: &Uuid) -> Result<ClaudeWorkflowState> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(CLAUDE_STATE_TABLE)?;

        match table.get(workflow_id.as_bytes())? {
            Some(json) => {
                let state: ClaudeWorkflowState = serde_json::from_str(json.value())?;
                Ok(state)
            }
            None => Err(DatabaseError::NotFound(format!("Workflow {}", workflow_id))),
        }
    }

    /// Store workflow definition
    pub fn store_workflow(&self, workflow: &Workflow) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(WORKFLOWS_TABLE)?;
            let json = serde_json::to_string(workflow)?;
            table.insert(workflow.id.as_bytes(), json.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// List all investigations with optional filter
    pub fn list_investigations(&self, limit: usize) -> Result<Vec<Investigation>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(INVESTIGATIONS_TABLE)?;

        let mut investigations = Vec::new();
        for result in table.iter()?.take(limit) {
            let (_key, value) = result?;
            let inv: Investigation = serde_json::from_str(value.value())?;
            investigations.push(inv);
        }

        Ok(investigations)
    }

    /// Get database statistics
    pub fn stats(&self) -> Result<DatabaseStats> {
        let read_txn = self.db.begin_read()?;

        let scans_count = read_txn.open_table(SCANS_TABLE)?.len()?;
        let investigations_count = read_txn.open_table(INVESTIGATIONS_TABLE)?.len()?;
        let events_count = read_txn.open_table(EVENTS_TABLE)?.len()?;
        let workflows_count = read_txn.open_table(WORKFLOWS_TABLE)?.len()?;

        Ok(DatabaseStats {
            scans: scans_count,
            investigations: investigations_count,
            events: events_count,
            workflows: workflows_count,
        })
    }
}

/// R-Map scan record (enhanced with PYRO metadata)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: Uuid,
    pub investigation_id: Option<Uuid>, // Link to PYRO investigation
    pub scan_type: String, // "port_scan", "service_detect", "os_detect", "comprehensive"
    pub target: String,
    pub timestamp: DateTime<Utc>,
    pub status: String, // "pending", "running", "completed", "failed"
    pub result: serde_json::Value, // JSON-serialized scan results
    pub fire_marshal_metadata: Option<FireMarshalMetadata>,
}

/// PYRO Fire Marshal investigation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Investigation {
    pub id: Uuid,
    pub fire_id: String, // e.g., "FIRE-20251122-001"
    pub marshal_level: String, // "L1", "L2", "L3"
    pub subject: String, // Target/asset being investigated
    pub status: String, // "open", "in_progress", "closed"
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub evidence: Vec<Uuid>, // Linked scan IDs
    pub detonator_results: Vec<serde_json::Value>,
    pub findings: String,
    pub remediation: Option<String>,
    pub claude_workflow_id: Option<Uuid>, // Link to Claude orchestration
}

/// Fire Marshal metadata for Cryptex v2.0 compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FireMarshalMetadata {
    pub marshal_level: String,
    pub cryptex_version: String, // "v2.0"
    pub detonator_triggered: bool,
    pub authorization: String,
    pub legal_review: bool,
}

/// Claude AI workflow state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeWorkflowState {
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub investigation_id: Option<Uuid>,
    pub current_step: usize,
    pub total_steps: usize,
    pub status: String, // "pending", "running", "completed", "failed"
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub context: serde_json::Value, // Workflow-specific state
    pub tools_used: Vec<String>,
}

/// Multi-agent workflow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub steps: Vec<WorkflowStep>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub name: String,
    pub tool: String, // MCP tool name
    pub parameters: serde_json::Value,
    pub depends_on: Vec<usize>, // Step indices this depends on
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub scans: u64,
    pub investigations: u64,
    pub events: u64,
    pub workflows: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_database_creation() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = PyroDatabase::new(&db_path).unwrap();
        let stats = db.stats().unwrap();
        assert_eq!(stats.scans, 0);
    }

    #[test]
    fn test_scan_storage() {
        let dir = tempdir().unwrap();
        let db = PyroDatabase::new(dir.path().join("test.db")).unwrap();

        let scan = ScanRecord {
            id: Uuid::new_v4(),
            investigation_id: None,
            scan_type: "port_scan".to_string(),
            target: "192.168.1.1".to_string(),
            timestamp: Utc::now(),
            status: "completed".to_string(),
            result: serde_json::json!({"ports": [80, 443]}),
            fire_marshal_metadata: None,
        };

        db.store_scan(&scan).unwrap();
        let retrieved = db.get_scan(&scan.id).unwrap();
        assert_eq!(retrieved.target, "192.168.1.1");
    }
}
