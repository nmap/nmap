use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Scan result stored in database
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: Uuid,
    pub scan_type: String,
    pub target: String,
    pub timestamp: DateTime<Utc>,
    pub result: String,
}

/// redb table definitions
const SCANS_TABLE: TableDefinition<&[u8; 16], &str> = TableDefinition::new("scans");
const METADATA_TABLE: TableDefinition<&[u8; 16], &str> = TableDefinition::new("metadata");

/// Scan database using redb
pub struct ScanDatabase {
    db: Database,
}

impl ScanDatabase {
    /// Create or open database
    pub fn new(path: PathBuf) -> Result<Self> {
        let db = Database::create(&path)
            .context("Failed to create/open redb database")?;

        // Initialize tables
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(SCANS_TABLE)?;
            let _ = write_txn.open_table(METADATA_TABLE)?;
        }
        write_txn.commit()?;

        Ok(Self { db })
    }

    /// Store scan result
    pub fn store_scan_result(
        &self,
        id: Uuid,
        scan_type: &str,
        target: &str,
        result: &str,
    ) -> Result<()> {
        let scan_result = ScanResult {
            id,
            scan_type: scan_type.to_string(),
            target: target.to_string(),
            timestamp: Utc::now(),
            result: result.to_string(),
        };

        let write_txn = self.db.begin_write()?;
        {
            let mut scans_table = write_txn.open_table(SCANS_TABLE)?;
            let mut metadata_table = write_txn.open_table(METADATA_TABLE)?;

            // Store scan result
            let scan_json = serde_json::to_string(&scan_result)?;
            scans_table.insert(id.as_bytes(), scan_json.as_str())?;

            // Store metadata for quick lookups
            let metadata = serde_json::json!({
                "id": id.to_string(),
                "type": scan_type,
                "target": target,
                "timestamp": scan_result.timestamp.to_rfc3339()
            });
            let metadata_json = serde_json::to_string(&metadata)?;
            metadata_table.insert(id.as_bytes(), metadata_json.as_str())?;
        }
        write_txn.commit()?;

        Ok(())
    }

    /// Get scan result by ID
    pub fn get_scan_result(&self, id: Uuid) -> Result<ScanResult> {
        let read_txn = self.db.begin_read()?;
        let scans_table = read_txn.open_table(SCANS_TABLE)?;

        let scan_json = scans_table
            .get(id.as_bytes())?
            .context("Scan not found")?
            .value();

        let scan_result: ScanResult = serde_json::from_str(scan_json)?;

        Ok(scan_result)
    }

    /// Get scan history (most recent scans)
    pub fn get_scan_history(&self, limit: usize) -> Result<String> {
        let read_txn = self.db.begin_read()?;
        let metadata_table = read_txn.open_table(METADATA_TABLE)?;

        let mut scans: Vec<serde_json::Value> = metadata_table
            .iter()?
            .filter_map(|result| {
                result.ok().and_then(|(_, value)| {
                    serde_json::from_str(value.value()).ok()
                })
            })
            .collect();

        // Sort by timestamp (most recent first)
        scans.sort_by(|a, b| {
            let a_time = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            let b_time = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            b_time.cmp(a_time)
        });

        // Limit results
        scans.truncate(limit);

        // Format output
        let mut output = String::new();
        output.push_str(&format!("Total scans in database: {}\n\n", scans.len()));

        for (i, scan) in scans.iter().enumerate() {
            output.push_str(&format!(
                "{}. {} - {} ({})\n   ID: {}\n\n",
                i + 1,
                scan.get("timestamp").and_then(|v| v.as_str()).unwrap_or("unknown"),
                scan.get("target").and_then(|v| v.as_str()).unwrap_or("unknown"),
                scan.get("type").and_then(|v| v.as_str()).unwrap_or("unknown"),
                scan.get("id").and_then(|v| v.as_str()).unwrap_or("unknown")
            ));
        }

        Ok(output)
    }

    /// Get database statistics
    pub fn get_stats(&self) -> Result<String> {
        let read_txn = self.db.begin_read()?;
        let scans_table = read_txn.open_table(SCANS_TABLE)?;

        let total_scans = scans_table.len()?;

        Ok(format!(
            "Database Statistics\n\
             Total scans: {}\n",
            total_scans
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_database_creation() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let db = ScanDatabase::new(db_path).unwrap();
        assert!(db.get_stats().is_ok());
    }

    #[test]
    fn test_store_and_retrieve() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = ScanDatabase::new(db_path).unwrap();

        let scan_id = Uuid::new_v4();
        db.store_scan_result(
            scan_id,
            "port_scan",
            "192.168.1.1",
            "{\"ports\": [80, 443]}"
        ).unwrap();

        let result = db.get_scan_result(scan_id).unwrap();
        assert_eq!(result.id, scan_id);
        assert_eq!(result.scan_type, "port_scan");
        assert_eq!(result.target, "192.168.1.1");
    }
}
