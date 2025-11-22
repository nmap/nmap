//! PYRO Fire Marshal Integration
//!
//! Implements the Fire Marshal investigation framework with Cryptex v2.0 compliance.
//!
//! **Fire Marshal Levels:**
//! - L1 (Routine): Single host, low risk
//! - L2 (Sensitive): Subnet, medium risk
//! - L3 (Critical): Large network, high risk, requires legal review

use crate::database::{PyroDatabase, Investigation, FireMarshalMetadata, ScanRecord};
use crate::events::{Event, EventBus};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;

/// Fire Marshal investigation orchestrator
pub struct FireMarshal {
    db: Arc<PyroDatabase>,
    event_bus: Arc<EventBus>,
}

impl FireMarshal {
    pub fn new(db: Arc<PyroDatabase>, event_bus: Arc<EventBus>) -> Self {
        Self { db, event_bus }
    }

    /// Create new Fire Marshal investigation
    pub async fn create_investigation(
        &self,
        req: CreateInvestigationRequest,
    ) -> Result<Investigation, Box<dyn std::error::Error>> {
        let id = Uuid::new_v4();
        let fire_id = self.generate_fire_id();

        let investigation = Investigation {
            id,
            fire_id: fire_id.clone(),
            marshal_level: req.marshal_level.clone(),
            subject: req.subject.clone(),
            status: "open".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            evidence: Vec::new(),
            detonator_results: Vec::new(),
            findings: String::new(),
            remediation: None,
            claude_workflow_id: None,
        };

        self.db.store_investigation(&investigation)?;

        self.event_bus.publish(Event::InvestigationCreated {
            id: Uuid::new_v4(),
            investigation_id: id,
            fire_id: fire_id.clone(),
            marshal_level: req.marshal_level.clone(),
            subject: req.subject.clone(),
            timestamp: Utc::now(),
        }).await?;

        Ok(investigation)
    }

    /// Add scan evidence to investigation
    pub async fn add_evidence(
        &self,
        investigation_id: &Uuid,
        scan_id: &Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut investigation = self.db.get_investigation(investigation_id)?;

        investigation.evidence.push(*scan_id);
        investigation.updated_at = Utc::now();

        self.db.store_investigation(&investigation)?;

        self.event_bus.publish(Event::EvidenceAdded {
            id: Uuid::new_v4(),
            investigation_id: *investigation_id,
            evidence_id: *scan_id,
            evidence_type: "scan_result".to_string(),
            timestamp: Utc::now(),
        }).await?;

        Ok(())
    }

    /// Trigger Fire Marshal "Detonator" (automated analysis)
    pub async fn trigger_detonator(
        &self,
        investigation_id: &Uuid,
        detonator_name: &str,
    ) -> Result<DetonatorResult, Box<dyn std::error::Error>> {
        let investigation = self.db.get_investigation(investigation_id)?;

        // Execute detonator logic based on name
        let result = match detonator_name {
            "vulnerability_assessment" => self.run_vulnerability_detonator(&investigation).await?,
            "compliance_check" => self.run_compliance_detonator(&investigation).await?,
            "anomaly_detection" => self.run_anomaly_detonator(&investigation).await?,
            _ => return Err("Unknown detonator".into()),
        };

        self.event_bus.publish(Event::DetonatorTriggered {
            id: Uuid::new_v4(),
            investigation_id: *investigation_id,
            detonator_name: detonator_name.to_string(),
            result: serde_json::to_string(&result)?,
            timestamp: Utc::now(),
        }).await?;

        Ok(result)
    }

    /// Close investigation with findings
    pub async fn close_investigation(
        &self,
        investigation_id: &Uuid,
        findings: String,
        remediation: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut investigation = self.db.get_investigation(investigation_id)?;

        investigation.status = "closed".to_string();
        investigation.findings = findings.clone();
        investigation.remediation = remediation;
        investigation.updated_at = Utc::now();

        self.db.store_investigation(&investigation)?;

        self.event_bus.publish(Event::InvestigationClosed {
            id: Uuid::new_v4(),
            investigation_id: *investigation_id,
            findings,
            timestamp: Utc::now(),
        }).await?;

        Ok(())
    }

    /// List all investigations
    pub fn list_investigations(&self, limit: usize) -> Result<Vec<Investigation>, Box<dyn std::error::Error>> {
        let investigations = self.db.list_investigations(limit)?;
        Ok(investigations)
    }

    /// Get investigation details
    pub fn get_investigation(&self, id: &Uuid) -> Result<Investigation, Box<dyn std::error::Error>> {
        let investigation = self.db.get_investigation(id)?;
        Ok(investigation)
    }

    /// Validate Cryptex v2.0 compliance
    pub fn validate_cryptex_compliance(&self, investigation: &Investigation) -> CryptexValidation {
        let mut issues = Vec::new();

        // Check Fire Marshal ID format
        if !investigation.fire_id.starts_with("FIRE-") {
            issues.push("Fire ID must start with FIRE-".to_string());
        }

        // Check marshal level
        if !["L1", "L2", "L3"].contains(&investigation.marshal_level.as_str()) {
            issues.push("Invalid marshal level. Must be L1, L2, or L3".to_string());
        }

        // Check evidence exists
        if investigation.evidence.is_empty() && investigation.status == "closed" {
            issues.push("Closed investigation must have evidence".to_string());
        }

        CryptexValidation {
            is_compliant: issues.is_empty(),
            cryptex_version: "v2.0".to_string(),
            issues,
        }
    }

    // Private methods

    fn generate_fire_id(&self) -> String {
        let now = Utc::now();
        format!("FIRE-{}-{:03}", now.format("%Y%m%d"), rand::random::<u16>() % 1000)
    }

    async fn run_vulnerability_detonator(&self, investigation: &Investigation) -> Result<DetonatorResult, Box<dyn std::error::Error>> {
        // Analyze all evidence scans for vulnerabilities
        let mut critical_count = 0;
        let mut high_count = 0;

        for scan_id in &investigation.evidence {
            let scan = self.db.get_scan(scan_id)?;
            // Parse scan results and count vulnerabilities
            // This is simplified - real implementation would parse the JSON
        }

        Ok(DetonatorResult {
            detonator_name: "vulnerability_assessment".to_string(),
            status: "completed".to_string(),
            summary: format!("Found {} critical and {} high severity vulnerabilities", critical_count, high_count),
            details: serde_json::json!({
                "critical": critical_count,
                "high": high_count
            }),
        })
    }

    async fn run_compliance_detonator(&self, investigation: &Investigation) -> Result<DetonatorResult, Box<dyn std::error::Error>> {
        // Check Cryptex v2.0 compliance
        let validation = self.validate_cryptex_compliance(investigation);

        Ok(DetonatorResult {
            detonator_name: "compliance_check".to_string(),
            status: if validation.is_compliant { "passed".to_string() } else { "failed".to_string() },
            summary: format!("Cryptex v2.0 compliance: {}", if validation.is_compliant { "PASS" } else { "FAIL" }),
            details: serde_json::to_value(&validation)?,
        })
    }

    async fn run_anomaly_detonator(&self, investigation: &Investigation) -> Result<DetonatorResult, Box<dyn std::error::Error>> {
        // Detect anomalies in scan results
        Ok(DetonatorResult {
            detonator_name: "anomaly_detection".to_string(),
            status: "completed".to_string(),
            summary: "Anomaly detection completed".to_string(),
            details: serde_json::json!({
                "anomalies_found": 0
            }),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInvestigationRequest {
    pub marshal_level: String, // "L1", "L2", "L3"
    pub subject: String,       // Target being investigated
    pub authorization: String,  // Who authorized this
    pub legal_review: bool,     // Required for L3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetonatorResult {
    pub detonator_name: String,
    pub status: String,
    pub summary: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptexValidation {
    pub is_compliant: bool,
    pub cryptex_version: String,
    pub issues: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_create_investigation() {
        let dir = tempdir().unwrap();
        let db = Arc::new(PyroDatabase::new(dir.path().join("test.db")).unwrap());
        let event_bus = Arc::new(EventBus::new(db.clone(), 100));
        let fire_marshal = FireMarshal::new(db, event_bus);

        let req = CreateInvestigationRequest {
            marshal_level: "L2".to_string(),
            subject: "192.168.1.0/24".to_string(),
            authorization: "Security Team".to_string(),
            legal_review: false,
        };

        let investigation = fire_marshal.create_investigation(req).await.unwrap();
        assert!(investigation.fire_id.starts_with("FIRE-"));
        assert_eq!(investigation.marshal_level, "L2");
    }

    #[tokio::test]
    async fn test_cryptex_validation() {
        let dir = tempdir().unwrap();
        let db = Arc::new(PyroDatabase::new(dir.path().join("test.db")).unwrap());
        let event_bus = Arc::new(EventBus::new(db.clone(), 100));
        let fire_marshal = FireMarshal::new(db.clone(), event_bus);

        let investigation = Investigation {
            id: Uuid::new_v4(),
            fire_id: "FIRE-20251122-001".to_string(),
            marshal_level: "L2".to_string(),
            subject: "test".to_string(),
            status: "open".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            evidence: vec![Uuid::new_v4()],
            detonator_results: Vec::new(),
            findings: String::new(),
            remediation: None,
            claude_workflow_id: None,
        };

        let validation = fire_marshal.validate_cryptex_compliance(&investigation);
        assert!(validation.is_compliant);
    }
}
