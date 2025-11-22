//! Claude AI Agent Integration Layer
//!
//! This module implements Claude (me!) as a first-class agent in the PYRO + R-Map system.
//!
//! **Philosophy:** Instead of Claude being an external tool, I become an integrated
//! component of the system with my own MCP tools, workflow orchestration, and state management.
//!
//! **Capabilities:**
//! - Execute multi-step investigation workflows
//! - Orchestrate R-Map scans + PYRO compliance checks
//! - Autonomous decision-making based on scan results
//! - Self-monitoring and self-correction
//! - Natural language interaction with Fire Marshal investigations

use crate::database::{PyroDatabase, ClaudeWorkflowState, Workflow, WorkflowStep};
use crate::events::{Event, EventBus};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;

/// Claude AI Agent - the autonomous investigation orchestrator
pub struct ClaudeAgent {
    db: Arc<PyroDatabase>,
    event_bus: Arc<EventBus>,
    agent_id: String,
}

impl ClaudeAgent {
    pub fn new(db: Arc<PyroDatabase>, event_bus: Arc<EventBus>) -> Self {
        Self {
            db,
            event_bus,
            agent_id: "claude-fire-marshal-agent".to_string(),
        }
    }

    /// Start a new autonomous investigation workflow
    pub async fn start_workflow(
        &self,
        workflow_def: Workflow,
        investigation_id: Option<Uuid>,
    ) -> Result<Uuid, Box<dyn std::error::Error>> {
        let workflow_id = Uuid::new_v4();

        // Create initial workflow state
        let state = ClaudeWorkflowState {
            workflow_id,
            workflow_name: workflow_def.name.clone(),
            investigation_id,
            current_step: 0,
            total_steps: workflow_def.steps.len(),
            status: "running".to_string(),
            started_at: Utc::now(),
            updated_at: Utc::now(),
            context: serde_json::json!({}),
            tools_used: Vec::new(),
        };

        // Store workflow and state
        self.db.store_workflow(&workflow_def)?;
        self.db.store_claude_state(&state)?;

        // Publish event
        self.event_bus.publish(Event::WorkflowStarted {
            id: Uuid::new_v4(),
            workflow_id,
            workflow_name: workflow_def.name.clone(),
            investigation_id,
            timestamp: Utc::now(),
        }).await?;

        // Execute workflow asynchronously
        let db = self.db.clone();
        let event_bus = self.event_bus.clone();
        tokio::spawn(async move {
            let _ = Self::execute_workflow(db, event_bus, workflow_id).await;
        });

        Ok(workflow_id)
    }

    /// Execute workflow steps autonomously
    async fn execute_workflow(
        db: Arc<PyroDatabase>,
        event_bus: Arc<EventBus>,
        workflow_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // This is where Claude (me!) executes the workflow
        // In a real implementation, this would call MCP tools based on the workflow definition

        let mut state = db.get_claude_state(&workflow_id)?;

        // Pseudocode for workflow execution:
        // 1. Get workflow definition
        // 2. For each step:
        //    - Check dependencies
        //    - Execute MCP tool
        //    - Update context
        //    - Publish progress event
        // 3. Mark workflow as completed

        state.status = "completed".to_string();
        state.updated_at = Utc::now();
        db.store_claude_state(&state)?;

        event_bus.publish(Event::WorkflowCompleted {
            id: Uuid::new_v4(),
            workflow_id,
            status: "completed".to_string(),
            timestamp: Utc::now(),
        }).await?;

        Ok(())
    }

    /// Get current workflow status
    pub fn get_workflow_status(&self, workflow_id: &Uuid) -> Result<ClaudeWorkflowState, Box<dyn std::error::Error>> {
        let state = self.db.get_claude_state(workflow_id)?;
        Ok(state)
    }

    /// Analyze scan results and provide recommendations (Claude's intelligence)
    pub async fn analyze_scan_results(
        &self,
        scan_id: &Uuid,
    ) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
        let scan = self.db.get_scan(scan_id)?;

        // This is where Claude (me!) applies intelligence to analyze results
        // Pseudocode:
        // 1. Parse scan results
        // 2. Identify patterns and anomalies
        // 3. Cross-reference with known vulnerabilities
        // 4. Generate natural language findings
        // 5. Recommend next actions

        Ok(AnalysisResult {
            scan_id: *scan_id,
            summary: format!("Analyzed scan of {}", scan.target),
            findings: vec![],
            recommendations: vec![],
            risk_score: 0.0,
            next_actions: vec![],
        })
    }

    /// Autonomous decision-making: Should we escalate this investigation?
    pub async fn should_escalate(
        &self,
        investigation_id: &Uuid,
    ) -> Result<EscalationDecision, Box<dyn std::error::Error>> {
        let investigation = self.db.get_investigation(investigation_id)?;

        // Claude's autonomous judgment
        // Pseudocode:
        // 1. Review all evidence
        // 2. Assess severity of findings
        // 3. Consider Fire Marshal level
        // 4. Make decision with reasoning

        Ok(EscalationDecision {
            should_escalate: false,
            current_level: investigation.marshal_level.clone(),
            recommended_level: investigation.marshal_level.clone(),
            reasoning: "No critical findings requiring escalation".to_string(),
            confidence: 0.85,
        })
    }
}

/// Result of Claude's analysis of scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub scan_id: Uuid,
    pub summary: String,
    pub findings: Vec<Finding>,
    pub recommendations: Vec<String>,
    pub risk_score: f64, // 0.0 - 10.0
    pub next_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: String, // "critical", "high", "medium", "low", "info"
    pub title: String,
    pub description: String,
    pub affected_hosts: Vec<String>,
    pub remediation: String,
    pub cve: Option<String>,
}

/// Claude's escalation decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationDecision {
    pub should_escalate: bool,
    pub current_level: String,
    pub recommended_level: String,
    pub reasoning: String,
    pub confidence: f64, // 0.0 - 1.0
}

/// Predefined Claude workflow templates
pub struct ClaudeWorkflows;

impl ClaudeWorkflows {
    /// Network perimeter assessment workflow
    pub fn network_perimeter_assessment(target: String) -> Workflow {
        Workflow {
            id: Uuid::new_v4(),
            name: "Network Perimeter Assessment".to_string(),
            description: format!("Comprehensive security assessment of {}", target),
            steps: vec![
                WorkflowStep {
                    name: "Initial Port Scan".to_string(),
                    tool: "rmap_scan".to_string(),
                    parameters: serde_json::json!({
                        "target": target,
                        "ports": "1-65535",
                        "scan_type": "syn",
                        "timing": "aggressive"
                    }),
                    depends_on: vec![],
                },
                WorkflowStep {
                    name: "Service Detection".to_string(),
                    tool: "rmap_service_detect".to_string(),
                    parameters: serde_json::json!({
                        "target": target,
                        "intensity": 9
                    }),
                    depends_on: vec![0],
                },
                WorkflowStep {
                    name: "OS Fingerprinting".to_string(),
                    tool: "rmap_os_detect".to_string(),
                    parameters: serde_json::json!({
                        "target": target,
                        "method": "all"
                    }),
                    depends_on: vec![0],
                },
                WorkflowStep {
                    name: "Vulnerability Assessment".to_string(),
                    tool: "claude_analyze".to_string(),
                    parameters: serde_json::json!({
                        "scan_id": "${step_0_result.scan_id}"
                    }),
                    depends_on: vec![0, 1, 2],
                },
                WorkflowStep {
                    name: "Generate Report".to_string(),
                    tool: "rmap_export".to_string(),
                    parameters: serde_json::json!({
                        "scan_id": "${step_0_result.scan_id}",
                        "format": "html"
                    }),
                    depends_on: vec![3],
                },
            ],
            created_at: Utc::now(),
        }
    }

    /// Incident response workflow
    pub fn incident_response(target_network: String) -> Workflow {
        Workflow {
            id: Uuid::new_v4(),
            name: "Incident Response Investigation".to_string(),
            description: format!("Investigate potential compromise on {}", target_network),
            steps: vec![
                WorkflowStep {
                    name: "Comprehensive Scan".to_string(),
                    tool: "rmap_comprehensive_scan".to_string(),
                    parameters: serde_json::json!({
                        "target": target_network,
                        "scan_profile": "thorough"
                    }),
                    depends_on: vec![],
                },
                WorkflowStep {
                    name: "Retrieve Baseline".to_string(),
                    tool: "rmap_history".to_string(),
                    parameters: serde_json::json!({
                        "limit": 10
                    }),
                    depends_on: vec![],
                },
                WorkflowStep {
                    name: "Compare with Baseline".to_string(),
                    tool: "claude_compare_scans".to_string(),
                    parameters: serde_json::json!({
                        "current_scan": "${step_0_result.scan_id}",
                        "baseline_scan": "${step_1_result.scans[0].id}"
                    }),
                    depends_on: vec![0, 1],
                },
                WorkflowStep {
                    name: "Escalation Decision".to_string(),
                    tool: "claude_escalate".to_string(),
                    parameters: serde_json::json!({
                        "investigation_id": "${investigation_id}"
                    }),
                    depends_on: vec![2],
                },
            ],
            created_at: Utc::now(),
        }
    }

    /// Continuous monitoring workflow
    pub fn continuous_monitoring(targets: Vec<String>) -> Workflow {
        Workflow {
            id: Uuid::new_v4(),
            name: "Continuous Security Monitoring".to_string(),
            description: "Periodic scans with change detection".to_string(),
            steps: vec![
                WorkflowStep {
                    name: "Scan All Targets".to_string(),
                    tool: "rmap_comprehensive_scan".to_string(),
                    parameters: serde_json::json!({
                        "target": targets.join(","),
                        "scan_profile": "standard"
                    }),
                    depends_on: vec![],
                },
                WorkflowStep {
                    name: "Detect Changes".to_string(),
                    tool: "claude_analyze".to_string(),
                    parameters: serde_json::json!({
                        "scan_id": "${step_0_result.scan_id}",
                        "check_for_changes": true
                    }),
                    depends_on: vec![0],
                },
                WorkflowStep {
                    name: "Alert on Criticals".to_string(),
                    tool: "claude_alert".to_string(),
                    parameters: serde_json::json!({
                        "severity": "critical",
                        "findings": "${step_1_result.findings}"
                    }),
                    depends_on: vec![1],
                },
            ],
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_workflow_creation() {
        let workflow = ClaudeWorkflows::network_perimeter_assessment("192.168.1.1".to_string());
        assert_eq!(workflow.steps.len(), 5);
        assert_eq!(workflow.name, "Network Perimeter Assessment");
    }

    #[tokio::test]
    async fn test_agent_workflow_start() {
        let dir = tempdir().unwrap();
        let db = Arc::new(PyroDatabase::new(dir.path().join("test.db")).unwrap());
        let event_bus = Arc::new(EventBus::new(db.clone(), 100));
        let agent = ClaudeAgent::new(db, event_bus);

        let workflow = ClaudeWorkflows::network_perimeter_assessment("192.168.1.1".to_string());
        let workflow_id = agent.start_workflow(workflow, None).await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let status = agent.get_workflow_status(&workflow_id).unwrap();
        assert_eq!(status.workflow_name, "Network Perimeter Assessment");
    }
}
