//! Workflow orchestration utilities

use serde::{Deserialize, Serialize};

/// Workflow execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExecutionResult {
    pub success: bool,
    pub steps_completed: usize,
    pub outputs: Vec<serde_json::Value>,
    pub error: Option<String>,
}

/// Workflow context for passing data between steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowContext {
    pub variables: serde_json::Map<String, serde_json::Value>,
}

impl WorkflowContext {
    pub fn new() -> Self {
        Self {
            variables: serde_json::Map::new(),
        }
    }

    pub fn set(&mut self, key: String, value: serde_json::Value) {
        self.variables.insert(key, value);
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.variables.get(key)
    }
}

impl Default for WorkflowContext {
    fn default() -> Self {
        Self::new()
    }
}
