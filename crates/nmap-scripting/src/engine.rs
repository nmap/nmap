use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// R-Map Scripting Engine (RSE) - Pure Rust replacement for NSE
/// 
/// This provides extensible scripting capabilities without requiring Lua
/// Scripts are implemented as Rust plugins for maximum performance and safety

pub trait Script: Send + Sync {
    /// Script metadata
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn categories(&self) -> Vec<ScriptCategory>;
    fn author(&self) -> &str;
    fn license(&self) -> &str;

    /// Script execution
    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult>;

    /// Script requirements
    fn requires_port(&self) -> bool { false }
    fn requires_service(&self) -> Option<&str> { None }
    fn requires_os(&self) -> bool { false }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScriptCategory {
    Auth,
    Broadcast,
    Brute,
    Default,
    Discovery,
    Dos,
    Exploit,
    External,
    Fuzzer,
    Intrusive,
    Malware,
    Safe,
    Version,
    Vuln,
}

#[derive(Debug, Clone)]
pub struct ScriptContext {
    pub target_ip: std::net::IpAddr,
    pub target_port: Option<u16>,
    pub protocol: Option<String>,
    pub service: Option<String>,
    pub version: Option<String>,
    pub os_info: Option<String>,
    pub timing: ScriptTiming,
    pub user_args: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ScriptTiming {
    pub timeout: std::time::Duration,
    pub max_retries: u32,
    pub delay_between_requests: std::time::Duration,
}

#[derive(Debug, Clone)]
pub struct ScriptResult {
    pub success: bool,
    pub output: String,
    pub structured_data: HashMap<String, serde_json::Value>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub execution_time: std::time::Duration,
}

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub title: String,
    pub severity: VulnerabilitySeverity,
    pub description: String,
    pub references: Vec<String>,
    pub cvss_score: Option<f32>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

pub struct ScriptEngine {
    scripts: Arc<RwLock<HashMap<String, Arc<Box<dyn Script>>>>>,
    categories: Arc<RwLock<HashMap<ScriptCategory, Vec<String>>>>,
}

impl ScriptEngine {
    pub fn new() -> Self {
        Self {
            scripts: Arc::new(RwLock::new(HashMap::new())),
            categories: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_script(&self, script: Box<dyn Script>) -> Result<()> {
        let name = script.name().to_string();
        let categories = script.categories();

        // Wrap in Arc for safe concurrent access
        let script = Arc::new(script);

        // Register script
        {
            let mut scripts = self.scripts.write().await;
            scripts.insert(name.clone(), script);
        }

        // Update category mappings
        {
            let mut cat_map = self.categories.write().await;
            for category in categories {
                cat_map.entry(category).or_insert_with(Vec::new).push(name.clone());
            }
        }

        info!("Registered script: {}", name);
        Ok(())
    }

    pub async fn execute_script(&self, script_name: &str, context: &ScriptContext) -> Result<ScriptResult> {
        // Clone the Arc to the script - this is cheap (just incrementing a reference count)
        // and keeps the script alive for the duration of execution
        let script = {
            let scripts = self.scripts.read().await;
            scripts.get(script_name)
                .ok_or_else(|| anyhow::anyhow!("Script not found: {}", script_name))?
                .clone() // Clone the Arc, not the script itself
        };

        debug!("Executing script: {} on target: {}", script_name, context.target_ip);
        let start_time = std::time::Instant::now();

        let mut result = script.execute(context).await?;
        result.execution_time = start_time.elapsed();

        debug!("Script {} completed in {:?}", script_name, result.execution_time);
        Ok(result)
    }

    pub async fn execute_category(&self, category: ScriptCategory, context: &ScriptContext) -> Result<Vec<ScriptResult>> {
        let script_names = {
            let categories = self.categories.read().await;
            categories.get(&category).cloned().unwrap_or_default()
        };

        let mut results = Vec::new();
        for script_name in script_names {
            match self.execute_script(&script_name, context).await {
                Ok(result) => results.push(result),
                Err(e) => warn!("Script {} failed: {}", script_name, e),
            }
        }

        Ok(results)
    }

    pub async fn list_scripts(&self) -> Vec<String> {
        let scripts = self.scripts.read().await;
        scripts.keys().cloned().collect()
    }

    pub async fn list_categories(&self) -> Vec<ScriptCategory> {
        let categories = self.categories.read().await;
        categories.keys().cloned().collect()
    }
}

impl Default for ScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ScriptTiming {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(30),
            max_retries: 3,
            delay_between_requests: std::time::Duration::from_millis(100),
        }
    }
}

impl ScriptResult {
    pub fn success(output: String) -> Self {
        Self {
            success: true,
            output,
            structured_data: HashMap::new(),
            vulnerabilities: Vec::new(),
            execution_time: std::time::Duration::default(),
        }
    }

    pub fn failure(error: String) -> Self {
        Self {
            success: false,
            output: error,
            structured_data: HashMap::new(),
            vulnerabilities: Vec::new(),
            execution_time: std::time::Duration::default(),
        }
    }

    pub fn with_vulnerability(mut self, vuln: Vulnerability) -> Self {
        self.vulnerabilities.push(vuln);
        self
    }

    pub fn with_data(mut self, key: String, value: serde_json::Value) -> Self {
        self.structured_data.insert(key, value);
        self
    }
}

impl std::fmt::Display for VulnerabilitySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnerabilitySeverity::Critical => write!(f, "CRITICAL"),
            VulnerabilitySeverity::High => write!(f, "HIGH"),
            VulnerabilitySeverity::Medium => write!(f, "MEDIUM"),
            VulnerabilitySeverity::Low => write!(f, "LOW"),
            VulnerabilitySeverity::Info => write!(f, "INFO"),
        }
    }
}

impl std::fmt::Display for ScriptCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptCategory::Auth => write!(f, "auth"),
            ScriptCategory::Broadcast => write!(f, "broadcast"),
            ScriptCategory::Brute => write!(f, "brute"),
            ScriptCategory::Default => write!(f, "default"),
            ScriptCategory::Discovery => write!(f, "discovery"),
            ScriptCategory::Dos => write!(f, "dos"),
            ScriptCategory::Exploit => write!(f, "exploit"),
            ScriptCategory::External => write!(f, "external"),
            ScriptCategory::Fuzzer => write!(f, "fuzzer"),
            ScriptCategory::Intrusive => write!(f, "intrusive"),
            ScriptCategory::Malware => write!(f, "malware"),
            ScriptCategory::Safe => write!(f, "safe"),
            ScriptCategory::Version => write!(f, "version"),
            ScriptCategory::Vuln => write!(f, "vuln"),
        }
    }
}