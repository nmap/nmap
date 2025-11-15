use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Timing template enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingTemplate {
    /// T0 - Paranoid (very slow, for IDS evasion)
    Paranoid,
    /// T1 - Sneaky (slow, for IDS evasion)
    Sneaky,
    /// T2 - Polite (slow, uses less bandwidth)
    Polite,
    /// T3 - Normal (default timing)
    Normal,
    /// T4 - Aggressive (fast, assumes reliable network)
    Aggressive,
    /// T5 - Insane (very fast, may miss results)
    Insane,
}

/// Timing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingConfig {
    pub template: TimingTemplate,
    pub min_rtt_timeout: Duration,
    pub max_rtt_timeout: Duration,
    pub initial_rtt_timeout: Duration,
    pub max_retries: u32,
    pub scan_delay: Duration,
    pub max_scan_delay: Duration,
    pub min_parallelism: u32,
    pub max_parallelism: u32,
    pub min_hostgroup: u32,
    pub max_hostgroup: u32,
    pub min_rate: Option<f64>,
    pub max_rate: Option<f64>,
}

impl TimingTemplate {
    /// Get the timing configuration for this template
    pub fn config(&self) -> TimingConfig {
        match self {
            TimingTemplate::Paranoid => TimingConfig {
                template: *self,
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(300),
                initial_rtt_timeout: Duration::from_secs(5),
                max_retries: 10,
                scan_delay: Duration::from_secs(5),
                max_scan_delay: Duration::from_secs(10),
                min_parallelism: 1,
                max_parallelism: 1,
                min_hostgroup: 1,
                max_hostgroup: 1,
                min_rate: None,
                max_rate: None,
            },
            TimingTemplate::Sneaky => TimingConfig {
                template: *self,
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(15),
                initial_rtt_timeout: Duration::from_secs(2),
                max_retries: 10,
                scan_delay: Duration::from_millis(15000),
                max_scan_delay: Duration::from_secs(15),
                min_parallelism: 1,
                max_parallelism: 1,
                min_hostgroup: 1,
                max_hostgroup: 1,
                min_rate: None,
                max_rate: None,
            },
            TimingTemplate::Polite => TimingConfig {
                template: *self,
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                initial_rtt_timeout: Duration::from_millis(1000),
                max_retries: 10,
                scan_delay: Duration::from_millis(400),
                max_scan_delay: Duration::from_secs(1),
                min_parallelism: 1,
                max_parallelism: 1,
                min_hostgroup: 1,
                max_hostgroup: 50,
                min_rate: None,
                max_rate: None,
            },
            TimingTemplate::Normal => TimingConfig {
                template: *self,
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                initial_rtt_timeout: Duration::from_millis(1000),
                max_retries: 10,
                scan_delay: Duration::from_millis(0),
                max_scan_delay: Duration::from_millis(1000),
                min_parallelism: 1,
                max_parallelism: 36,
                min_hostgroup: 1,
                max_hostgroup: 50,
                min_rate: None,
                max_rate: None,
            },
            TimingTemplate::Aggressive => TimingConfig {
                template: *self,
                min_rtt_timeout: Duration::from_millis(50),
                max_rtt_timeout: Duration::from_millis(1250),
                initial_rtt_timeout: Duration::from_millis(500),
                max_retries: 6,
                scan_delay: Duration::from_millis(0),
                max_scan_delay: Duration::from_millis(10),
                min_parallelism: 1,
                max_parallelism: 100,
                min_hostgroup: 1,
                max_hostgroup: 100,
                min_rate: None,
                max_rate: None,
            },
            TimingTemplate::Insane => TimingConfig {
                template: *self,
                min_rtt_timeout: Duration::from_millis(50),
                max_rtt_timeout: Duration::from_millis(300),
                initial_rtt_timeout: Duration::from_millis(250),
                max_retries: 2,
                scan_delay: Duration::from_millis(0),
                max_scan_delay: Duration::from_millis(5),
                min_parallelism: 1,
                max_parallelism: 300,
                min_hostgroup: 1,
                max_hostgroup: 300,
                min_rate: None,
                max_rate: None,
            },
        }
    }
}

impl Default for TimingTemplate {
    fn default() -> Self {
        TimingTemplate::Normal
    }
}

impl TimingConfig {
    /// Create timing config from a timing template number (0-5)
    pub fn from_template(template_num: u8) -> Self {
        let template = match template_num {
            0 => TimingTemplate::Paranoid,
            1 => TimingTemplate::Sneaky,
            2 => TimingTemplate::Polite,
            3 => TimingTemplate::Normal,
            4 => TimingTemplate::Aggressive,
            5 => TimingTemplate::Insane,
            _ => TimingTemplate::Normal,
        };
        template.config()
    }
}