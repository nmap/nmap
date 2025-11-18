use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;
use nmap_net::{ScanType, PortSpec};
pub use nmap_timing::TimingTemplate;

/// Nmap scanning options and configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapOptions {
    // Target specification
    pub targets: Vec<String>,

    // Port specification
    pub ports: String,
    pub port_specs: Vec<PortSpec>,

    // Scan types
    pub tcp_scan: bool,
    pub syn_scan: bool,
    pub udp_scan: bool,
    pub connect_scan: bool,
    pub scan_types: Vec<ScanType>,

    // Host discovery
    pub skip_ping: bool,
    pub ping_types: Vec<PingType>,

    // Service/Version detection
    pub service_detection: bool,
    pub version_detection: bool,
    pub os_detection: bool,

    // Output options
    pub verbose: u8,
    pub debug_level: u8,
    pub output_format: String,
    pub output_file: Option<String>,

    // Timing and performance (use u8 for serialization compatibility)
    pub timing_template_level: u8,  // 0-5
    pub max_rate: Option<u32>,
    pub min_rate: Option<u32>,
    pub max_retries: u32,
    pub host_timeout: Duration,
    pub scan_delay: Duration,

    // Advanced options
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub interface: Option<String>,
    pub spoof_mac: Option<String>,
    pub decoys: Vec<IpAddr>,

    // Firewall/IDS evasion
    pub fragment_packets: bool,
    pub mtu_discovery: bool,
    pub randomize_hosts: bool,

    // NSE options
    pub script_scan: bool,
    pub scripts: Vec<String>,
    pub script_args: Vec<String>,
}

impl NmapOptions {
    /// Get TimingTemplate from the level
    pub fn timing_template(&self) -> TimingTemplate {
        match self.timing_template_level {
            0 => TimingTemplate::Paranoid,
            1 => TimingTemplate::Sneaky,
            2 => TimingTemplate::Polite,
            3 => TimingTemplate::Normal,
            4 => TimingTemplate::Aggressive,
            5 => TimingTemplate::Insane,
            _ => TimingTemplate::Normal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PingType {
    Icmp,
    TcpSyn,
    TcpAck,
    Udp,
    Sctp,
    ArpPing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanTechnique {
    TcpConnect,
    TcpSyn,
    TcpAck,
    TcpWindow,
    TcpMaimon,
    UdpScan,
    SctpInit,
    SctpCookieEcho,
    IpProtocol,
    FtpBounce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressFamily {
    IPv4,
    IPv6,
    Unspecified,
}

impl Default for NmapOptions {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            ports: "1-1000".to_string(),
            port_specs: vec![PortSpec::default_tcp()],

            tcp_scan: true,
            syn_scan: false,
            udp_scan: false,
            connect_scan: false,
            scan_types: vec![ScanType::Connect],

            skip_ping: false,
            ping_types: vec![PingType::Icmp, PingType::TcpSyn],

            service_detection: false,
            version_detection: false,
            os_detection: false,

            verbose: 0,
            debug_level: 0,
            output_format: "normal".to_string(),
            output_file: None,

            timing_template_level: 3,  // Normal
            max_rate: None,
            min_rate: None,
            max_retries: 3,
            host_timeout: Duration::from_secs(300),
            scan_delay: Duration::from_millis(0),

            source_ip: None,
            source_port: None,
            interface: None,
            spoof_mac: None,
            decoys: Vec::new(),

            fragment_packets: false,
            mtu_discovery: false,
            randomize_hosts: false,

            script_scan: false,
            scripts: Vec::new(),
            script_args: Vec::new(),
        }
    }
}

impl NmapOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_targets(mut self, targets: Vec<String>) -> Self {
        self.targets = targets;
        self
    }

    pub fn with_ports(mut self, ports: String) -> Self {
        self.ports = ports;
        self
    }

    pub fn with_service_detection(mut self, enable: bool) -> Self {
        self.service_detection = enable;
        self
    }

    pub fn with_os_detection(mut self, enable: bool) -> Self {
        self.os_detection = enable;
        self
    }

    pub fn with_verbose(mut self, level: u8) -> Self {
        self.verbose = level;
        self
    }

    pub fn with_timing_template(mut self, level: u8) -> Self {
        self.timing_template_level = level.min(5);
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.targets.is_empty() {
            return Err(anyhow::anyhow!("No targets specified"));
        }

        if self.timing_template_level > 5 {
            return Err(anyhow::anyhow!("Invalid timing template level: {}", self.timing_template_level));
        }

        Ok(())
    }

    pub fn get_timing_values(&self) -> TimingValues {
        match self.timing_template_level {
            0 => TimingValues::paranoid(),
            1 => TimingValues::sneaky(),
            2 => TimingValues::polite(),
            3 => TimingValues::normal(),
            4 => TimingValues::aggressive(),
            5 => TimingValues::insane(),
            _ => TimingValues::normal(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimingValues {
    pub max_rtt_timeout: Duration,
    pub min_rtt_timeout: Duration,
    pub initial_rtt_timeout: Duration,
    pub max_retries: u32,
    pub host_group_size: usize,
    pub scan_delay: Duration,
    pub max_scan_delay: Duration,
}

impl TimingValues {
    pub fn paranoid() -> Self {
        Self {
            max_rtt_timeout: Duration::from_secs(300),
            min_rtt_timeout: Duration::from_secs(5),
            initial_rtt_timeout: Duration::from_secs(5),
            max_retries: 10,
            host_group_size: 1,
            scan_delay: Duration::from_secs(5),
            max_scan_delay: Duration::from_secs(300),
        }
    }

    pub fn sneaky() -> Self {
        Self {
            max_rtt_timeout: Duration::from_secs(150),
            min_rtt_timeout: Duration::from_secs(2),
            initial_rtt_timeout: Duration::from_secs(2),
            max_retries: 7,
            host_group_size: 1,
            scan_delay: Duration::from_secs(1),
            max_scan_delay: Duration::from_secs(150),
        }
    }

    pub fn polite() -> Self {
        Self {
            max_rtt_timeout: Duration::from_secs(100),
            min_rtt_timeout: Duration::from_millis(500),
            initial_rtt_timeout: Duration::from_secs(1),
            max_retries: 6,
            host_group_size: 1,
            scan_delay: Duration::from_millis(400),
            max_scan_delay: Duration::from_secs(100),
        }
    }

    pub fn normal() -> Self {
        Self {
            max_rtt_timeout: Duration::from_secs(10),
            min_rtt_timeout: Duration::from_millis(100),
            initial_rtt_timeout: Duration::from_secs(1),
            max_retries: 3,
            host_group_size: 64,
            scan_delay: Duration::from_millis(0),
            max_scan_delay: Duration::from_secs(10),
        }
    }

    pub fn aggressive() -> Self {
        Self {
            max_rtt_timeout: Duration::from_secs(5),
            min_rtt_timeout: Duration::from_millis(50),
            initial_rtt_timeout: Duration::from_millis(500),
            max_retries: 2,
            host_group_size: 128,
            scan_delay: Duration::from_millis(0),
            max_scan_delay: Duration::from_secs(5),
        }
    }

    pub fn insane() -> Self {
        Self {
            max_rtt_timeout: Duration::from_secs(2),
            min_rtt_timeout: Duration::from_millis(25),
            initial_rtt_timeout: Duration::from_millis(250),
            max_retries: 1,
            host_group_size: 256,
            scan_delay: Duration::from_millis(0),
            max_scan_delay: Duration::from_secs(2),
        }
    }
}