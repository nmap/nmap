use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use chrono::{DateTime, Utc};

use nmap_net::{ScanType, PortSpec, PingType};
use nmap_timing::TimingTemplate;
use nmap_output::OutputFormat;

/// Global Nmap options structure - Rust equivalent of NmapOps class
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapOptions {
    // Basic scan configuration
    pub scan_types: Vec<ScanType>,
    pub ping_types: Vec<PingType>,
    pub port_specs: Vec<PortSpec>,
    
    // Target specification
    pub targets: Vec<String>,
    pub target_file: Option<PathBuf>,
    pub random_targets: Option<u32>,
    pub exclude_targets: Vec<String>,
    pub exclude_file: Option<PathBuf>,
    
    // Timing and performance
    pub timing_template: TimingTemplate,
    pub max_parallelism: Option<u32>,
    pub min_parallelism: Option<u32>,
    pub max_rtt_timeout: Duration,
    pub min_rtt_timeout: Duration,
    pub initial_rtt_timeout: Duration,
    pub max_retries: u32,
    pub host_timeout: Option<Duration>,
    pub scan_delay: Option<Duration>,
    pub max_scan_delay: Option<Duration>,
    pub min_rate: Option<f64>,
    pub max_rate: Option<f64>,
    
    // Network configuration
    pub address_family: AddressFamily,
    pub source_addr: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub interface: Option<String>,
    pub spoof_mac: Option<String>,
    pub decoys: Vec<IpAddr>,
    pub ttl: Option<u8>,
    pub ip_options: Option<Vec<u8>>,
    
    // Detection options
    pub os_detection: bool,
    pub version_detection: bool,
    pub version_intensity: u8,
    pub script_scan: bool,
    pub script_args: HashMap<String, String>,
    pub script_files: Vec<String>,
    
    // Output options
    pub output_formats: Vec<OutputFormat>,
    pub output_files: HashMap<OutputFormat, PathBuf>,
    pub verbosity: u8,
    pub debug_level: u8,
    pub packet_trace: bool,
    pub reason: bool,
    pub open_only: bool,
    pub append_output: bool,
    
    // Advanced options
    pub privileged: Option<bool>,
    pub send_eth: bool,
    pub send_ip: bool,
    pub fragment_packets: bool,
    pub mtu: Option<u16>,
    pub data_payload: Option<Vec<u8>>,
    pub data_string: Option<String>,
    pub data_length: Option<usize>,
    pub bad_checksum: bool,
    
    // DNS options
    pub dns_servers: Vec<IpAddr>,
    pub system_dns: bool,
    pub resolve_all: bool,
    pub never_resolve: bool,
    
    // Misc options
    pub traceroute: bool,
    pub randomize_hosts: bool,
    pub noninteractive: bool,
    pub datadir: Option<PathBuf>,
    pub stylesheet: Option<String>,
    pub webxml: bool,
    pub no_stylesheet: bool,
    
    // Internal state
    pub start_time: DateTime<Utc>,
    pub resuming: bool,
    pub locale: Option<String>,
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
            scan_types: vec![ScanType::Syn],
            ping_types: vec![PingType::IcmpPing, PingType::TcpSyn],
            port_specs: Vec::new(),
            
            targets: Vec::new(),
            target_file: None,
            random_targets: None,
            exclude_targets: Vec::new(),
            exclude_file: None,
            
            timing_template: TimingTemplate::Normal,
            max_parallelism: None,
            min_parallelism: None,
            max_rtt_timeout: Duration::from_millis(10000),
            min_rtt_timeout: Duration::from_millis(100),
            initial_rtt_timeout: Duration::from_millis(1000),
            max_retries: 10,
            host_timeout: None,
            scan_delay: None,
            max_scan_delay: None,
            min_rate: None,
            max_rate: None,
            
            address_family: AddressFamily::Unspecified,
            source_addr: None,
            source_port: None,
            interface: None,
            spoof_mac: None,
            decoys: Vec::new(),
            ttl: None,
            ip_options: None,
            
            os_detection: false,
            version_detection: false,
            version_intensity: 7,
            script_scan: false,
            script_args: HashMap::new(),
            script_files: Vec::new(),
            
            output_formats: vec![OutputFormat::Normal],
            output_files: HashMap::new(),
            verbosity: 1,
            debug_level: 0,
            packet_trace: false,
            reason: false,
            open_only: false,
            append_output: false,
            
            privileged: None,
            send_eth: false,
            send_ip: false,
            fragment_packets: false,
            mtu: None,
            data_payload: None,
            data_string: None,
            data_length: None,
            bad_checksum: false,
            
            dns_servers: Vec::new(),
            system_dns: false,
            resolve_all: false,
            never_resolve: false,
            
            traceroute: false,
            randomize_hosts: false,
            noninteractive: false,
            datadir: None,
            stylesheet: None,
            webxml: false,
            no_stylesheet: false,
            
            start_time: Utc::now(),
            resuming: false,
            locale: None,
        }
    }
}

impl NmapOptions {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Check if running with root privileges
    pub fn is_privileged(&self) -> bool {
        self.privileged.unwrap_or_else(|| {
            #[cfg(unix)]
            {
                unsafe { libc::geteuid() == 0 }
            }
            #[cfg(windows)]
            {
                // TODO: Implement Windows privilege check
                false
            }
        })
    }
    
    /// Get the protocol family based on address family
    pub fn protocol_family(&self) -> i32 {
        match self.address_family {
            AddressFamily::IPv4 => libc::AF_INET,
            AddressFamily::IPv6 => libc::AF_INET6,
            AddressFamily::Unspecified => libc::AF_UNSPEC,
        }
    }
    
    /// Validate and adjust options based on privileges and compatibility
    pub fn validate(&mut self) -> crate::Result<()> {
        // Adjust ping types based on privileges
        if !self.is_privileged() {
            self.ping_types.retain(|pt| match pt {
                PingType::IcmpPing | PingType::IcmpTimestamp | PingType::IcmpMask => false,
                _ => true,
            });
            
            if self.ping_types.is_empty() {
                self.ping_types.push(PingType::TcpConnect);
            }
        }
        
        // Set default ports if none specified
        if self.port_specs.is_empty() {
            self.port_specs.push(PortSpec::default_tcp());
        }
        
        Ok(())
    }
}