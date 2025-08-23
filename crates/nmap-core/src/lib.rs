pub mod engine;
pub mod options;
pub mod error;

pub use engine::NmapEngine;
pub use options::NmapOptions;
pub use error::{NmapError, Result};

// Re-export commonly used types from other crates
pub use nmap_targets::{Target, TargetGroup};
pub use nmap_timing::TimingTemplate;
pub use nmap_output::{OutputFormat, OutputManager};
pub use nmap_net::{ScanType, PortSpec};

/// Version information
pub const NMAP_VERSION: &str = "7.98.1";
pub const NMAP_NAME: &str = "Nmap";
pub const NMAP_URL: &str = "https://nmap.org";

/// Default configuration constants
pub const MAX_SOCKETS: usize = 36;
pub const MAX_PROBE_PORTS: usize = 10;
pub const DEFAULT_TCP_PROBE_PORT: u16 = 80;
pub const DEFAULT_UDP_PROBE_PORT: u16 = 40125;
pub const DEFAULT_SCTP_PROBE_PORT: u16 = 80;
pub const MAX_DECOYS: usize = 128;
pub const PING_GROUP_SIZE: usize = 4096;