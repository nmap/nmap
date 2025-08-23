pub mod engine;
pub mod options;
pub mod error;
pub mod data;

pub use engine::NmapEngine;
pub use options::NmapOptions;
pub use error::{NmapError, Result};
pub use data::DataManager;

// Re-export commonly used types from other crates
pub use nmap_targets::{Target, TargetGroup};
pub use nmap_timing::TimingTemplate;
pub use nmap_net::{ScanType, PortSpec};

/// Version information
pub const RMAP_VERSION: &str = "0.1.0";
pub const RMAP_NAME: &str = "R-Map";
pub const RMAP_URL: &str = "https://github.com/Ununp3ntium115/nmap";

/// Default configuration constants
pub const MAX_SOCKETS: usize = 36;
pub const MAX_PROBE_PORTS: usize = 10;
pub const DEFAULT_TCP_PROBE_PORT: u16 = 80;
pub const DEFAULT_UDP_PROBE_PORT: u16 = 40125;
pub const DEFAULT_SCTP_PROBE_PORT: u16 = 80;
pub const MAX_DECOYS: usize = 128;
pub const PING_GROUP_SIZE: usize = 4096;