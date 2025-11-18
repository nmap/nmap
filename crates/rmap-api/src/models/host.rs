use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::net::IpAddr;
use uuid::Uuid;

/// Port state enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    #[serde(rename = "open|filtered")]
    OpenFiltered,
    #[serde(rename = "closed|filtered")]
    ClosedFiltered,
}

/// Network protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Port information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub number: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub product: Option<String>,
    pub extra_info: Option<String>,
}

/// Operating system information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSInfo {
    pub name: String,
    pub version: Option<String>,
    pub confidence: u8, // 0-100
    pub cpe: Option<String>, // Common Platform Enumeration
    pub family: Option<String>,
}

/// Host information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub os: Option<OSInfo>,
    pub ports: Vec<Port>,
    pub state: HostState,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Host state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HostState {
    Up,
    Down,
    Unknown,
}

impl Host {
    pub fn new(scan_id: Uuid, ip: IpAddr) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            scan_id,
            ip,
            hostname: None,
            mac: None,
            vendor: None,
            os: None,
            ports: Vec::new(),
            state: HostState::Unknown,
            first_seen: now,
            last_seen: now,
        }
    }

    pub fn add_port(&mut self, port: Port) {
        self.ports.push(port);
        self.last_seen = Utc::now();
    }

    pub fn set_os(&mut self, os: OSInfo) {
        self.os = Some(os);
        self.last_seen = Utc::now();
    }

    pub fn set_state(&mut self, state: HostState) {
        self.state = state;
        self.last_seen = Utc::now();
    }
}

/// Response for getting hosts
#[derive(Debug, Serialize)]
pub struct ListHostsResponse {
    pub hosts: Vec<Host>,
    pub total: usize,
}
