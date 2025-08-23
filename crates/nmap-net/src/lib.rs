pub mod scan_types;
pub mod port_spec;
pub mod ping_types;
pub mod socket_utils;
pub mod raw_socket;
pub mod packet;

pub use scan_types::ScanType;
pub use port_spec::PortSpec;
pub use ping_types::PingType;
pub use socket_utils::*;
pub use raw_socket::{RawSocket, TcpResponse, parse_tcp_response};
pub use packet::*;

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// Port state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered,
    ClosedFiltered,
}

/// Protocol enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
    Ip,
}

/// Port information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub number: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<String>,
    pub version: Option<String>,
    pub reason: Option<String>,
}

/// Host information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub address: IpAddr,
    pub hostname: Option<String>,
    pub state: HostState,
    pub ports: Vec<Port>,
    pub os_info: Option<OsInfo>,
    pub mac_address: Option<String>,
}

/// Host state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostState {
    Up,
    Down,
    Unknown,
}

/// OS detection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub family: String,
    pub generation: Option<String>,
    pub vendor: String,
    pub accuracy: u8,
}

impl Port {
    pub fn new(number: u16, protocol: Protocol) -> Self {
        Self {
            number,
            protocol,
            state: PortState::Closed,
            service: None,
            version: None,
            reason: None,
        }
    }
}

impl Host {
    pub fn new(address: IpAddr) -> Self {
        Self {
            address,
            hostname: None,
            state: HostState::Unknown,
            ports: Vec::new(),
            os_info: None,
            mac_address: None,
        }
    }
}