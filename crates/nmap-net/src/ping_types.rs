use serde::{Deserialize, Serialize};

/// Ping type enumeration for host discovery
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PingType {
    /// ICMP echo request (-PE)
    IcmpPing,
    /// ICMP timestamp request (-PP)
    IcmpTimestamp,
    /// ICMP netmask request (-PM)
    IcmpMask,
    /// TCP SYN ping (-PS)
    TcpSyn,
    /// TCP ACK ping (-PA)
    TcpAck,
    /// TCP connect() ping
    TcpConnect,
    /// UDP ping (-PU)
    Udp,
    /// SCTP INIT ping (-PY)
    SctpInit,
    /// IP protocol ping (-PO)
    IpProtocol,
    /// ARP ping (implicit for local networks)
    Arp,
}

impl PingType {
    /// Returns true if this ping type requires root privileges
    pub fn requires_root(&self) -> bool {
        match self {
            PingType::TcpConnect => false,
            _ => true,
        }
    }
    
    /// Returns true if this ping type works over the internet
    pub fn works_remotely(&self) -> bool {
        match self {
            PingType::Arp => false,
            _ => true,
        }
    }
    
    /// Get the default port for this ping type
    pub fn default_port(&self) -> Option<u16> {
        match self {
            PingType::TcpSyn | PingType::TcpConnect => Some(80),
            PingType::TcpAck => Some(80),
            PingType::Udp => Some(40125),
            PingType::SctpInit => Some(80),
            _ => None,
        }
    }
}