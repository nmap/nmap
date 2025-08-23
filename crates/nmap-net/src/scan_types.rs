use serde::{Deserialize, Serialize};

/// Scan type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanType {
    /// TCP SYN scan (-sS)
    Syn,
    /// TCP connect() scan (-sT)
    Connect,
    /// TCP ACK scan (-sA)
    Ack,
    /// TCP Window scan (-sW)
    Window,
    /// TCP Maimon scan (-sM)
    Maimon,
    /// UDP scan (-sU)
    Udp,
    /// TCP NULL scan (-sN)
    Null,
    /// TCP FIN scan (-sF)
    Fin,
    /// TCP Xmas scan (-sX)
    Xmas,
    /// SCTP INIT scan (-sY)
    SctpInit,
    /// SCTP COOKIE-ECHO scan (-sZ)
    SctpCookieEcho,
    /// IP protocol scan (-sO)
    IpProtocol,
    /// Idle scan (-sI)
    Idle,
    /// FTP bounce scan (-b)
    FtpBounce,
    /// List scan (-sL)
    List,
    /// Ping scan (-sn)
    Ping,
}

impl ScanType {
    /// Returns true if this scan type requires root privileges
    pub fn requires_root(&self) -> bool {
        match self {
            ScanType::Connect | ScanType::List | ScanType::Ping => false,
            _ => true,
        }
    }
    
    /// Returns true if this is a TCP-based scan
    pub fn is_tcp(&self) -> bool {
        match self {
            ScanType::Syn | ScanType::Connect | ScanType::Ack | ScanType::Window 
            | ScanType::Maimon | ScanType::Null | ScanType::Fin | ScanType::Xmas => true,
            _ => false,
        }
    }
    
    /// Returns true if this is a UDP-based scan
    pub fn is_udp(&self) -> bool {
        matches!(self, ScanType::Udp)
    }
    
    /// Returns true if this is an SCTP-based scan
    pub fn is_sctp(&self) -> bool {
        matches!(self, ScanType::SctpInit | ScanType::SctpCookieEcho)
    }
    
    /// Get the default port for this scan type
    pub fn default_port(&self) -> u16 {
        match self {
            ScanType::Udp => 53,
            _ => 80,
        }
    }
}