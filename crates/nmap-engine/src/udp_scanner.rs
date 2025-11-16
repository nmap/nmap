/// UDP Scanner Implementation
/// Provides UDP port scanning with ICMP port unreachable detection

use anyhow::{anyhow, Result};
use nmap_net::{Host, Port, PortState};
use nmap_timing::TimingConfig;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// UDP Scanner for port discovery
pub struct UdpScanner {
    timing: TimingConfig,
}

impl UdpScanner {
    pub fn new(timing: TimingConfig) -> Self {
        Self { timing }
    }

    /// Scan UDP ports on multiple hosts
    pub async fn scan_hosts(&self, hosts: &mut [Host], ports: &[u16]) -> Result<()> {
        info!("Starting UDP scan on {} hosts", hosts.len());

        for host in hosts {
            debug!("Scanning UDP ports on {}", host.address);

            for &port in ports {
                let port_state = self.scan_port(host.address, port).await?;

                host.ports.push(Port {
                    number: port,
                    state: port_state,
                    service: Some(get_common_udp_service(port)),
                    version: None,
                });
            }
        }

        Ok(())
    }

    /// Scan a single UDP port
    async fn scan_port(&self, target: IpAddr, port: u16) -> Result<PortState> {
        // UDP scanning is tricky:
        // - No response usually means open|filtered
        // - ICMP port unreachable means closed
        // - Response means definitely open

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(SocketAddr::new(target, port)).await?;

        // Send UDP probe (protocol-specific payload if known service)
        let probe = get_udp_probe(port);

        match timeout(self.timing.timeout, socket.send(&probe)).await {
            Ok(Ok(_)) => {
                // Probe sent, now wait for response
                let mut response = vec![0u8; 1024];

                match timeout(self.timing.timeout, socket.recv(&mut response)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Got a response! Port is definitely open
                        debug!("UDP port {} on {} is open (received response)", port, target);
                        Ok(PortState::Open)
                    }
                    _ => {
                        // No response - could be open or filtered
                        // In nmap, this is marked as "open|filtered"
                        // For simplicity, we'll mark as filtered with a note
                        debug!("UDP port {} on {} is open|filtered (no response)", port, target);
                        Ok(PortState::Filtered)
                    }
                }
            }
            Ok(Err(e)) => {
                // Check if we got ICMP port unreachable (connection refused in UDP means closed)
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    debug!("UDP port {} on {} is closed (ICMP unreachable)", port, target);
                    Ok(PortState::Closed)
                } else {
                    debug!("UDP port {} on {} scan error: {}", port, target, e);
                    Ok(PortState::Filtered)
                }
            }
            Err(_) => {
                // Timeout - no response, likely filtered or open
                debug!("UDP port {} on {} timeout (open|filtered)", port, target);
                Ok(PortState::Filtered)
            }
        }
    }
}

/// Get UDP probe payload for known services
fn get_udp_probe(port: u16) -> Vec<u8> {
    match port {
        53 => {
            // DNS query for version.bind
            vec![
                0x00, 0x1e, // Transaction ID
                0x01, 0x00, // Flags: standard query
                0x00, 0x01, // Questions: 1
                0x00, 0x00, // Answer RRs: 0
                0x00, 0x00, // Authority RRs: 0
                0x00, 0x00, // Additional RRs: 0
                // Query: version.bind
                0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
                0x04, 0x62, 0x69, 0x6e, 0x64,
                0x00, // Name terminator
                0x00, 0x10, // Type: TXT
                0x00, 0x03, // Class: CHAOS
            ]
        }
        123 => {
            // NTP query
            vec![
                0x1b, // Leap indicator (3), Version (3), Mode (3)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        }
        161 => {
            // SNMP GetRequest for system description
            vec![
                0x30, 0x26, // SEQUENCE
                0x02, 0x01, 0x00, // Version: 1
                0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // Community: public
                0xa0, 0x19, // GetRequest PDU
                0x02, 0x01, 0x01, // Request ID
                0x02, 0x01, 0x00, // Error status
                0x02, 0x01, 0x00, // Error index
                0x30, 0x0e, // Variable bindings
                0x30, 0x0c, // Variable binding
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: sysDescr
                0x05, 0x00, // NULL
            ]
        }
        137 => {
            // NetBIOS Name Service query
            vec![
                0x00, 0x00, // Transaction ID
                0x00, 0x10, // Flags: Name query
                0x00, 0x01, // Questions
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
                0x00, 0x21, // Type: NB
                0x00, 0x01, // Class: IN
            ]
        }
        _ => {
            // Generic UDP probe (empty packet)
            vec![0x00]
        }
    }
}

/// Get common UDP service name for known ports
fn get_common_udp_service(port: u16) -> String {
    match port {
        53 => "domain".to_string(),
        67 => "dhcps".to_string(),
        68 => "dhcpc".to_string(),
        69 => "tftp".to_string(),
        123 => "ntp".to_string(),
        135 => "msrpc".to_string(),
        137 => "netbios-ns".to_string(),
        138 => "netbios-dgm".to_string(),
        139 => "netbios-ssn".to_string(),
        161 => "snmp".to_string(),
        162 => "snmptrap".to_string(),
        445 => "microsoft-ds".to_string(),
        500 => "isakmp".to_string(),
        514 => "syslog".to_string(),
        520 => "route".to_string(),
        631 => "ipp".to_string(),
        1434 => "ms-sql-m".to_string(),
        1900 => "upnp".to_string(),
        4500 => "ipsec-nat-t".to_string(),
        5353 => "mdns".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Get top 100 UDP ports (commonly scanned)
pub fn get_top_udp_ports() -> Vec<u16> {
    vec![
        53, 67, 68, 69, 123, 135, 137, 138, 139, 161,
        162, 445, 500, 514, 520, 631, 1434, 1900, 4500, 5353,
        7, 9, 13, 17, 19, 37, 49, 111, 177, 427,
        497, 593, 623, 626, 996, 997, 998, 999, 1000, 1022,
        1023, 1025, 1026, 1027, 1028, 1029, 1030, 1433, 1434, 1645,
        1646, 1701, 1718, 1719, 1812, 1813, 1985, 2000, 2001, 2002,
        2049, 2222, 2223, 2483, 2484, 3456, 3784, 3785, 4045, 4444,
        5000, 5001, 5060, 5353, 5632, 9200, 10000, 17185, 20031, 27015,
        27016, 27017, 27018, 27019, 27960, 30718, 31337, 32768, 32769, 32770,
        32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_probe_generation() {
        // DNS probe
        let dns_probe = get_udp_probe(53);
        assert!(dns_probe.len() > 0);
        assert_eq!(dns_probe[2], 0x01); // Standard query flag

        // NTP probe
        let ntp_probe = get_udp_probe(123);
        assert_eq!(ntp_probe[0], 0x1b); // NTP version 3, client mode

        // Generic probe
        let generic_probe = get_udp_probe(9999);
        assert_eq!(generic_probe, vec![0x00]);
    }

    #[test]
    fn test_common_udp_services() {
        assert_eq!(get_common_udp_service(53), "domain");
        assert_eq!(get_common_udp_service(123), "ntp");
        assert_eq!(get_common_udp_service(161), "snmp");
        assert_eq!(get_common_udp_service(9999), "unknown");
    }

    #[test]
    fn test_top_udp_ports() {
        let ports = get_top_udp_ports();
        assert_eq!(ports.len(), 100);
        assert!(ports.contains(&53)); // DNS
        assert!(ports.contains(&161)); // SNMP
        assert!(ports.contains(&123)); // NTP
    }
}
