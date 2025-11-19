use nmap_core::{NmapError, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use tokio::time::Duration;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::TransportProtocol;
use rand::Rng;
use crate::raw_socket::RawSocketSender;
use crate::utils::guess_initial_ttl;

#[derive(Debug, Clone)]
pub struct UdpTestResults {
    pub u1_test: Option<U1Test>,
}

#[derive(Debug, Clone)]
pub struct U1Test {
    pub r: String,    // Response
    pub df: String,   // Don't fragment bit
    pub t: u8,        // Initial TTL
    pub ipl: u16,     // IP total length
    pub un: u16,      // Unused port number
    pub ripl: u16,    // Returned IP total length
    pub rid: u16,     // Returned IP ID
    pub ripck: String, // Returned IP checksum
    pub ruck: u16,    // Returned UDP checksum
    pub rud: String,  // Returned UDP data
}

pub struct UdpTester {
    target: IpAddr,
    timeout: Duration,
    source_ip: IpAddr,
}

impl UdpTester {
    pub fn new(target: IpAddr) -> Self {
        let source_ip = match target {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        };

        Self {
            target,
            timeout: Duration::from_secs(3),
            source_ip,
        }
    }

    pub fn with_source_ip(mut self, source_ip: IpAddr) -> Self {
        self.source_ip = source_ip;
        self
    }

    pub async fn run_all_tests(&mut self) -> Result<UdpTestResults> {
        let mut results = UdpTestResults {
            u1_test: None,
        };

        // Run U1 test (UDP probe to closed port)
        results.u1_test = self.run_u1_test().await.ok();

        Ok(results)
    }

    async fn run_u1_test(&self) -> Result<U1Test> {
        // Send UDP packet to a likely closed port and analyze ICMP port unreachable response
        let closed_port = 40125; // Commonly closed port

        // Create UDP sender
        let protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp);
        let mut udp_sender = RawSocketSender::new(self.source_ip, protocol)?;

        // Create ICMP receiver to catch port unreachable
        let icmp_protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp);
        let mut icmp_receiver = RawSocketSender::new(self.source_ip, icmp_protocol)?;

        let mut rng = rand::thread_rng();
        let source_port = rng.gen_range(49152..=65535);
        let probe_data = b"nmap-udp-probe\x00";

        // Send UDP probe to closed port
        udp_sender.send_udp_probe(
            self.target,
            closed_port,
            source_port,
            probe_data,
            64,   // TTL
            true, // DF bit
        )?;

        // Try to receive ICMP port unreachable response
        match icmp_receiver.receive_icmp(self.timeout).await {
            Ok((data, _addr)) => {
                // Analyze the ICMP port unreachable response
                self.analyze_icmp_response(&data, closed_port)
            }
            Err(_) => {
                // No response - port might be open or filtered
                Ok(U1Test {
                    r: "N".to_string(), // No response
                    df: "N".to_string(),
                    t: 0,
                    ipl: 0,
                    un: closed_port,
                    ripl: 0,
                    rid: 0,
                    ripck: "G".to_string(),
                    ruck: 0,
                    rud: "".to_string(),
                })
            }
        }
    }

    fn analyze_icmp_response(&self, data: &[u8], closed_port: u16) -> Result<U1Test> {
        // Parse ICMP port unreachable packet
        if data.len() < 8 {
            return Err(NmapError::InvalidPacket);
        }

        let icmp_type = data[0];
        let icmp_code = data[1];

        // ICMP Type 3 (Destination Unreachable), Code 3 (Port Unreachable)
        if icmp_type != 3 || icmp_code != 3 {
            return Err(NmapError::InvalidPacket);
        }

        // Extract TTL (would need IP header parsing)
        let observed_ttl = 64u8; // Placeholder
        let initial_ttl = guess_initial_ttl(observed_ttl);

        // Extract other fields from ICMP payload
        // The ICMP payload contains the original IP header + 8 bytes of original datagram
        let ipl = data.len() as u16;
        let ripl = if data.len() >= 28 {
            u16::from_be_bytes([data[8], data[9]]) // IP total length from returned header
        } else {
            0
        };

        let rid = if data.len() >= 28 {
            u16::from_be_bytes([data[12], data[13]]) // IP ID from returned header
        } else {
            0
        };

        Ok(U1Test {
            r: "Y".to_string(), // Response received
            df: "Y".to_string(), // DF bit (would check IP header)
            t: initial_ttl,
            ipl,
            un: closed_port,
            ripl,
            rid,
            ripck: "G".to_string(), // Good checksum (would verify)
            ruck: 0,                // Returned UDP checksum
            rud: "".to_string(),    // Returned UDP data (simplified)
        })
    }

    pub async fn probe_udp_port(&self, port: u16) -> Result<bool> {
        let addr = SocketAddr::new(self.target, port);
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|_| NmapError::SocketCreationFailed)?;
        
        socket.set_read_timeout(Some(Duration::from_millis(500).into()))
            .map_err(|_| NmapError::SocketConfigurationFailed)?;

        // Send probe
        let probe_data = b"nmap";
        match socket.send_to(probe_data, addr) {
            Ok(_) => {
                // Try to receive response
                let mut buffer = [0u8; 1024];
                match socket.recv_from(&mut buffer) {
                    Ok(_) => Ok(true),  // Port is open
                    Err(_) => Ok(false), // Port is closed or filtered
                }
            }
            Err(_) => Err(NmapError::SendFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_udp_tester_creation() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let tester = UdpTester::new(target);
        assert_eq!(tester.target, target);
    }

    #[tokio::test]
    async fn test_udp_port_probe() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let tester = UdpTester::new(target);
        
        // This test might fail if no UDP service is running on localhost:53
        // but it demonstrates the interface
        let _result = tester.probe_udp_port(53).await;
    }
}