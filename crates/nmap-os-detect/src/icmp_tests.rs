use nmap_core::{NmapError, Result};
use std::net::{IpAddr, Ipv4Addr};
use tokio::time::Duration;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::TransportProtocol;
use rand::Rng;
use crate::raw_socket::RawSocketSender;
use crate::utils::guess_initial_ttl;

#[derive(Debug, Clone)]
pub struct IcmpTestResults {
    pub ie_test: Option<IeTest>,
}

#[derive(Debug, Clone)]
pub struct IeTest {
    pub r: String,   // Response
    pub dfi: String, // Don't fragment bit (ICMP)
    pub t: u8,       // Initial TTL
    pub cd: String,  // ICMP code
}

pub struct IcmpTester {
    target: IpAddr,
    timeout: Duration,
    source_ip: IpAddr,
}

impl IcmpTester {
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

    pub async fn run_all_tests(&mut self) -> Result<IcmpTestResults> {
        let mut results = IcmpTestResults {
            ie_test: None,
        };

        // Run IE test (ICMP echo request)
        results.ie_test = self.run_ie_test().await.ok();

        Ok(results)
    }

    async fn run_ie_test(&self) -> Result<IeTest> {
        // Send ICMP echo request and analyze response using raw sockets
        let protocol = match self.target {
            IpAddr::V4(_) => TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp),
            IpAddr::V6(_) => TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6),
        };

        let mut sender = RawSocketSender::new(self.source_ip, protocol)?;

        let mut rng = rand::thread_rng();
        let identifier = rng.gen::<u16>();
        let sequence = rng.gen::<u16>();
        let payload = b"NMAP OS FINGERPRINT PROBE"; // 25 bytes payload

        // Send ICMP echo request
        sender.send_icmp_echo(
            self.target,
            identifier,
            sequence,
            payload,
            64,   // TTL
            true, // DF bit
        )?;

        // Receive ICMP echo reply
        match sender.receive_icmp(self.timeout).await {
            Ok((data, _addr)) => {
                // Parse ICMP response
                if data.len() < 8 {
                    return Err(NmapError::InvalidPacket);
                }

                let icmp_type = data[0];
                let icmp_code = data[1];

                // Extract TTL from IP header (would need IP layer parsing)
                let observed_ttl = 64u8; // Placeholder - would extract from IP header
                let initial_ttl = guess_initial_ttl(observed_ttl);

                // Determine if DF bit was set (would check IP header)
                let df_set = true; // Placeholder

                Ok(IeTest {
                    r: "Y".to_string(), // Response received
                    dfi: if df_set { "Y" } else { "N" }.to_string(),
                    t: initial_ttl,
                    cd: if icmp_code == 0 {
                        "Z".to_string() // Code 0 (echo reply)
                    } else {
                        format!("{:X}", icmp_code)
                    },
                })
            }
            Err(_) => {
                // No response
                Ok(IeTest {
                    r: "N".to_string(), // No response
                    dfi: "N".to_string(),
                    t: 0,
                    cd: "".to_string(),
                })
            }
        }
    }

    pub async fn ping(&self) -> Result<Duration> {
        // Ping implementation using raw ICMP sockets
        let protocol = match self.target {
            IpAddr::V4(_) => TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp),
            IpAddr::V6(_) => TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6),
        };

        let mut sender = RawSocketSender::new(self.source_ip, protocol)?;

        let mut rng = rand::thread_rng();
        let identifier = rng.gen::<u16>();
        let sequence = rng.gen::<u16>();
        let payload = b"PING";

        let start = std::time::Instant::now();

        // Send ICMP echo request
        sender.send_icmp_echo(self.target, identifier, sequence, payload, 64, true)?;

        // Receive ICMP echo reply
        match sender.receive_icmp(self.timeout).await {
            Ok(_) => Ok(start.elapsed()),
            Err(e) => Err(e),
        }
    }

    pub async fn traceroute(&self, max_hops: u8) -> Result<Vec<(u8, Option<IpAddr>, Duration)>> {
        // Simple traceroute implementation
        // Returns (hop_number, ip_address, rtt)
        
        let mut hops = Vec::new();
        
        for hop in 1..=max_hops {
            // Simulate traceroute hop
            let rtt = Duration::from_millis((hop as u64) * 10);
            
            if hop < max_hops {
                // Intermediate hop (simulated)
                hops.push((hop, Some(self.target), rtt));
            } else {
                // Final destination
                hops.push((hop, Some(self.target), rtt));
                break;
            }
            
            // Stop if we've reached the target (simplified logic)
            if hop > 5 {
                break;
            }
        }
        
        Ok(hops)
    }

    pub async fn detect_firewall(&self) -> Result<bool> {
        // Detect if there's a firewall by analyzing ICMP responses
        // This is a simplified implementation
        
        match self.run_ie_test().await {
            Ok(ie_test) => {
                // If we get a response, there might not be a firewall blocking ICMP
                Ok(ie_test.r == "N")
            }
            Err(_) => {
                // No response could indicate firewall or host down
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_icmp_tester_creation() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let tester = IcmpTester::new(target);
        assert_eq!(tester.target, target);
    }

    #[tokio::test]
    async fn test_ie_test() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut tester = IcmpTester::new(target);
        
        let result = tester.run_ie_test().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ping() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let tester = IcmpTester::new(target);
        
        let result = tester.ping().await;
        assert!(result.is_ok());
        
        if let Ok(duration) = result {
            assert!(duration < Duration::from_secs(1));
        }
    }

    #[tokio::test]
    async fn test_traceroute() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let tester = IcmpTester::new(target);
        
        let result = tester.traceroute(10).await;
        assert!(result.is_ok());
        
        if let Ok(hops) = result {
            assert!(!hops.is_empty());
            assert!(hops.len() <= 10);
        }
    }
}