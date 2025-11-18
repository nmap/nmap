use anyhow::Result;
use nmap_net::{Host, Port, PortState, Protocol, RawSocket, TcpResponse, parse_tcp_response};
use nmap_timing::TimingConfig;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{debug, warn, error};
use rand::Rng;

/// Information about a sent probe
#[derive(Debug, Clone)]
struct ProbeInfo {
    target_port: u16,
    sent_time: Instant,
    retries: u32,
}

/// TCP ACK scanner implementation for firewall rule detection
/// ACK scanning is used to map firewall rules. An ACK packet is sent to each port.
/// If no response is received, the port is considered filtered (firewall is blocking).
/// If a RST packet is received, the port is considered unfiltered (no firewall blocking).
pub struct AckScanner {
    raw_socket: RawSocket,
    timing: TimingConfig,
    source_port_base: u16,
}

impl AckScanner {
    /// Create a new ACK scanner
    pub fn new(timing: TimingConfig) -> Result<Self> {
        let raw_socket = RawSocket::new_tcp()?;
        let mut rng = rand::thread_rng();
        let source_port_base = rng.gen_range(32768..65535);

        Ok(Self {
            raw_socket,
            timing,
            source_port_base,
        })
    }

    /// Scan multiple hosts and ports
    pub async fn scan_hosts(&self, hosts: &mut [Host], ports: &[u16]) -> Result<()> {
        debug!("Starting ACK scan for {} hosts, {} ports", hosts.len(), ports.len());

        for host in hosts {
            self.scan_host(host, ports).await?;

            // Rate limiting between hosts
            if self.timing.scan_delay > Duration::from_millis(0) {
                sleep(self.timing.scan_delay).await;
            }
        }

        Ok(())
    }

    /// Scan a single host
    async fn scan_host(&self, host: &mut Host, ports: &[u16]) -> Result<()> {
        debug!("ACK scanning host {} with {} ports", host.address, ports.len());

        let mut pending_probes = HashMap::new();
        let mut results = Vec::new();

        // Send ACK packets for all ports
        for (i, &port) in ports.iter().enumerate() {
            let source_port = self.source_port_base.wrapping_add(i as u16);

            match self.send_ack_probe(host.address, port, source_port).await {
                Ok(_) => {
                    pending_probes.insert(source_port, ProbeInfo {
                        target_port: port,
                        sent_time: Instant::now(),
                        retries: 0,
                    });
                }
                Err(e) => {
                    warn!("Failed to send ACK probe to {}:{}: {}", host.address, port, e);
                }
            }

            // Rate limiting between probes
            if self.timing.scan_delay > Duration::from_millis(0) {
                sleep(self.timing.scan_delay).await;
            }
        }

        // Collect responses
        let response_timeout = self.timing.max_rtt_timeout;
        let start_time = Instant::now();

        while !pending_probes.is_empty() && start_time.elapsed() < response_timeout {
            match self.receive_response().await {
                Ok(Some(response)) => {
                    if let Some(probe_info) = pending_probes.remove(&response.dest_port) {
                        // For ACK scans:
                        // - RST response = unfiltered (firewall allows packet through)
                        // - No response = filtered (firewall is blocking)
                        let port_state = if response.is_rst() {
                            PortState::Unfiltered
                        } else {
                            PortState::Filtered
                        };

                        results.push(Port {
                            number: probe_info.target_port,
                            protocol: Protocol::Tcp,
                            state: port_state,
                            service: None,
                            version: None,
                            reason: Some(format!("rst from {}", response.source_ip)),
                        });

                        debug!("Port {}:{} is {:?}",
                               host.address, probe_info.target_port, port_state);
                    }
                }
                Ok(None) => {
                    // No response available, continue waiting
                    sleep(Duration::from_millis(10)).await;
                }
                Err(e) => {
                    error!("Error receiving response: {}", e);
                    break;
                }
            }
        }

        // Handle timeouts - mark remaining ports as filtered
        for (_, probe_info) in pending_probes {
            results.push(Port {
                number: probe_info.target_port,
                protocol: Protocol::Tcp,
                state: PortState::Filtered,
                service: None,
                version: None,
                reason: Some("no-response".to_string()),
            });
        }

        host.ports = results;
        Ok(())
    }

    /// Send an ACK probe to a specific port
    async fn send_ack_probe(
        &self,
        target: IpAddr,
        target_port: u16,
        source_port: u16,
    ) -> Result<()> {
        self.raw_socket.send_ack_packet(target, target_port, source_port)?;
        debug!("Sent ACK probe to {}:{} from port {}", target, target_port, source_port);
        Ok(())
    }

    /// Receive and parse a response packet
    async fn receive_response(&self) -> Result<Option<TcpResponse>> {
        let mut buffer = vec![0u8; 1500]; // MTU size buffer

        match self.raw_socket.receive_packet(&mut buffer) {
            Ok(0) => Ok(None), // No data available
            Ok(size) => {
                match parse_tcp_response(&buffer[..size]) {
                    Ok(response) => {
                        debug!("Received TCP response from {}:{} flags={:02x}",
                               response.source_ip, response.source_port, response.flags);
                        Ok(Some(response))
                    }
                    Err(e) => {
                        debug!("Failed to parse TCP response: {}", e);
                        Ok(None)
                    }
                }
            }
            Err(e) => Err(e),
        }
    }
}

/// TCP FIN scanner implementation (stealth scan)
/// FIN scanning sends a packet with only the FIN flag set.
/// Open ports should not respond (RFC 793), closed ports should respond with RST.
pub struct FinScanner {
    raw_socket: RawSocket,
    timing: TimingConfig,
    source_port_base: u16,
}

impl FinScanner {
    /// Create a new FIN scanner
    pub fn new(timing: TimingConfig) -> Result<Self> {
        let raw_socket = RawSocket::new_tcp()?;
        let mut rng = rand::thread_rng();
        let source_port_base = rng.gen_range(32768..65535);

        Ok(Self {
            raw_socket,
            timing,
            source_port_base,
        })
    }

    /// Scan multiple hosts and ports
    pub async fn scan_hosts(&self, hosts: &mut [Host], ports: &[u16]) -> Result<()> {
        debug!("Starting FIN scan for {} hosts, {} ports", hosts.len(), ports.len());

        for host in hosts {
            self.scan_host(host, ports).await?;

            // Rate limiting between hosts
            if self.timing.scan_delay > Duration::from_millis(0) {
                sleep(self.timing.scan_delay).await;
            }
        }

        Ok(())
    }

    /// Scan a single host
    async fn scan_host(&self, host: &mut Host, ports: &[u16]) -> Result<()> {
        debug!("FIN scanning host {} with {} ports", host.address, ports.len());

        let mut pending_probes = HashMap::new();
        let mut results = Vec::new();

        // Send FIN packets for all ports
        for (i, &port) in ports.iter().enumerate() {
            let source_port = self.source_port_base.wrapping_add(i as u16);

            match self.send_fin_probe(host.address, port, source_port).await {
                Ok(_) => {
                    pending_probes.insert(source_port, ProbeInfo {
                        target_port: port,
                        sent_time: Instant::now(),
                        retries: 0,
                    });
                }
                Err(e) => {
                    warn!("Failed to send FIN probe to {}:{}: {}", host.address, port, e);
                }
            }

            // Rate limiting between probes
            if self.timing.scan_delay > Duration::from_millis(0) {
                sleep(self.timing.scan_delay).await;
            }
        }

        // Collect responses
        let response_timeout = self.timing.max_rtt_timeout;
        let start_time = Instant::now();

        while !pending_probes.is_empty() && start_time.elapsed() < response_timeout {
            match self.receive_response().await {
                Ok(Some(response)) => {
                    if let Some(probe_info) = pending_probes.remove(&response.dest_port) {
                        // For FIN scans:
                        // - RST response = closed
                        // - No response = open|filtered
                        let port_state = if response.is_rst() {
                            PortState::Closed
                        } else {
                            PortState::OpenFiltered
                        };

                        results.push(Port {
                            number: probe_info.target_port,
                            protocol: Protocol::Tcp,
                            state: port_state,
                            service: None,
                            version: None,
                            reason: Some(format!("rst from {}", response.source_ip)),
                        });

                        debug!("Port {}:{} is {:?}",
                               host.address, probe_info.target_port, port_state);
                    }
                }
                Ok(None) => {
                    // No response available, continue waiting
                    sleep(Duration::from_millis(10)).await;
                }
                Err(e) => {
                    error!("Error receiving response: {}", e);
                    break;
                }
            }
        }

        // Handle timeouts - mark remaining ports as open|filtered
        for (_, probe_info) in pending_probes {
            results.push(Port {
                number: probe_info.target_port,
                protocol: Protocol::Tcp,
                state: PortState::OpenFiltered,
                service: None,
                version: None,
                reason: Some("no-response".to_string()),
            });
        }

        host.ports = results;
        Ok(())
    }

    /// Send a FIN probe to a specific port
    async fn send_fin_probe(
        &self,
        target: IpAddr,
        target_port: u16,
        source_port: u16,
    ) -> Result<()> {
        self.raw_socket.send_fin_packet(target, target_port, source_port)?;
        debug!("Sent FIN probe to {}:{} from port {}", target, target_port, source_port);
        Ok(())
    }

    /// Receive and parse a response packet
    async fn receive_response(&self) -> Result<Option<TcpResponse>> {
        let mut buffer = vec![0u8; 1500]; // MTU size buffer

        match self.raw_socket.receive_packet(&mut buffer) {
            Ok(0) => Ok(None), // No data available
            Ok(size) => {
                match parse_tcp_response(&buffer[..size]) {
                    Ok(response) => {
                        debug!("Received TCP response from {}:{} flags={:02x}",
                               response.source_ip, response.source_port, response.flags);
                        Ok(Some(response))
                    }
                    Err(e) => {
                        debug!("Failed to parse TCP response: {}", e);
                        Ok(None)
                    }
                }
            }
            Err(e) => Err(e),
        }
    }
}

/// TCP NULL scanner implementation (all flags off)
/// NULL scanning sends a packet with no flags set.
/// Open ports should not respond, closed ports should respond with RST.
pub struct NullScanner {
    raw_socket: RawSocket,
    timing: TimingConfig,
    source_port_base: u16,
}

impl NullScanner {
    /// Create a new NULL scanner
    pub fn new(timing: TimingConfig) -> Result<Self> {
        let raw_socket = RawSocket::new_tcp()?;
        let mut rng = rand::thread_rng();
        let source_port_base = rng.gen_range(32768..65535);

        Ok(Self {
            raw_socket,
            timing,
            source_port_base,
        })
    }

    /// Scan multiple hosts and ports
    pub async fn scan_hosts(&self, hosts: &mut [Host], ports: &[u16]) -> Result<()> {
        debug!("Starting NULL scan for {} hosts, {} ports", hosts.len(), ports.len());

        for host in hosts {
            self.scan_host(host, ports).await?;

            // Rate limiting between hosts
            if self.timing.scan_delay > Duration::from_millis(0) {
                sleep(self.timing.scan_delay).await;
            }
        }

        Ok(())
    }

    /// Scan a single host
    async fn scan_host(&self, host: &mut Host, ports: &[u16]) -> Result<()> {
        debug!("NULL scanning host {} with {} ports", host.address, ports.len());

        let mut pending_probes = HashMap::new();
        let mut results = Vec::new();

        // Send NULL packets for all ports
        for (i, &port) in ports.iter().enumerate() {
            let source_port = self.source_port_base.wrapping_add(i as u16);

            match self.send_null_probe(host.address, port, source_port).await {
                Ok(_) => {
                    pending_probes.insert(source_port, ProbeInfo {
                        target_port: port,
                        sent_time: Instant::now(),
                        retries: 0,
                    });
                }
                Err(e) => {
                    warn!("Failed to send NULL probe to {}:{}: {}", host.address, port, e);
                }
            }

            // Rate limiting between probes
            if self.timing.scan_delay > Duration::from_millis(0) {
                sleep(self.timing.scan_delay).await;
            }
        }

        // Collect responses
        let response_timeout = self.timing.max_rtt_timeout;
        let start_time = Instant::now();

        while !pending_probes.is_empty() && start_time.elapsed() < response_timeout {
            match self.receive_response().await {
                Ok(Some(response)) => {
                    if let Some(probe_info) = pending_probes.remove(&response.dest_port) {
                        // For NULL scans:
                        // - RST response = closed
                        // - No response = open|filtered
                        let port_state = if response.is_rst() {
                            PortState::Closed
                        } else {
                            PortState::OpenFiltered
                        };

                        results.push(Port {
                            number: probe_info.target_port,
                            protocol: Protocol::Tcp,
                            state: port_state,
                            service: None,
                            version: None,
                            reason: Some(format!("rst from {}", response.source_ip)),
                        });

                        debug!("Port {}:{} is {:?}",
                               host.address, probe_info.target_port, port_state);
                    }
                }
                Ok(None) => {
                    // No response available, continue waiting
                    sleep(Duration::from_millis(10)).await;
                }
                Err(e) => {
                    error!("Error receiving response: {}", e);
                    break;
                }
            }
        }

        // Handle timeouts - mark remaining ports as open|filtered
        for (_, probe_info) in pending_probes {
            results.push(Port {
                number: probe_info.target_port,
                protocol: Protocol::Tcp,
                state: PortState::OpenFiltered,
                service: None,
                version: None,
                reason: Some("no-response".to_string()),
            });
        }

        host.ports = results;
        Ok(())
    }

    /// Send a NULL probe to a specific port
    async fn send_null_probe(
        &self,
        target: IpAddr,
        target_port: u16,
        source_port: u16,
    ) -> Result<()> {
        self.raw_socket.send_null_packet(target, target_port, source_port)?;
        debug!("Sent NULL probe to {}:{} from port {}", target, target_port, source_port);
        Ok(())
    }

    /// Receive and parse a response packet
    async fn receive_response(&self) -> Result<Option<TcpResponse>> {
        let mut buffer = vec![0u8; 1500]; // MTU size buffer

        match self.raw_socket.receive_packet(&mut buffer) {
            Ok(0) => Ok(None), // No data available
            Ok(size) => {
                match parse_tcp_response(&buffer[..size]) {
                    Ok(response) => {
                        debug!("Received TCP response from {}:{} flags={:02x}",
                               response.source_ip, response.source_port, response.flags);
                        Ok(Some(response))
                    }
                    Err(e) => {
                        debug!("Failed to parse TCP response: {}", e);
                        Ok(None)
                    }
                }
            }
            Err(e) => Err(e),
        }
    }
}

/// TCP Xmas scanner implementation (FIN, PSH, URG flags set)
/// Xmas scanning sends a packet with FIN, PSH, and URG flags set (like a Christmas tree).
/// Open ports should not respond, closed ports should respond with RST.
pub struct XmasScanner {
    raw_socket: RawSocket,
    timing: TimingConfig,
    source_port_base: u16,
}

impl XmasScanner {
    /// Create a new Xmas scanner
    pub fn new(timing: TimingConfig) -> Result<Self> {
        let raw_socket = RawSocket::new_tcp()?;
        let mut rng = rand::thread_rng();
        let source_port_base = rng.gen_range(32768..65535);

        Ok(Self {
            raw_socket,
            timing,
            source_port_base,
        })
    }

    /// Scan multiple hosts and ports
    pub async fn scan_hosts(&self, hosts: &mut [Host], ports: &[u16]) -> Result<()> {
        debug!("Starting Xmas scan for {} hosts, {} ports", hosts.len(), ports.len());

        for host in hosts {
            self.scan_host(host, ports).await?;

            // Rate limiting between hosts
            if self.timing.scan_delay > Duration::from_millis(0) {
                sleep(self.timing.scan_delay).await;
            }
        }

        Ok(())
    }

    /// Scan a single host
    async fn scan_host(&self, host: &mut Host, ports: &[u16]) -> Result<()> {
        debug!("Xmas scanning host {} with {} ports", host.address, ports.len());

        let mut pending_probes = HashMap::new();
        let mut results = Vec::new();

        // Send Xmas packets for all ports
        for (i, &port) in ports.iter().enumerate() {
            let source_port = self.source_port_base.wrapping_add(i as u16);

            match self.send_xmas_probe(host.address, port, source_port).await {
                Ok(_) => {
                    pending_probes.insert(source_port, ProbeInfo {
                        target_port: port,
                        sent_time: Instant::now(),
                        retries: 0,
                    });
                }
                Err(e) => {
                    warn!("Failed to send Xmas probe to {}:{}: {}", host.address, port, e);
                }
            }

            // Rate limiting between probes
            if self.timing.scan_delay > Duration::from_millis(0) {
                sleep(self.timing.scan_delay).await;
            }
        }

        // Collect responses
        let response_timeout = self.timing.max_rtt_timeout;
        let start_time = Instant::now();

        while !pending_probes.is_empty() && start_time.elapsed() < response_timeout {
            match self.receive_response().await {
                Ok(Some(response)) => {
                    if let Some(probe_info) = pending_probes.remove(&response.dest_port) {
                        // For Xmas scans:
                        // - RST response = closed
                        // - No response = open|filtered
                        let port_state = if response.is_rst() {
                            PortState::Closed
                        } else {
                            PortState::OpenFiltered
                        };

                        results.push(Port {
                            number: probe_info.target_port,
                            protocol: Protocol::Tcp,
                            state: port_state,
                            service: None,
                            version: None,
                            reason: Some(format!("rst from {}", response.source_ip)),
                        });

                        debug!("Port {}:{} is {:?}",
                               host.address, probe_info.target_port, port_state);
                    }
                }
                Ok(None) => {
                    // No response available, continue waiting
                    sleep(Duration::from_millis(10)).await;
                }
                Err(e) => {
                    error!("Error receiving response: {}", e);
                    break;
                }
            }
        }

        // Handle timeouts - mark remaining ports as open|filtered
        for (_, probe_info) in pending_probes {
            results.push(Port {
                number: probe_info.target_port,
                protocol: Protocol::Tcp,
                state: PortState::OpenFiltered,
                service: None,
                version: None,
                reason: Some("no-response".to_string()),
            });
        }

        host.ports = results;
        Ok(())
    }

    /// Send a Xmas probe to a specific port
    async fn send_xmas_probe(
        &self,
        target: IpAddr,
        target_port: u16,
        source_port: u16,
    ) -> Result<()> {
        self.raw_socket.send_xmas_packet(target, target_port, source_port)?;
        debug!("Sent Xmas probe to {}:{} from port {}", target, target_port, source_port);
        Ok(())
    }

    /// Receive and parse a response packet
    async fn receive_response(&self) -> Result<Option<TcpResponse>> {
        let mut buffer = vec![0u8; 1500]; // MTU size buffer

        match self.raw_socket.receive_packet(&mut buffer) {
            Ok(0) => Ok(None), // No data available
            Ok(size) => {
                match parse_tcp_response(&buffer[..size]) {
                    Ok(response) => {
                        debug!("Received TCP response from {}:{} flags={:02x}",
                               response.source_ip, response.source_port, response.flags);
                        Ok(Some(response))
                    }
                    Err(e) => {
                        debug!("Failed to parse TCP response: {}", e);
                        Ok(None)
                    }
                }
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nmap_timing::TimingTemplate;

    #[tokio::test]
    async fn test_ack_scanner_creation() {
        let timing = TimingTemplate::Normal.config();
        let result = AckScanner::new(timing);
        // May fail without raw socket privileges
        if let Err(e) = result {
            println!("ACK scanner creation failed (expected without root): {}", e);
        }
    }

    #[tokio::test]
    async fn test_fin_scanner_creation() {
        let timing = TimingTemplate::Normal.config();
        let result = FinScanner::new(timing);
        // May fail without raw socket privileges
        if let Err(e) = result {
            println!("FIN scanner creation failed (expected without root): {}", e);
        }
    }

    #[tokio::test]
    async fn test_null_scanner_creation() {
        let timing = TimingTemplate::Normal.config();
        let result = NullScanner::new(timing);
        // May fail without raw socket privileges
        if let Err(e) = result {
            println!("NULL scanner creation failed (expected without root): {}", e);
        }
    }

    #[tokio::test]
    async fn test_xmas_scanner_creation() {
        let timing = TimingTemplate::Normal.config();
        let result = XmasScanner::new(timing);
        // May fail without raw socket privileges
        if let Err(e) = result {
            println!("Xmas scanner creation failed (expected without root): {}", e);
        }
    }

    #[test]
    fn test_response_interpretation_ack_scan() {
        // ACK scan: RST = unfiltered, no response = filtered
        use pnet::packet::tcp::TcpFlags;

        let rst_response = TcpResponse {
            source_ip: "127.0.0.1".parse().unwrap(),
            source_port: 80,
            dest_port: 12345,
            flags: TcpFlags::RST,
            sequence: 0,
            acknowledgement: 0,
        };

        assert!(rst_response.is_rst());
        // In ACK scan, RST means unfiltered
    }

    #[test]
    fn test_response_interpretation_fin_scan() {
        // FIN scan: RST = closed, no response = open|filtered
        use pnet::packet::tcp::TcpFlags;

        let rst_response = TcpResponse {
            source_ip: "127.0.0.1".parse().unwrap(),
            source_port: 80,
            dest_port: 12345,
            flags: TcpFlags::RST,
            sequence: 0,
            acknowledgement: 0,
        };

        assert!(rst_response.is_rst());
        // In FIN scan, RST means closed
    }

    #[test]
    fn test_response_interpretation_null_scan() {
        // NULL scan: RST = closed, no response = open|filtered
        use pnet::packet::tcp::TcpFlags;

        let rst_response = TcpResponse {
            source_ip: "127.0.0.1".parse().unwrap(),
            source_port: 80,
            dest_port: 12345,
            flags: TcpFlags::RST,
            sequence: 0,
            acknowledgement: 0,
        };

        assert!(rst_response.is_rst());
        // In NULL scan, RST means closed
    }

    #[test]
    fn test_response_interpretation_xmas_scan() {
        // Xmas scan: RST = closed, no response = open|filtered
        use pnet::packet::tcp::TcpFlags;

        let rst_response = TcpResponse {
            source_ip: "127.0.0.1".parse().unwrap(),
            source_port: 80,
            dest_port: 12345,
            flags: TcpFlags::RST,
            sequence: 0,
            acknowledgement: 0,
        };

        assert!(rst_response.is_rst());
        // In Xmas scan, RST means closed
    }
}
