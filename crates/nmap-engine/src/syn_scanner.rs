use anyhow::Result;
use nmap_net::{Host, Port, PortState, Protocol, RawSocket, TcpResponse, parse_tcp_response};
use nmap_timing::TimingConfig;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};
use tracing::{debug, warn, error};
use rand::Rng;

/// TCP SYN scanner implementation
pub struct SynScanner {
    raw_socket: RawSocket,
    timing: TimingConfig,
    source_port_base: u16,
}

impl SynScanner {
    /// Create a new SYN scanner
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
        debug!("Starting SYN scan for {} hosts, {} ports", hosts.len(), ports.len());
        
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
        debug!("Scanning host {} with {} ports", host.address, ports.len());
        
        let mut pending_probes = HashMap::new();
        let mut results = Vec::new();
        
        // Send SYN packets for all ports
        for (i, &port) in ports.iter().enumerate() {
            let source_port = self.source_port_base.wrapping_add(i as u16);
            
            match self.send_syn_probe(host.address, port, source_port).await {
                Ok(_) => {
                    pending_probes.insert(source_port, ProbeInfo {
                        target_port: port,
                        sent_time: Instant::now(),
                        retries: 0,
                    });
                }
                Err(e) => {
                    warn!("Failed to send SYN probe to {}:{}: {}", host.address, port, e);
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
                        let port_state = if response.is_syn_ack() {
                            PortState::Open
                        } else if response.is_rst() {
                            PortState::Closed
                        } else {
                            PortState::Filtered
                        };
                        
                        results.push(Port {
                            number: probe_info.target_port,
                            protocol: Protocol::Tcp,
                            state: port_state,
                            service: None,
                            version: None,
                            reason: Some(format!("syn-ack from {}", response.source_ip)),
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
    
    /// Send a SYN probe to a specific port
    async fn send_syn_probe(
        &self,
        target: IpAddr,
        target_port: u16,
        source_port: u16,
    ) -> Result<()> {
        self.raw_socket.send_syn_packet(target, target_port, source_port)?;
        debug!("Sent SYN probe to {}:{} from port {}", target, target_port, source_port);
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

/// Information about a sent probe
#[derive(Debug, Clone)]
struct ProbeInfo {
    target_port: u16,
    sent_time: Instant,
    retries: u32,
}

/// TCP Connect scanner for non-privileged users
pub struct ConnectScanner {
    timing: TimingConfig,
}

impl ConnectScanner {
    pub fn new(timing: TimingConfig) -> Self {
        Self { timing }
    }
    
    /// Scan hosts using TCP connect()
    pub async fn scan_hosts(&self, hosts: &mut [Host], ports: &[u16]) -> Result<()> {
        debug!("Starting TCP connect scan for {} hosts, {} ports", hosts.len(), ports.len());
        
        for host in hosts {
            self.scan_host(host, ports).await?;
        }
        
        Ok(())
    }
    
    async fn scan_host(&self, host: &mut Host, ports: &[u16]) -> Result<()> {
        debug!("Connect scanning host {} with {} ports", host.address, ports.len());
        
        let mut results = Vec::new();
        
        for &port in ports {
            let port_state = self.test_port_connect(host.address, port).await;
            
            results.push(Port {
                number: port,
                protocol: Protocol::Tcp,
                state: port_state,
                service: None,
                version: None,
                reason: Some(match port_state {
                    PortState::Open => "syn-ack".to_string(),
                    PortState::Closed => "conn-refused".to_string(),
                    PortState::Filtered => "no-response".to_string(),
                    _ => "unknown".to_string(),
                }),
            });
            
            // Rate limiting
            if self.timing.scan_delay > Duration::from_millis(0) {
                sleep(self.timing.scan_delay).await;
            }
        }
        
        host.ports = results;
        Ok(())
    }
    
    async fn test_port_connect(&self, target: IpAddr, port: u16) -> PortState {
        let addr = std::net::SocketAddr::new(target, port);
        
        match timeout(self.timing.max_rtt_timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                debug!("Port {}:{} is open (connect succeeded)", target, port);
                PortState::Open
            }
            Ok(Err(e)) => {
                match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => {
                        debug!("Port {}:{} is closed (connection refused)", target, port);
                        PortState::Closed
                    }
                    _ => {
                        debug!("Port {}:{} is filtered ({})", target, port, e);
                        PortState::Filtered
                    }
                }
            }
            Err(_) => {
                debug!("Port {}:{} is filtered (timeout)", target, port);
                PortState::Filtered
            }
        }
    }
}