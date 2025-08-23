use crate::Protocol;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Port specification for scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortSpec {
    pub protocol: Protocol,
    pub ports: Vec<PortRange>,
}

/// Port range specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortRange {
    Single(u16),
    Range(u16, u16),
    List(Vec<u16>),
}

impl PortSpec {
    /// Create a default TCP port specification
    pub fn default_tcp() -> Self {
        Self {
            protocol: Protocol::Tcp,
            ports: vec![PortRange::default_tcp_ports()],
        }
    }
    
    /// Create a default UDP port specification
    pub fn default_udp() -> Self {
        Self {
            protocol: Protocol::Udp,
            ports: vec![PortRange::default_udp_ports()],
        }
    }
    
    /// Parse a port specification string
    pub fn parse(spec: &str) -> Result<Self> {
        let mut protocol = Protocol::Tcp;
        let mut spec = spec;
        
        // Check for protocol prefix (T:, U:, S:)
        if let Some(colon_pos) = spec.find(':') {
            let proto_part = &spec[..colon_pos];
            spec = &spec[colon_pos + 1..];
            
            protocol = match proto_part.to_uppercase().as_str() {
                "T" | "TCP" => Protocol::Tcp,
                "U" | "UDP" => Protocol::Udp,
                "S" | "SCTP" => Protocol::Sctp,
                _ => return Err(anyhow!("Invalid protocol: {}", proto_part)),
            };
        }
        
        let ports = parse_port_ranges(spec)?;
        
        Ok(Self { protocol, ports })
    }
    
    /// Get all individual ports from this specification
    pub fn get_ports(&self) -> Vec<u16> {
        let mut ports = HashSet::new();
        
        for range in &self.ports {
            match range {
                PortRange::Single(port) => {
                    ports.insert(*port);
                }
                PortRange::Range(start, end) => {
                    for port in *start..=*end {
                        ports.insert(port);
                    }
                }
                PortRange::List(port_list) => {
                    for port in port_list {
                        ports.insert(*port);
                    }
                }
            }
        }
        
        let mut result: Vec<u16> = ports.into_iter().collect();
        result.sort();
        result
    }
}

impl PortRange {
    /// Default TCP ports (top 1000)
    fn default_tcp_ports() -> Self {
        // This is a simplified version - in reality, this would be the top 1000 ports
        PortRange::List(vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3389, 5900, 8080
        ])
    }
    
    /// Default UDP ports
    fn default_udp_ports() -> Self {
        PortRange::List(vec![
            53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500, 49152
        ])
    }
}

fn parse_port_ranges(spec: &str) -> Result<Vec<PortRange>> {
    let mut ranges = Vec::new();
    
    for part in spec.split(',') {
        let part = part.trim();
        
        if part.contains('-') {
            // Range specification
            let parts: Vec<&str> = part.split('-').collect();
            if parts.len() != 2 {
                return Err(anyhow!("Invalid port range: {}", part));
            }
            
            let start: u16 = parts[0].parse()
                .map_err(|_| anyhow!("Invalid start port: {}", parts[0]))?;
            let end: u16 = parts[1].parse()
                .map_err(|_| anyhow!("Invalid end port: {}", parts[1]))?;
            
            if start > end {
                return Err(anyhow!("Invalid port range: start > end"));
            }
            
            ranges.push(PortRange::Range(start, end));
        } else {
            // Single port
            let port: u16 = part.parse()
                .map_err(|_| anyhow!("Invalid port: {}", part))?;
            ranges.push(PortRange::Single(port));
        }
    }
    
    Ok(ranges)
}