use anyhow::{anyhow, Result};
use nmap_net::Host;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::{info, debug};

pub use nmap_net::{Host as Target, HostState as TargetState};

pub struct TargetGroup {
    pub targets: Vec<Host>,
}

pub struct TargetManager {
    target_specs: Vec<String>,
}

impl TargetManager {
    pub fn new(target_specs: Vec<String>) -> Result<Self> {
        Ok(Self {
            target_specs,
        })
    }
    
    pub async fn discover_targets(&self) -> Result<Vec<Host>> {
        info!("Discovering targets from {} specifications", self.target_specs.len());
        
        let mut targets = Vec::new();
        
        for spec in &self.target_specs {
            let mut spec_targets = self.parse_target_spec(spec).await?;
            targets.append(&mut spec_targets);
        }
        
        debug!("Discovered {} targets", targets.len());
        Ok(targets)
    }
    
    async fn parse_target_spec(&self, spec: &str) -> Result<Vec<Host>> {
        let mut targets = Vec::new();
        
        // Try to parse as IP address
        if let Ok(ip) = IpAddr::from_str(spec) {
            targets.push(Host::new(ip));
            return Ok(targets);
        }
        
        // Try to parse as CIDR network
        if let Ok(network) = ipnet::IpNet::from_str(spec) {
            for ip in network.hosts() {
                targets.push(Host::new(ip));
                // Limit to prevent huge networks
                if targets.len() >= 1000 {
                    break;
                }
            }
            return Ok(targets);
        }
        
        // Try to resolve as hostname
        match dns_lookup::lookup_host(spec) {
            Ok(ips) => {
                for ip in ips {
                    let mut host = Host::new(ip);
                    host.hostname = Some(spec.to_string());
                    targets.push(host);
                }
            }
            Err(_) => {
                return Err(anyhow!("Could not resolve hostname: {}", spec));
            }
        }
        
        Ok(targets)
    }
}