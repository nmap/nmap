use anyhow::{anyhow, Result};
use nmap_net::Host;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::{info, debug, warn};

pub use nmap_net::{Host as Target, HostState as TargetState};

/// Maximum length for a hostname (DNS limit is 253 characters)
const MAX_HOSTNAME_LENGTH: usize = 253;
/// Maximum length for a single hostname label (DNS limit is 63 characters)
const MAX_LABEL_LENGTH: usize = 63;

pub struct TargetGroup {
    pub targets: Vec<Host>,
}

pub struct TargetManager {
    target_specs: Vec<String>,
}

/// Validate a hostname to prevent DNS injection and other attacks
fn validate_hostname(hostname: &str) -> Result<()> {
    // Check length constraints
    if hostname.is_empty() {
        return Err(anyhow!("Hostname cannot be empty"));
    }

    if hostname.len() > MAX_HOSTNAME_LENGTH {
        return Err(anyhow!("Hostname too long (max {} characters)", MAX_HOSTNAME_LENGTH));
    }

    // Hostnames cannot start or end with a hyphen or dot
    if hostname.starts_with('-') || hostname.starts_with('.') {
        return Err(anyhow!("Hostname cannot start with hyphen or dot"));
    }

    if hostname.ends_with('-') || hostname.ends_with('.') {
        return Err(anyhow!("Hostname cannot end with hyphen or dot"));
    }

    // Split into labels and validate each
    let labels: Vec<&str> = hostname.split('.').collect();

    for label in labels {
        // Each label must be 1-63 characters
        if label.is_empty() {
            return Err(anyhow!("Hostname cannot contain empty labels (consecutive dots)"));
        }

        if label.len() > MAX_LABEL_LENGTH {
            return Err(anyhow!("Hostname label too long (max {} characters)", MAX_LABEL_LENGTH));
        }

        // Labels can only contain alphanumeric characters and hyphens
        // Labels cannot start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return Err(anyhow!("Hostname label '{}' cannot start or end with hyphen", label));
        }

        // Check all characters are valid (alphanumeric or hyphen)
        for ch in label.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' {
                return Err(anyhow!(
                    "Invalid character '{}' in hostname label '{}'. Only alphanumeric and hyphen allowed",
                    ch, label
                ));
            }
        }
    }

    // Additional security checks

    // Prevent localhost variants that could bypass filters
    let lowercase = hostname.to_lowercase();
    if lowercase == "localhost" || lowercase.ends_with(".localhost") {
        warn!("Localhost scanning detected: {}", hostname);
    }

    // Check for suspicious patterns that might indicate injection attempts
    let suspicious_chars = ['\\', '/', '|', '&', ';', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '\'', '"', '\n', '\r', '\0'];
    for &ch in &suspicious_chars {
        if hostname.contains(ch) {
            return Err(anyhow!(
                "Suspicious character '{}' detected in hostname. Possible injection attempt",
                ch
            ));
        }
    }

    Ok(())
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
        
        // Try to resolve as hostname (with validation)
        // First validate the hostname to prevent DNS injection
        validate_hostname(spec)?;

        match dns_lookup::lookup_host(spec) {
            Ok(ips) => {
                for ip in ips {
                    let mut host = Host::new(ip);
                    host.hostname = Some(spec.to_string());
                    targets.push(host);
                }
            }
            Err(e) => {
                return Err(anyhow!("Could not resolve hostname '{}': {}", spec, e));
            }
        }
        
        Ok(targets)
    }
}