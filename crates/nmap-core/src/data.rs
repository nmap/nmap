use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Pure Rust implementation of Nmap data file parsing
/// Replaces the need for C-based parsing of nmap-services, nmap-os-db, etc.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub port: u16,
    pub protocol: String,
    pub description: Option<String>,
    pub frequency: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsFingerprint {
    pub name: String,
    pub class: String,
    pub vendor: String,
    pub family: String,
    pub generation: Option<String>,
    pub device_type: String,
    pub cpe: Vec<String>,
    pub fingerprint_data: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceProbe {
    pub name: String,
    pub protocol: String,
    pub ports: Vec<u16>,
    pub probe_string: String,
    pub matches: Vec<ServiceMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMatch {
    pub pattern: String,
    pub service: String,
    pub version: Option<String>,
    pub info: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub device_type: Option<String>,
    pub cpe: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacPrefix {
    pub prefix: String,
    pub vendor: String,
}

pub struct DataManager {
    services: HashMap<(u16, String), ServiceInfo>,
    os_fingerprints: Vec<OsFingerprint>,
    service_probes: HashMap<String, ServiceProbe>,
    mac_prefixes: HashMap<String, String>,
    protocols: HashMap<u8, String>,
    rpc_services: HashMap<u32, String>,
}

impl DataManager {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
            os_fingerprints: Vec::new(),
            service_probes: HashMap::new(),
            mac_prefixes: HashMap::new(),
            protocols: HashMap::new(),
            rpc_services: HashMap::new(),
        }
    }

    pub fn load_default_data(&mut self) -> Result<()> {
        self.load_default_services()?;
        self.load_default_protocols()?;
        self.load_default_mac_prefixes()?;
        self.load_default_os_fingerprints()?;
        self.load_default_service_probes()?;
        Ok(())
    }

    pub fn lookup_service(&self, port: u16, protocol: &str) -> Option<&ServiceInfo> {
        self.services.get(&(port, protocol.to_string()))
    }

    pub fn lookup_protocol(&self, number: u8) -> Option<&String> {
        self.protocols.get(&number)
    }

    pub fn lookup_mac_vendor(&self, mac: &str) -> Option<&String> {
        // Extract first 6 characters (3 bytes) for OUI lookup
        if mac.len() >= 8 {
            let oui = &mac[..8].to_uppercase();
            self.mac_prefixes.get(oui)
        } else {
            None
        }
    }

    pub fn get_service_probes(&self, service: &str) -> Vec<&ServiceProbe> {
        self.service_probes.values()
            .filter(|probe| probe.name == service)
            .collect()
    }

    pub fn get_os_fingerprints(&self) -> &[OsFingerprint] {
        &self.os_fingerprints
    }

    fn load_default_services(&mut self) -> Result<()> {
        // Common services - in a real implementation, this would load from nmap-services
        let services = vec![
            ServiceInfo {
                name: "http".to_string(),
                port: 80,
                protocol: "tcp".to_string(),
                description: Some("World Wide Web HTTP".to_string()),
                frequency: 0.484143,
            },
            ServiceInfo {
                name: "https".to_string(),
                port: 443,
                protocol: "tcp".to_string(),
                description: Some("HTTP over TLS/SSL".to_string()),
                frequency: 0.330151,
            },
            ServiceInfo {
                name: "ssh".to_string(),
                port: 22,
                protocol: "tcp".to_string(),
                description: Some("Secure Shell".to_string()),
                frequency: 0.182286,
            },
            ServiceInfo {
                name: "ftp".to_string(),
                port: 21,
                protocol: "tcp".to_string(),
                description: Some("File Transfer Protocol".to_string()),
                frequency: 0.197667,
            },
            ServiceInfo {
                name: "smtp".to_string(),
                port: 25,
                protocol: "tcp".to_string(),
                description: Some("Simple Mail Transfer Protocol".to_string()),
                frequency: 0.131314,
            },
            ServiceInfo {
                name: "dns".to_string(),
                port: 53,
                protocol: "tcp".to_string(),
                description: Some("Domain Name System".to_string()),
                frequency: 0.133969,
            },
            ServiceInfo {
                name: "dns".to_string(),
                port: 53,
                protocol: "udp".to_string(),
                description: Some("Domain Name System".to_string()),
                frequency: 0.133969,
            },
            ServiceInfo {
                name: "telnet".to_string(),
                port: 23,
                protocol: "tcp".to_string(),
                description: Some("Telnet".to_string()),
                frequency: 0.221265,
            },
            ServiceInfo {
                name: "pop3".to_string(),
                port: 110,
                protocol: "tcp".to_string(),
                description: Some("Post Office Protocol v3".to_string()),
                frequency: 0.076842,
            },
            ServiceInfo {
                name: "imap".to_string(),
                port: 143,
                protocol: "tcp".to_string(),
                description: Some("Internet Message Access Protocol".to_string()),
                frequency: 0.059406,
            },
            ServiceInfo {
                name: "snmp".to_string(),
                port: 161,
                protocol: "udp".to_string(),
                description: Some("Simple Network Management Protocol".to_string()),
                frequency: 0.027178,
            },
            ServiceInfo {
                name: "ldap".to_string(),
                port: 389,
                protocol: "tcp".to_string(),
                description: Some("Lightweight Directory Access Protocol".to_string()),
                frequency: 0.018326,
            },
        ];

        for service in services {
            self.services.insert((service.port, service.protocol.clone()), service);
        }

        Ok(())
    }

    fn load_default_protocols(&mut self) -> Result<()> {
        // Common IP protocols
        let protocols = vec![
            (1, "icmp"),
            (6, "tcp"),
            (17, "udp"),
            (47, "gre"),
            (50, "esp"),
            (51, "ah"),
            (58, "ipv6-icmp"),
        ];

        for (number, name) in protocols {
            self.protocols.insert(number, name.to_string());
        }

        Ok(())
    }

    fn load_default_mac_prefixes(&mut self) -> Result<()> {
        // Common MAC address prefixes (OUI)
        let prefixes = vec![
            ("00:00:0C", "Cisco Systems"),
            ("00:01:42", "Parallels"),
            ("00:03:FF", "Microsoft Corporation"),
            ("00:0C:29", "VMware"),
            ("00:15:5D", "Microsoft Corporation"),
            ("00:16:3E", "Xensource"),
            ("00:1B:21", "Intel Corporation"),
            ("00:50:56", "VMware"),
            ("08:00:27", "PCS Systemtechnik GmbH"),
            ("52:54:00", "QEMU/KVM"),
            ("AC:DE:48", "Private"),
        ];

        for (prefix, vendor) in prefixes {
            self.mac_prefixes.insert(prefix.to_string(), vendor.to_string());
        }

        Ok(())
    }

    fn load_default_os_fingerprints(&mut self) -> Result<()> {
        // Sample OS fingerprints - in reality, this would be much more extensive
        let fingerprints = vec![
            OsFingerprint {
                name: "Linux 2.6.X".to_string(),
                class: "Linux".to_string(),
                vendor: "Linux".to_string(),
                family: "Linux".to_string(),
                generation: Some("2.6.X".to_string()),
                device_type: "general purpose".to_string(),
                cpe: vec!["cpe:/o:linux:linux_kernel:2.6".to_string()],
                fingerprint_data: HashMap::new(),
            },
            OsFingerprint {
                name: "Microsoft Windows 10".to_string(),
                class: "Windows".to_string(),
                vendor: "Microsoft".to_string(),
                family: "Windows".to_string(),
                generation: Some("10".to_string()),
                device_type: "general purpose".to_string(),
                cpe: vec!["cpe:/o:microsoft:windows_10".to_string()],
                fingerprint_data: HashMap::new(),
            },
            OsFingerprint {
                name: "Apple macOS".to_string(),
                class: "Mac OS X".to_string(),
                vendor: "Apple".to_string(),
                family: "Mac OS X".to_string(),
                generation: None,
                device_type: "general purpose".to_string(),
                cpe: vec!["cpe:/o:apple:mac_os_x".to_string()],
                fingerprint_data: HashMap::new(),
            },
        ];

        self.os_fingerprints = fingerprints;
        Ok(())
    }

    fn load_default_service_probes(&mut self) -> Result<()> {
        // Sample service probes
        let probes = vec![
            ServiceProbe {
                name: "HTTP".to_string(),
                protocol: "tcp".to_string(),
                ports: vec![80, 443, 8080, 8443],
                probe_string: "GET / HTTP/1.0\\r\\n\\r\\n".to_string(),
                matches: vec![
                    ServiceMatch {
                        pattern: "HTTP/1\\.[01] \\d+ .*Server: Apache/([\\d.]+)".to_string(),
                        service: "http".to_string(),
                        version: Some("Apache $1".to_string()),
                        info: None,
                        hostname: None,
                        os: None,
                        device_type: None,
                        cpe: vec!["cpe:/a:apache:http_server:$1".to_string()],
                    },
                    ServiceMatch {
                        pattern: "HTTP/1\\.[01] \\d+ .*Server: nginx/([\\d.]+)".to_string(),
                        service: "http".to_string(),
                        version: Some("nginx $1".to_string()),
                        info: None,
                        hostname: None,
                        os: None,
                        device_type: None,
                        cpe: vec!["cpe:/a:nginx:nginx:$1".to_string()],
                    },
                ],
            },
            ServiceProbe {
                name: "SSH".to_string(),
                protocol: "tcp".to_string(),
                ports: vec![22],
                probe_string: "".to_string(), // SSH sends banner immediately
                matches: vec![
                    ServiceMatch {
                        pattern: "SSH-([\\d.]+)-OpenSSH_([\\d.]+)".to_string(),
                        service: "ssh".to_string(),
                        version: Some("OpenSSH $2 (protocol $1)".to_string()),
                        info: None,
                        hostname: None,
                        os: None,
                        device_type: None,
                        cpe: vec!["cpe:/a:openbsd:openssh:$2".to_string()],
                    },
                ],
            },
        ];

        for probe in probes {
            self.service_probes.insert(probe.name.clone(), probe);
        }

        Ok(())
    }
}

impl Default for DataManager {
    fn default() -> Self {
        let mut manager = Self::new();
        let _ = manager.load_default_data();
        manager
    }
}

/// Parse nmap-services format
pub fn parse_services_file(content: &str) -> Result<Vec<ServiceInfo>> {
    let mut services = Vec::new();
    
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let name = parts[0].to_string();
            let port_proto = parts[1];
            let frequency = parts[2].parse::<f32>().unwrap_or(0.0);
            
            if let Some((port_str, protocol)) = port_proto.split_once('/') {
                if let Ok(port) = port_str.parse::<u16>() {
                    services.push(ServiceInfo {
                        name,
                        port,
                        protocol: protocol.to_string(),
                        description: parts.get(3).map(|s| s.to_string()),
                        frequency,
                    });
                }
            }
        }
    }
    
    Ok(services)
}

/// Parse nmap-mac-prefixes format
pub fn parse_mac_prefixes_file(content: &str) -> Result<Vec<MacPrefix>> {
    let mut prefixes = Vec::new();
    
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        if let Some((prefix, vendor)) = line.split_once('\t') {
            prefixes.push(MacPrefix {
                prefix: prefix.to_string(),
                vendor: vendor.to_string(),
            });
        }
    }
    
    Ok(prefixes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_lookup() {
        let manager = DataManager::default();
        
        let http_service = manager.lookup_service(80, "tcp");
        assert!(http_service.is_some());
        assert_eq!(http_service.unwrap().name, "http");
        
        let ssh_service = manager.lookup_service(22, "tcp");
        assert!(ssh_service.is_some());
        assert_eq!(ssh_service.unwrap().name, "ssh");
    }

    #[test]
    fn test_protocol_lookup() {
        let manager = DataManager::default();
        
        assert_eq!(manager.lookup_protocol(6), Some(&"tcp".to_string()));
        assert_eq!(manager.lookup_protocol(17), Some(&"udp".to_string()));
        assert_eq!(manager.lookup_protocol(1), Some(&"icmp".to_string()));
    }

    #[test]
    fn test_mac_vendor_lookup() {
        let manager = DataManager::default();
        
        let vendor = manager.lookup_mac_vendor("00:0C:29:12:34:56");
        assert_eq!(vendor, Some(&"VMware".to_string()));
    }

    #[test]
    fn test_parse_services_file() {
        let content = r#"
# Sample services file
http	80/tcp	0.484143	# World Wide Web HTTP
https	443/tcp	0.330151	# HTTP over TLS/SSL
ssh	22/tcp	0.182286	# Secure Shell
"#;
        
        let services = parse_services_file(content).unwrap();
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].name, "http");
        assert_eq!(services[0].port, 80);
        assert_eq!(services[0].protocol, "tcp");
    }
}