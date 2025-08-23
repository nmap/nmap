use nmap_core::{NmapError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub name: String,
    pub protocol: String,
    pub data: Vec<u8>,
    pub ports: Vec<u16>,
    pub ssl_ports: Vec<u16>,
    pub rarity: u8,
    pub fallback: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProbeDatabase {
    probes: Vec<Probe>,
    port_index: HashMap<(u16, String), Vec<usize>>,
}

impl ProbeDatabase {
    pub fn load_default() -> Result<Self> {
        // In a real implementation, this would load from nmap-service-probes
        // For now, we'll create a minimal database with common probes
        let probes = vec![
            // NULL probe - just connect
            Probe {
                name: "NULL".to_string(),
                protocol: "tcp".to_string(),
                data: vec![],
                ports: (1..=65535).collect(),
                ssl_ports: vec![443, 993, 995, 8443],
                rarity: 1,
                fallback: None,
            },
            
            // HTTP GET probe
            Probe {
                name: "GetRequest".to_string(),
                protocol: "tcp".to_string(),
                data: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
                ports: vec![80, 8080, 8000, 8008, 8888, 9000],
                ssl_ports: vec![443, 8443],
                rarity: 2,
                fallback: Some("NULL".to_string()),
            },
            
            // FTP probe
            Probe {
                name: "FTP".to_string(),
                protocol: "tcp".to_string(),
                data: b"HELP\r\n".to_vec(),
                ports: vec![21],
                ssl_ports: vec![990],
                rarity: 3,
                fallback: Some("NULL".to_string()),
            },
            
            // SSH probe
            Probe {
                name: "SSH".to_string(),
                protocol: "tcp".to_string(),
                data: b"SSH-2.0-Nmap-SSH1-Hostkey\r\n".to_vec(),
                ports: vec![22],
                ssl_ports: vec![],
                rarity: 3,
                fallback: Some("NULL".to_string()),
            },
            
            // SMTP probe
            Probe {
                name: "SMTP".to_string(),
                protocol: "tcp".to_string(),
                data: b"EHLO nmap.scanme.org\r\n".to_vec(),
                ports: vec![25, 587],
                ssl_ports: vec![465],
                rarity: 3,
                fallback: Some("NULL".to_string()),
            },
            
            // DNS probe
            Probe {
                name: "DNSVersionBindReq".to_string(),
                protocol: "udp".to_string(),
                data: vec![
                    0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x07, 0x76, 0x65, 0x72,
                    0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e,
                    0x64, 0x00, 0x00, 0x10, 0x00, 0x03,
                ],
                ports: vec![53],
                ssl_ports: vec![],
                rarity: 4,
                fallback: None,
            },
            
            // POP3 probe
            Probe {
                name: "POP3".to_string(),
                protocol: "tcp".to_string(),
                data: b"CAPA\r\n".to_vec(),
                ports: vec![110],
                ssl_ports: vec![995],
                rarity: 4,
                fallback: Some("NULL".to_string()),
            },
            
            // IMAP probe
            Probe {
                name: "IMAP".to_string(),
                protocol: "tcp".to_string(),
                data: b"A001 CAPABILITY\r\n".to_vec(),
                ports: vec![143],
                ssl_ports: vec![993],
                rarity: 4,
                fallback: Some("NULL".to_string()),
            },
            
            // Telnet probe
            Probe {
                name: "Telnet".to_string(),
                protocol: "tcp".to_string(),
                data: vec![0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03, 0xff, 0xfc, 0x22],
                ports: vec![23],
                ssl_ports: vec![],
                rarity: 4,
                fallback: Some("NULL".to_string()),
            },
            
            // SNMP probe
            Probe {
                name: "SNMPv1GetRequest".to_string(),
                protocol: "udp".to_string(),
                data: vec![
                    0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
                    0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
                    0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00,
                    0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06,
                    0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
                ],
                ports: vec![161],
                ssl_ports: vec![],
                rarity: 5,
                fallback: None,
            },
        ];

        let mut port_index = HashMap::new();
        for (i, probe) in probes.iter().enumerate() {
            for &port in &probe.ports {
                let key = (port, probe.protocol.clone());
                port_index.entry(key).or_insert_with(Vec::new).push(i);
            }
        }

        Ok(Self { probes, port_index })
    }

    pub fn get_probes_for_port(&self, port: u16, protocol: &str) -> Vec<&Probe> {
        let key = (port, protocol.to_string());
        if let Some(indices) = self.port_index.get(&key) {
            indices.iter().map(|&i| &self.probes[i]).collect()
        } else {
            // Return NULL probe as fallback
            self.probes.iter().filter(|p| p.name == "NULL").collect()
        }
    }

    pub fn get_probe_by_name(&self, name: &str) -> Option<&Probe> {
        self.probes.iter().find(|p| p.name == name)
    }

    pub fn get_all_probes(&self) -> &[Probe] {
        &self.probes
    }

    pub fn get_probes_by_rarity(&self, max_rarity: u8) -> Vec<&Probe> {
        self.probes.iter().filter(|p| p.rarity <= max_rarity).collect()
    }
}

impl Clone for ProbeDatabase {
    fn clone(&self) -> Self {
        Self {
            probes: self.probes.clone(),
            port_index: self.port_index.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_database_creation() {
        let db = ProbeDatabase::load_default().unwrap();
        assert!(!db.probes.is_empty());
        assert!(!db.port_index.is_empty());
    }

    #[test]
    fn test_get_probes_for_port() {
        let db = ProbeDatabase::load_default().unwrap();
        
        // Test HTTP port
        let http_probes = db.get_probes_for_port(80, "tcp");
        assert!(!http_probes.is_empty());
        assert!(http_probes.iter().any(|p| p.name == "GetRequest"));
        
        // Test SSH port
        let ssh_probes = db.get_probes_for_port(22, "tcp");
        assert!(!ssh_probes.is_empty());
        assert!(ssh_probes.iter().any(|p| p.name == "SSH"));
        
        // Test unknown port should return NULL probe
        let unknown_probes = db.get_probes_for_port(12345, "tcp");
        assert!(!unknown_probes.is_empty());
        assert!(unknown_probes.iter().any(|p| p.name == "NULL"));
    }

    #[test]
    fn test_get_probe_by_name() {
        let db = ProbeDatabase::load_default().unwrap();
        
        let http_probe = db.get_probe_by_name("GetRequest");
        assert!(http_probe.is_some());
        assert_eq!(http_probe.unwrap().name, "GetRequest");
        
        let nonexistent = db.get_probe_by_name("NonExistent");
        assert!(nonexistent.is_none());
    }

    #[test]
    fn test_get_probes_by_rarity() {
        let db = ProbeDatabase::load_default().unwrap();
        
        let common_probes = db.get_probes_by_rarity(3);
        assert!(!common_probes.is_empty());
        
        let all_probes = db.get_probes_by_rarity(10);
        assert_eq!(all_probes.len(), db.probes.len());
    }
}