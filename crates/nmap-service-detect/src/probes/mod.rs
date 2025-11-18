pub mod basic;
pub mod databases;

use nmap_core::Result;
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

#[derive(Debug)]
pub struct ProbeDatabase {
    probes: Vec<Probe>,
    port_index: HashMap<(u16, String), Vec<usize>>,
}

impl ProbeDatabase {
    pub fn load_default() -> Result<Self> {
        let mut probes = Vec::new();

        // Load basic probes (HTTP, FTP, SSH, etc.)
        probes.extend(basic::load_basic_probes());

        // Load database probes
        probes.extend(databases::load_database_probes());

        // Load message queue probes
        probes.extend(databases::load_message_queue_probes());

        // Build port index
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

    pub fn get_probes_by_protocol(&self, protocol: &str) -> Vec<&Probe> {
        self.probes.iter().filter(|p| p.protocol == protocol).collect()
    }

    pub fn get_probe_count(&self) -> usize {
        self.probes.len()
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
        println!("Loaded {} probes", db.get_probe_count());
        assert!(db.get_probe_count() >= 40, "Should have 40+ probes");
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

    #[test]
    fn test_get_probes_by_protocol() {
        let db = ProbeDatabase::load_default().unwrap();

        let tcp_probes = db.get_probes_by_protocol("tcp");
        assert!(!tcp_probes.is_empty());

        let udp_probes = db.get_probes_by_protocol("udp");
        assert!(!udp_probes.is_empty());
    }

    #[test]
    fn test_database_probes() {
        let db = ProbeDatabase::load_default().unwrap();

        // MySQL
        let mysql_probes = db.get_probes_for_port(3306, "tcp");
        assert!(mysql_probes.iter().any(|p| p.name == "MySQL"));

        // PostgreSQL
        let postgres_probes = db.get_probes_for_port(5432, "tcp");
        assert!(postgres_probes.iter().any(|p| p.name == "PostgreSQL"));

        // Redis
        let redis_probes = db.get_probes_for_port(6379, "tcp");
        assert!(redis_probes.iter().any(|p| p.name == "Redis"));

        // MongoDB
        let mongo_probes = db.get_probes_for_port(27017, "tcp");
        assert!(mongo_probes.iter().any(|p| p.name == "MongoDB"));
    }

    #[test]
    fn test_message_queue_probes() {
        let db = ProbeDatabase::load_default().unwrap();

        // RabbitMQ (AMQP)
        let amqp_probes = db.get_probes_for_port(5672, "tcp");
        assert!(amqp_probes.iter().any(|p| p.name == "AMQP"));

        // Kafka
        let kafka_probes = db.get_probes_for_port(9092, "tcp");
        assert!(kafka_probes.iter().any(|p| p.name == "Kafka"));

        // MQTT
        let mqtt_probes = db.get_probes_for_port(1883, "tcp");
        assert!(mqtt_probes.iter().any(|p| p.name == "MQTT"));
    }

    #[test]
    fn test_remote_access_probes() {
        let db = ProbeDatabase::load_default().unwrap();

        // RDP
        let rdp_probes = db.get_probes_for_port(3389, "tcp");
        assert!(rdp_probes.iter().any(|p| p.name == "RDP"));

        // X11
        let x11_probes = db.get_probes_for_port(6000, "tcp");
        assert!(x11_probes.iter().any(|p| p.name == "X11"));
    }

    #[test]
    fn test_mail_server_probes() {
        let db = ProbeDatabase::load_default().unwrap();

        // SMTP
        let smtp_probes = db.get_probes_for_port(25, "tcp");
        assert!(smtp_probes.iter().any(|p| p.name == "SMTP"));

        // POP3
        let pop3_probes = db.get_probes_for_port(110, "tcp");
        assert!(pop3_probes.iter().any(|p| p.name == "POP3"));

        // IMAP
        let imap_probes = db.get_probes_for_port(143, "tcp");
        assert!(imap_probes.iter().any(|p| p.name == "IMAP"));
    }
}
