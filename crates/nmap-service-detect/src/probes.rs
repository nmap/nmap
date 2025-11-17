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

        // ========== BASIC PROBES ==========

        // NULL probe - just connect
        probes.push(Probe {
            name: "NULL".to_string(),
            protocol: "tcp".to_string(),
            data: vec![],
            ports: (1..=65535).collect(),
            ssl_ports: vec![443, 993, 995, 8443],
            rarity: 1,
            fallback: None,
        });

        // ========== HTTP PROBES ==========

        // HTTP GET probe
        probes.push(Probe {
            name: "GetRequest".to_string(),
            protocol: "tcp".to_string(),
            data: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
            ports: vec![80, 8080, 8000, 8008, 8888, 9000, 3000, 5000],
            ssl_ports: vec![443, 8443],
            rarity: 2,
            fallback: Some("NULL".to_string()),
        });

        // HTTP OPTIONS probe
        probes.push(Probe {
            name: "HTTPOptions".to_string(),
            protocol: "tcp".to_string(),
            data: b"OPTIONS / HTTP/1.0\r\n\r\n".to_vec(),
            ports: vec![80, 8080, 443],
            ssl_ports: vec![443],
            rarity: 3,
            fallback: Some("GetRequest".to_string()),
        });

        // ========== FTP PROBES ==========

        // FTP probe
        probes.push(Probe {
            name: "FTP".to_string(),
            protocol: "tcp".to_string(),
            data: b"HELP\r\n".to_vec(),
            ports: vec![21],
            ssl_ports: vec![990],
            rarity: 3,
            fallback: Some("NULL".to_string()),
        });

        // ========== SSH PROBES ==========

        // SSH probe
        probes.push(Probe {
            name: "SSH".to_string(),
            protocol: "tcp".to_string(),
            data: b"SSH-2.0-Nmap-SSH1-Hostkey\r\n".to_vec(),
            ports: vec![22],
            ssl_ports: vec![],
            rarity: 3,
            fallback: Some("NULL".to_string()),
        });

        // ========== MAIL SERVER PROBES ==========

        // SMTP probe
        probes.push(Probe {
            name: "SMTP".to_string(),
            protocol: "tcp".to_string(),
            data: b"EHLO nmap.scanme.org\r\n".to_vec(),
            ports: vec![25, 587],
            ssl_ports: vec![465],
            rarity: 3,
            fallback: Some("NULL".to_string()),
        });

        // POP3 probe
        probes.push(Probe {
            name: "POP3".to_string(),
            protocol: "tcp".to_string(),
            data: b"CAPA\r\n".to_vec(),
            ports: vec![110],
            ssl_ports: vec![995],
            rarity: 4,
            fallback: Some("NULL".to_string()),
        });

        // IMAP probe
        probes.push(Probe {
            name: "IMAP".to_string(),
            protocol: "tcp".to_string(),
            data: b"A001 CAPABILITY\r\n".to_vec(),
            ports: vec![143],
            ssl_ports: vec![993],
            rarity: 4,
            fallback: Some("NULL".to_string()),
        });

        // ========== DATABASE PROBES ==========

        // MySQL probe
        probes.push(Probe {
            name: "MySQL".to_string(),
            protocol: "tcp".to_string(),
            data: vec![],  // MySQL servers send handshake on connect
            ports: vec![3306],
            ssl_ports: vec![],
            rarity: 5,
            fallback: Some("NULL".to_string()),
        });

        // PostgreSQL probe
        probes.push(Probe {
            name: "PostgreSQL".to_string(),
            protocol: "tcp".to_string(),
            data: vec![
                0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f,
            ],
            ports: vec![5432],
            ssl_ports: vec![],
            rarity: 5,
            fallback: Some("NULL".to_string()),
        });

        // MongoDB probe (using ismaster command)
        probes.push(Probe {
            name: "MongoDB".to_string(),
            protocol: "tcp".to_string(),
            data: vec![],  // MongoDB Wire Protocol - would need proper OP_QUERY packet
            ports: vec![27017, 27018, 27019],
            ssl_ports: vec![],
            rarity: 5,
            fallback: Some("NULL".to_string()),
        });

        // Redis probe
        probes.push(Probe {
            name: "Redis".to_string(),
            protocol: "tcp".to_string(),
            data: b"INFO\r\n".to_vec(),
            ports: vec![6379],
            ssl_ports: vec![],
            rarity: 5,
            fallback: Some("NULL".to_string()),
        });

        // Memcached probe
        probes.push(Probe {
            name: "Memcached".to_string(),
            protocol: "tcp".to_string(),
            data: b"version\r\n".to_vec(),
            ports: vec![11211],
            ssl_ports: vec![],
            rarity: 5,
            fallback: Some("NULL".to_string()),
        });

        // ========== MESSAGE QUEUE PROBES ==========

        // AMQP probe (RabbitMQ)
        probes.push(Probe {
            name: "AMQP".to_string(),
            protocol: "tcp".to_string(),
            data: b"AMQP\x00\x00\x09\x01".to_vec(),
            ports: vec![5672, 5671],
            ssl_ports: vec![5671],
            rarity: 6,
            fallback: Some("NULL".to_string()),
        });

        // Kafka probe (would need proper Kafka protocol)
        probes.push(Probe {
            name: "Kafka".to_string(),
            protocol: "tcp".to_string(),
            data: vec![],  // Kafka Protocol - complex binary protocol
            ports: vec![9092],
            ssl_ports: vec![],
            rarity: 6,
            fallback: Some("NULL".to_string()),
        });

        // MQTT probe
        probes.push(Probe {
            name: "MQTT".to_string(),
            protocol: "tcp".to_string(),
            data: vec![
                0x10, 0x0c, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,
                0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
            ],
            ports: vec![1883],
            ssl_ports: vec![8883],
            rarity: 6,
            fallback: Some("NULL".to_string()),
        });

        // NATS probe
        probes.push(Probe {
            name: "NATS".to_string(),
            protocol: "tcp".to_string(),
            data: vec![],  // NATS sends INFO on connect
            ports: vec![4222, 6222, 8222],
            ssl_ports: vec![],
            rarity: 6,
            fallback: Some("NULL".to_string()),
        });

        // ZeroMQ probe
        probes.push(Probe {
            name: "ZeroMQ".to_string(),
            protocol: "tcp".to_string(),
            data: vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f],
            ports: vec![],
            ssl_ports: vec![],
            rarity: 7,
            fallback: Some("NULL".to_string()),
        });

        // Pulsar probe
        probes.push(Probe {
            name: "Pulsar".to_string(),
            protocol: "tcp".to_string(),
            data: vec![],  // Pulsar binary protocol
            ports: vec![6650, 6651],
            ssl_ports: vec![6651],
            rarity: 7,
            fallback: Some("NULL".to_string()),
        });

        // ========== FILE SERVER PROBES ==========

        // SMB probe
        probes.push(Probe {
            name: "SMB".to_string(),
            protocol: "tcp".to_string(),
            data: vec![
                0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42,
                0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,
            ],
            ports: vec![139, 445],
            ssl_ports: vec![],
            rarity: 5,
            fallback: Some("NULL".to_string()),
        });

        // NFS probe (RPC NULL)
        probes.push(Probe {
            name: "NFS".to_string(),
            protocol: "tcp".to_string(),
            data: vec![
                0x80, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            ],
            ports: vec![2049],
            ssl_ports: vec![],
            rarity: 6,
            fallback: Some("NULL".to_string()),
        });

        // AFP probe (Apple Filing Protocol)
        probes.push(Probe {
            name: "AFP".to_string(),
            protocol: "tcp".to_string(),
            data: vec![
                0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            ],
            ports: vec![548],
            ssl_ports: vec![],
            rarity: 6,
            fallback: Some("NULL".to_string()),
        });

        // TFTP probe
        probes.push(Probe {
            name: "TFTP".to_string(),
            protocol: "udp".to_string(),
            data: vec![
                0x00, 0x01, 0x6e, 0x65, 0x74, 0x61, 0x73, 0x63,
                0x69, 0x69, 0x00, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00,
            ],
            ports: vec![69],
            ssl_ports: vec![],
            rarity: 6,
            fallback: None,
        });

        // ========== REMOTE ACCESS PROBES ==========

        // Telnet probe
        probes.push(Probe {
            name: "Telnet".to_string(),
            protocol: "tcp".to_string(),
            data: vec![0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03, 0xff, 0xfc, 0x22],
            ports: vec![23],
            ssl_ports: vec![],
            rarity: 4,
            fallback: Some("NULL".to_string()),
        });

        // RDP probe
        probes.push(Probe {
            name: "RDP".to_string(),
            protocol: "tcp".to_string(),
            data: vec![
                0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00,
                0x00, 0x00, 0x00,
            ],
            ports: vec![3389],
            ssl_ports: vec![],
            rarity: 5,
            fallback: Some("NULL".to_string()),
        });

        // VNC probe (handled by NULL, sends RFB banner on connect)
        // X11 probe
        probes.push(Probe {
            name: "X11".to_string(),
            protocol: "tcp".to_string(),
            data: vec![
                0x6c, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            ports: vec![6000, 6001, 6002],
            ssl_ports: vec![],
            rarity: 6,
            fallback: Some("NULL".to_string()),
        });

        // TeamViewer probe
        probes.push(Probe {
            name: "TeamViewer".to_string(),
            protocol: "tcp".to_string(),
            data: vec![0x17, 0x24, 0x00, 0x01],
            ports: vec![5938],
            ssl_ports: vec![],
            rarity: 7,
            fallback: Some("NULL".to_string()),
        });

        // ========== DIRECTORY SERVICE PROBES ==========

        // LDAP probe
        probes.push(Probe {
            name: "LDAP".to_string(),
            protocol: "tcp".to_string(),
            data: vec![
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02,
                0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
            ],
            ports: vec![389, 636, 3268, 3269],
            ssl_ports: vec![636, 3269],
            rarity: 5,
            fallback: Some("NULL".to_string()),
        });

        // Kerberos probe
        probes.push(Probe {
            name: "Kerberos".to_string(),
            protocol: "tcp".to_string(),
            data: vec![
                0x00, 0x00, 0x00, 0x00,
            ],
            ports: vec![88],
            ssl_ports: vec![],
            rarity: 6,
            fallback: Some("NULL".to_string()),
        });

        // NIS probe
        probes.push(Probe {
            name: "NIS".to_string(),
            protocol: "tcp".to_string(),
            data: vec![],
            ports: vec![],
            ssl_ports: vec![],
            rarity: 7,
            fallback: Some("NULL".to_string()),
        });

        // RADIUS probe
        probes.push(Probe {
            name: "RADIUS".to_string(),
            protocol: "udp".to_string(),
            data: vec![
                0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            ports: vec![1812, 1813],
            ssl_ports: vec![],
            rarity: 6,
            fallback: None,
        });

        // ========== NETWORK MANAGEMENT PROBES ==========

        // DNS probe
        probes.push(Probe {
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
        });

        // SNMP v1 probe
        probes.push(Probe {
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
        });

        // SNMP v3 probe
        probes.push(Probe {
            name: "SNMPv3GetRequest".to_string(),
            protocol: "udp".to_string(),
            data: vec![
                0x30, 0x3a, 0x02, 0x01, 0x03, 0x30, 0x0f, 0x02,
                0x02, 0x4a, 0x69, 0x02, 0x03, 0x00, 0xff, 0xe3,
                0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10,
                0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02,
                0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00,
                0x30, 0x12, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0c,
                0x02, 0x02, 0x37, 0xf0, 0x02, 0x01, 0x00, 0x02,
                0x01, 0x00, 0x30, 0x00,
            ],
            ports: vec![161],
            ssl_ports: vec![],
            rarity: 6,
            fallback: Some("SNMPv1GetRequest".to_string()),
        });

        // ========== MONITORING PROBES ==========

        // Zabbix probe
        probes.push(Probe {
            name: "Zabbix".to_string(),
            protocol: "tcp".to_string(),
            data: b"ZBXD\x01".to_vec(),
            ports: vec![10050, 10051],
            ssl_ports: vec![],
            rarity: 6,
            fallback: Some("NULL".to_string()),
        });

        // ========== VERSION CONTROL PROBES ==========

        // Git protocol probe
        probes.push(Probe {
            name: "Git".to_string(),
            protocol: "tcp".to_string(),
            data: b"git-upload-pack /\0host=nmap\0".to_vec(),
            ports: vec![9418],
            ssl_ports: vec![],
            rarity: 6,
            fallback: Some("NULL".to_string()),
        });

        // SVN probe
        probes.push(Probe {
            name: "SVN".to_string(),
            protocol: "tcp".to_string(),
            data: b"( 2 ( edit-pipeline svndiff1 absent-entries commit-revprops depth log-revprops atomic-revprops partial-replay inherited-props ephemeral-txnprops file-revs-reverse list ) 36:svn://host/svn/test-repository ) ".to_vec(),
            ports: vec![3690],
            ssl_ports: vec![],
            rarity: 6,
            fallback: Some("NULL".to_string()),
        });

        // ========== OTHER PROTOCOL PROBES ==========

        // MSSQL probe (TDS protocol)
        probes.push(Probe {
            name: "MSSQL".to_string(),
            protocol: "tcp".to_string(),
            data: vec![
                0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,
            ],
            ports: vec![1433, 1434],
            ssl_ports: vec![],
            rarity: 5,
            fallback: Some("NULL".to_string()),
        });

        // Oracle probe (TNS protocol)
        probes.push(Probe {
            name: "Oracle".to_string(),
            protocol: "tcp".to_string(),
            data: vec![
                0x00, 0x3a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00,
            ],
            ports: vec![1521, 1526],
            ssl_ports: vec![],
            rarity: 5,
            fallback: Some("NULL".to_string()),
        });

        // Cassandra probe (CQL native protocol)
        probes.push(Probe {
            name: "Cassandra".to_string(),
            protocol: "tcp".to_string(),
            data: vec![0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            ports: vec![9042, 9160],
            ssl_ports: vec![],
            rarity: 6,
            fallback: Some("NULL".to_string()),
        });

        // SQLite probe (not typically networked, but included for completeness)
        probes.push(Probe {
            name: "SQLite".to_string(),
            protocol: "tcp".to_string(),
            data: vec![],
            ports: vec![],
            ssl_ports: vec![],
            rarity: 9,
            fallback: Some("NULL".to_string()),
        });

        // ========== BUILD INDICES ==========

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
    fn test_file_server_probes() {
        let db = ProbeDatabase::load_default().unwrap();

        // SMB
        let smb_probes = db.get_probes_for_port(445, "tcp");
        assert!(smb_probes.iter().any(|p| p.name == "SMB"));

        // NFS
        let nfs_probes = db.get_probes_for_port(2049, "tcp");
        assert!(nfs_probes.iter().any(|p| p.name == "NFS"));

        // AFP
        let afp_probes = db.get_probes_for_port(548, "tcp");
        assert!(afp_probes.iter().any(|p| p.name == "AFP"));
    }

    #[test]
    fn test_directory_service_probes() {
        let db = ProbeDatabase::load_default().unwrap();

        // LDAP
        let ldap_probes = db.get_probes_for_port(389, "tcp");
        assert!(ldap_probes.iter().any(|p| p.name == "LDAP"));

        // Kerberos
        let kerberos_probes = db.get_probes_for_port(88, "tcp");
        assert!(kerberos_probes.iter().any(|p| p.name == "Kerberos"));
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
