use crate::ServiceInfo;
use nmap_core::{NmapError, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSignature {
    pub service_name: String,
    pub probe_name: String,
    pub pattern: String,
    pub version_info: Option<VersionInfo>,
    pub ports: Vec<u16>,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub product: Option<String>,
    pub version: Option<String>,
    pub info: Option<String>,
    pub hostname: Option<String>,
    pub os_type: Option<String>,
    pub device_type: Option<String>,
    pub cpe: Vec<String>,
}

#[derive(Debug)]
pub struct SignatureDatabase {
    signatures: Vec<ServiceSignature>,
    compiled_patterns: HashMap<usize, Regex>,
    service_index: HashMap<String, Vec<usize>>,
    probe_index: HashMap<String, Vec<usize>>,
    port_index: HashMap<u16, Vec<usize>>,
}

impl SignatureDatabase {
    pub fn load_default() -> Result<Self> {
        let mut signatures = Vec::new();

        // ========== WEB SERVERS (10) ==========

        // Generic HTTP
        signatures.push(ServiceSignature {
            service_name: "http".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"HTTP/1\.[01] \d+ ".to_string(),
            version_info: Some(VersionInfo {
                product: Some("HTTP server".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:http:http_server".to_string()],
            }),
            ports: vec![80, 8080, 8000, 8008, 8888, 9000],
            protocol: "tcp".to_string(),
        });

        // Apache HTTP Server
        signatures.push(ServiceSignature {
            service_name: "http".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Server: Apache/([0-9.]+)(?:\s+\(([^)]+)\))?".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Apache httpd".to_string()),
                version: Some("$1".to_string()),
                info: Some("$2".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:apache:http_server:$1".to_string()],
            }),
            ports: vec![80, 8080, 443, 8443],
            protocol: "tcp".to_string(),
        });

        // Nginx
        signatures.push(ServiceSignature {
            service_name: "http".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Server: nginx/([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("nginx".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:nginx:nginx:$1".to_string()],
            }),
            ports: vec![80, 8080, 443, 8443],
            protocol: "tcp".to_string(),
        });

        // Microsoft IIS
        signatures.push(ServiceSignature {
            service_name: "http".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Server: Microsoft-IIS/([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Microsoft IIS httpd".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: Some("Windows".to_string()),
                device_type: None,
                cpe: vec!["cpe:/a:microsoft:iis:$1".to_string()],
            }),
            ports: vec![80, 8080, 443],
            protocol: "tcp".to_string(),
        });

        // Apache Tomcat
        signatures.push(ServiceSignature {
            service_name: "http".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Server: Apache-Coyote/([0-9.]+)|Apache Tomcat/([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Apache Tomcat".to_string()),
                version: Some("$1$2".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:apache:tomcat:$1$2".to_string()],
            }),
            ports: vec![8080, 8009, 8443],
            protocol: "tcp".to_string(),
        });

        // Jetty
        signatures.push(ServiceSignature {
            service_name: "http".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Server: Jetty\(([0-9.]+[^)]*)\)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Jetty".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:eclipse:jetty:$1".to_string()],
            }),
            ports: vec![8080, 8443],
            protocol: "tcp".to_string(),
        });

        // Lighttpd
        signatures.push(ServiceSignature {
            service_name: "http".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Server: lighttpd/([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("lighttpd".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:lighttpd:lighttpd:$1".to_string()],
            }),
            ports: vec![80, 8080, 443],
            protocol: "tcp".to_string(),
        });

        // Node.js
        signatures.push(ServiceSignature {
            service_name: "http".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"X-Powered-By: Express|Node\.js".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Node.js".to_string()),
                version: None,
                info: Some("Express framework".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:nodejs:node.js".to_string()],
            }),
            ports: vec![3000, 8080, 8000],
            protocol: "tcp".to_string(),
        });

        // Gunicorn
        signatures.push(ServiceSignature {
            service_name: "http".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Server: gunicorn/([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Gunicorn".to_string()),
                version: Some("$1".to_string()),
                info: Some("Python WSGI HTTP Server".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:gunicorn:gunicorn:$1".to_string()],
            }),
            ports: vec![8000, 8080],
            protocol: "tcp".to_string(),
        });

        // Caddy
        signatures.push(ServiceSignature {
            service_name: "http".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Server: Caddy|caddy".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Caddy".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:caddyserver:caddy".to_string()],
            }),
            ports: vec![80, 443, 2015],
            protocol: "tcp".to_string(),
        });

        // ========== DATABASES (15) ==========

        // MySQL
        signatures.push(ServiceSignature {
            service_name: "mysql".to_string(),
            probe_name: "MySQL".to_string(),
            pattern: r"([0-9.]+)-MariaDB|([0-9.]+).*MySQL".to_string(),
            version_info: Some(VersionInfo {
                product: Some("MySQL".to_string()),
                version: Some("$1$2".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:mysql:mysql:$1$2".to_string()],
            }),
            ports: vec![3306],
            protocol: "tcp".to_string(),
        });

        // PostgreSQL
        signatures.push(ServiceSignature {
            service_name: "postgresql".to_string(),
            probe_name: "PostgreSQL".to_string(),
            pattern: r"PostgreSQL.*([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("PostgreSQL".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:postgresql:postgresql:$1".to_string()],
            }),
            ports: vec![5432],
            protocol: "tcp".to_string(),
        });

        // MongoDB
        signatures.push(ServiceSignature {
            service_name: "mongodb".to_string(),
            probe_name: "MongoDB".to_string(),
            pattern: r"MongoDB.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("MongoDB".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:mongodb:mongodb:$1".to_string()],
            }),
            ports: vec![27017, 27018, 27019],
            protocol: "tcp".to_string(),
        });

        // Redis
        signatures.push(ServiceSignature {
            service_name: "redis".to_string(),
            probe_name: "Redis".to_string(),
            pattern: r"\$[0-9]+\r\n.*redis_version:([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Redis".to_string()),
                version: Some("$1".to_string()),
                info: Some("key-value store".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:redis:redis:$1".to_string()],
            }),
            ports: vec![6379],
            protocol: "tcp".to_string(),
        });

        // Memcached
        signatures.push(ServiceSignature {
            service_name: "memcached".to_string(),
            probe_name: "Memcached".to_string(),
            pattern: r"VERSION ([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Memcached".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:memcached:memcached:$1".to_string()],
            }),
            ports: vec![11211],
            protocol: "tcp".to_string(),
        });

        // Elasticsearch
        signatures.push(ServiceSignature {
            service_name: "elasticsearch".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r#""version"\s*:\s*\{\s*"number"\s*:\s*"([0-9.]+)""#.to_string(),
            version_info: Some(VersionInfo {
                product: Some("Elasticsearch".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:elasticsearch:elasticsearch:$1".to_string()],
            }),
            ports: vec![9200, 9300],
            protocol: "tcp".to_string(),
        });

        // CouchDB
        signatures.push(ServiceSignature {
            service_name: "couchdb".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r#""couchdb":"Welcome".*"version":"([0-9.]+)""#.to_string(),
            version_info: Some(VersionInfo {
                product: Some("Apache CouchDB".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:apache:couchdb:$1".to_string()],
            }),
            ports: vec![5984],
            protocol: "tcp".to_string(),
        });

        // Apache Cassandra
        signatures.push(ServiceSignature {
            service_name: "cassandra".to_string(),
            probe_name: "Cassandra".to_string(),
            pattern: r"Cassandra.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Apache Cassandra".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:apache:cassandra:$1".to_string()],
            }),
            ports: vec![9042, 9160],
            protocol: "tcp".to_string(),
        });

        // InfluxDB
        signatures.push(ServiceSignature {
            service_name: "influxdb".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"X-Influxdb-Version: ([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("InfluxDB".to_string()),
                version: Some("$1".to_string()),
                info: Some("Time series database".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:influxdata:influxdb:$1".to_string()],
            }),
            ports: vec![8086],
            protocol: "tcp".to_string(),
        });

        // MariaDB
        signatures.push(ServiceSignature {
            service_name: "mysql".to_string(),
            probe_name: "MySQL".to_string(),
            pattern: r"([0-9.]+)-MariaDB".to_string(),
            version_info: Some(VersionInfo {
                product: Some("MariaDB".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:mariadb:mariadb:$1".to_string()],
            }),
            ports: vec![3306],
            protocol: "tcp".to_string(),
        });

        // Oracle Database
        signatures.push(ServiceSignature {
            service_name: "oracle".to_string(),
            probe_name: "Oracle".to_string(),
            pattern: r"Oracle.*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Oracle Database".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:oracle:database_server:$1".to_string()],
            }),
            ports: vec![1521, 1526],
            protocol: "tcp".to_string(),
        });

        // Microsoft SQL Server
        signatures.push(ServiceSignature {
            service_name: "mssql".to_string(),
            probe_name: "MSSQL".to_string(),
            pattern: r"Microsoft SQL Server.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Microsoft SQL Server".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: Some("Windows".to_string()),
                device_type: None,
                cpe: vec!["cpe:/a:microsoft:sql_server:$1".to_string()],
            }),
            ports: vec![1433, 1434],
            protocol: "tcp".to_string(),
        });

        // Neo4j
        signatures.push(ServiceSignature {
            service_name: "neo4j".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r#""neo4j_version"\s*:\s*"([0-9.]+)""#.to_string(),
            version_info: Some(VersionInfo {
                product: Some("Neo4j".to_string()),
                version: Some("$1".to_string()),
                info: Some("Graph database".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:neo4j:neo4j:$1".to_string()],
            }),
            ports: vec![7474, 7687],
            protocol: "tcp".to_string(),
        });

        // RethinkDB
        signatures.push(ServiceSignature {
            service_name: "rethinkdb".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"RethinkDB.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("RethinkDB".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:rethinkdb:rethinkdb:$1".to_string()],
            }),
            ports: vec![28015, 29015, 8080],
            protocol: "tcp".to_string(),
        });

        // SQLite (network exposed via various means)
        signatures.push(ServiceSignature {
            service_name: "sqlite".to_string(),
            probe_name: "SQLite".to_string(),
            pattern: r"SQLite.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("SQLite".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:sqlite:sqlite:$1".to_string()],
            }),
            ports: vec![],
            protocol: "tcp".to_string(),
        });

        // ========== SSH & REMOTE ACCESS (10) ==========

        // Generic SSH
        signatures.push(ServiceSignature {
            service_name: "ssh".to_string(),
            probe_name: "NULL".to_string(),
            pattern: r"SSH-([0-9.]+)-(.+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("$2".to_string()),
                version: Some("protocol $1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:ssh:ssh:$1".to_string()],
            }),
            ports: vec![22],
            protocol: "tcp".to_string(),
        });

        // OpenSSH
        signatures.push(ServiceSignature {
            service_name: "ssh".to_string(),
            probe_name: "NULL".to_string(),
            pattern: r"SSH-2\.0-OpenSSH_([0-9.]+[p0-9]*)(?:\s+(.+))?".to_string(),
            version_info: Some(VersionInfo {
                product: Some("OpenSSH".to_string()),
                version: Some("$1".to_string()),
                info: Some("$2".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:openbsd:openssh:$1".to_string()],
            }),
            ports: vec![22],
            protocol: "tcp".to_string(),
        });

        // Dropbear SSH
        signatures.push(ServiceSignature {
            service_name: "ssh".to_string(),
            probe_name: "NULL".to_string(),
            pattern: r"SSH-2\.0-dropbear_([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Dropbear sshd".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: Some("embedded".to_string()),
                cpe: vec!["cpe:/a:matt_johnston:dropbear_ssh_server:$1".to_string()],
            }),
            ports: vec![22],
            protocol: "tcp".to_string(),
        });

        // Telnet
        signatures.push(ServiceSignature {
            service_name: "telnet".to_string(),
            probe_name: "NULL".to_string(),
            pattern: r".*(?:login|Username|password).*:".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Telnet server".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:telnet:telnet_server".to_string()],
            }),
            ports: vec![23],
            protocol: "tcp".to_string(),
        });

        // Microsoft RDP
        signatures.push(ServiceSignature {
            service_name: "rdp".to_string(),
            probe_name: "RDP".to_string(),
            pattern: r".*RDP.*".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Microsoft Terminal Services".to_string()),
                version: None,
                info: Some("RDP".to_string()),
                hostname: None,
                os_type: Some("Windows".to_string()),
                device_type: None,
                cpe: vec!["cpe:/a:microsoft:terminal_services".to_string()],
            }),
            ports: vec![3389],
            protocol: "tcp".to_string(),
        });

        // VNC
        signatures.push(ServiceSignature {
            service_name: "vnc".to_string(),
            probe_name: "NULL".to_string(),
            pattern: r"RFB ([0-9]{3}\.[0-9]{3})".to_string(),
            version_info: Some(VersionInfo {
                product: Some("VNC".to_string()),
                version: Some("protocol $1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:realvnc:vnc:$1".to_string()],
            }),
            ports: vec![5900, 5901, 5902],
            protocol: "tcp".to_string(),
        });

        // RealVNC
        signatures.push(ServiceSignature {
            service_name: "vnc".to_string(),
            probe_name: "NULL".to_string(),
            pattern: r"RFB.*RealVNC".to_string(),
            version_info: Some(VersionInfo {
                product: Some("RealVNC".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:realvnc:vnc".to_string()],
            }),
            ports: vec![5900],
            protocol: "tcp".to_string(),
        });

        // TightVNC
        signatures.push(ServiceSignature {
            service_name: "vnc".to_string(),
            probe_name: "NULL".to_string(),
            pattern: r"RFB.*TightVNC".to_string(),
            version_info: Some(VersionInfo {
                product: Some("TightVNC".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:tightvnc:tightvnc".to_string()],
            }),
            ports: vec![5900],
            protocol: "tcp".to_string(),
        });

        // X11
        signatures.push(ServiceSignature {
            service_name: "x11".to_string(),
            probe_name: "X11".to_string(),
            pattern: r"^[BNl].*".to_string(),
            version_info: Some(VersionInfo {
                product: Some("X11 server".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:x:x11".to_string()],
            }),
            ports: vec![6000, 6001, 6002],
            protocol: "tcp".to_string(),
        });

        // TeamViewer
        signatures.push(ServiceSignature {
            service_name: "teamviewer".to_string(),
            probe_name: "TeamViewer".to_string(),
            pattern: r"TeamViewer".to_string(),
            version_info: Some(VersionInfo {
                product: Some("TeamViewer".to_string()),
                version: None,
                info: Some("Remote desktop software".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:teamviewer:teamviewer".to_string()],
            }),
            ports: vec![5938],
            protocol: "tcp".to_string(),
        });

        // ========== FTP & FILE SERVERS (10) ==========

        // Generic FTP
        signatures.push(ServiceSignature {
            service_name: "ftp".to_string(),
            probe_name: "NULL".to_string(),
            pattern: r"220.*FTP".to_string(),
            version_info: Some(VersionInfo {
                product: Some("FTP server".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:ftp:ftp_server".to_string()],
            }),
            ports: vec![21],
            protocol: "tcp".to_string(),
        });

        // vsftpd
        signatures.push(ServiceSignature {
            service_name: "ftp".to_string(),
            probe_name: "NULL".to_string(),
            pattern: r"220.*vsftpd ([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("vsftpd".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:vsftpd:vsftpd:$1".to_string()],
            }),
            ports: vec![21],
            protocol: "tcp".to_string(),
        });

        // ProFTPD
        signatures.push(ServiceSignature {
            service_name: "ftp".to_string(),
            probe_name: "NULL".to_string(),
            pattern: r"220.*ProFTPD ([0-9.]+[a-z]*)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("ProFTPD".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:proftpd:proftpd:$1".to_string()],
            }),
            ports: vec![21],
            protocol: "tcp".to_string(),
        });

        // Pure-FTPd
        signatures.push(ServiceSignature {
            service_name: "ftp".to_string(),
            probe_name: "NULL".to_string(),
            pattern: r"220.*Pure-FTPd".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Pure-FTPd".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:pureftpd:pure-ftpd".to_string()],
            }),
            ports: vec![21],
            protocol: "tcp".to_string(),
        });

        // FileZilla FTP
        signatures.push(ServiceSignature {
            service_name: "ftp".to_string(),
            probe_name: "NULL".to_string(),
            pattern: r"220.*FileZilla Server ([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("FileZilla ftpd".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:filezilla:ftp_server:$1".to_string()],
            }),
            ports: vec![21],
            protocol: "tcp".to_string(),
        });

        // Samba/SMB
        signatures.push(ServiceSignature {
            service_name: "smb".to_string(),
            probe_name: "SMB".to_string(),
            pattern: r"Samba ([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Samba smbd".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:samba:samba:$1".to_string()],
            }),
            ports: vec![139, 445],
            protocol: "tcp".to_string(),
        });

        // Microsoft Windows SMB
        signatures.push(ServiceSignature {
            service_name: "smb".to_string(),
            probe_name: "SMB".to_string(),
            pattern: r"Windows.*SMB".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Microsoft Windows SMB".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: Some("Windows".to_string()),
                device_type: None,
                cpe: vec!["cpe:/o:microsoft:windows".to_string()],
            }),
            ports: vec![139, 445],
            protocol: "tcp".to_string(),
        });

        // TFTP
        signatures.push(ServiceSignature {
            service_name: "tftp".to_string(),
            probe_name: "TFTP".to_string(),
            pattern: r".*".to_string(),
            version_info: Some(VersionInfo {
                product: Some("TFTP server".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:tftp:tftp_server".to_string()],
            }),
            ports: vec![69],
            protocol: "udp".to_string(),
        });

        // NFS
        signatures.push(ServiceSignature {
            service_name: "nfs".to_string(),
            probe_name: "NFS".to_string(),
            pattern: r".*".to_string(),
            version_info: Some(VersionInfo {
                product: Some("NFS".to_string()),
                version: None,
                info: Some("Network File System".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:nfs:nfs".to_string()],
            }),
            ports: vec![2049],
            protocol: "tcp".to_string(),
        });

        // AFP (Apple Filing Protocol)
        signatures.push(ServiceSignature {
            service_name: "afp".to_string(),
            probe_name: "AFP".to_string(),
            pattern: r"AFP.*([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Apple Filing Protocol".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: Some("Mac OS X".to_string()),
                device_type: None,
                cpe: vec!["cpe:/a:apple:afp:$1".to_string()],
            }),
            ports: vec![548],
            protocol: "tcp".to_string(),
        });

        // ========== MAIL SERVERS (8) ==========

        // Generic SMTP
        signatures.push(ServiceSignature {
            service_name: "smtp".to_string(),
            probe_name: "NULL".to_string(),
            pattern: r"220.*SMTP|220.*ESMTP".to_string(),
            version_info: Some(VersionInfo {
                product: Some("SMTP server".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:smtp:smtp_server".to_string()],
            }),
            ports: vec![25, 587, 465],
            protocol: "tcp".to_string(),
        });

        // Postfix
        signatures.push(ServiceSignature {
            service_name: "smtp".to_string(),
            probe_name: "SMTP".to_string(),
            pattern: r"220.*Postfix".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Postfix smtpd".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:postfix:postfix".to_string()],
            }),
            ports: vec![25, 587],
            protocol: "tcp".to_string(),
        });

        // Sendmail
        signatures.push(ServiceSignature {
            service_name: "smtp".to_string(),
            probe_name: "SMTP".to_string(),
            pattern: r"220.*Sendmail ([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Sendmail smtpd".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:sendmail:sendmail:$1".to_string()],
            }),
            ports: vec![25, 587],
            protocol: "tcp".to_string(),
        });

        // Exim
        signatures.push(ServiceSignature {
            service_name: "smtp".to_string(),
            probe_name: "SMTP".to_string(),
            pattern: r"220.*Exim ([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Exim smtpd".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:exim:exim:$1".to_string()],
            }),
            ports: vec![25, 587],
            protocol: "tcp".to_string(),
        });

        // Microsoft Exchange
        signatures.push(ServiceSignature {
            service_name: "smtp".to_string(),
            probe_name: "SMTP".to_string(),
            pattern: r"220.*Microsoft ESMTP MAIL Service".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Microsoft Exchange smtpd".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: Some("Windows".to_string()),
                device_type: None,
                cpe: vec!["cpe:/a:microsoft:exchange_server".to_string()],
            }),
            ports: vec![25, 587],
            protocol: "tcp".to_string(),
        });

        // Dovecot
        signatures.push(ServiceSignature {
            service_name: "imap".to_string(),
            probe_name: "IMAP".to_string(),
            pattern: r"Dovecot.*ready".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Dovecot imapd".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:dovecot:dovecot".to_string()],
            }),
            ports: vec![143, 993],
            protocol: "tcp".to_string(),
        });

        // Courier
        signatures.push(ServiceSignature {
            service_name: "imap".to_string(),
            probe_name: "IMAP".to_string(),
            pattern: r"Courier-IMAP".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Courier imapd".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:courier:courier_imap".to_string()],
            }),
            ports: vec![143, 993],
            protocol: "tcp".to_string(),
        });

        // Cyrus
        signatures.push(ServiceSignature {
            service_name: "imap".to_string(),
            probe_name: "IMAP".to_string(),
            pattern: r"Cyrus.*IMAP.*v([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Cyrus imapd".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:cmu:cyrus_imap_server:$1".to_string()],
            }),
            ports: vec![143, 993],
            protocol: "tcp".to_string(),
        });

        // ========== MESSAGE QUEUES (8) ==========

        // RabbitMQ
        signatures.push(ServiceSignature {
            service_name: "rabbitmq".to_string(),
            probe_name: "AMQP".to_string(),
            pattern: r"AMQP.*RabbitMQ".to_string(),
            version_info: Some(VersionInfo {
                product: Some("RabbitMQ".to_string()),
                version: None,
                info: Some("AMQP message broker".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:pivotal_software:rabbitmq".to_string()],
            }),
            ports: vec![5672, 15672],
            protocol: "tcp".to_string(),
        });

        // Apache Kafka
        signatures.push(ServiceSignature {
            service_name: "kafka".to_string(),
            probe_name: "Kafka".to_string(),
            pattern: r"Kafka".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Apache Kafka".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:apache:kafka".to_string()],
            }),
            ports: vec![9092],
            protocol: "tcp".to_string(),
        });

        // ActiveMQ
        signatures.push(ServiceSignature {
            service_name: "activemq".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"ActiveMQ".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Apache ActiveMQ".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:apache:activemq".to_string()],
            }),
            ports: vec![61616, 8161],
            protocol: "tcp".to_string(),
        });

        // ZeroMQ
        signatures.push(ServiceSignature {
            service_name: "zeromq".to_string(),
            probe_name: "ZeroMQ".to_string(),
            pattern: r"ZMTP".to_string(),
            version_info: Some(VersionInfo {
                product: Some("ZeroMQ".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:zeromq:zeromq".to_string()],
            }),
            ports: vec![],
            protocol: "tcp".to_string(),
        });

        // NATS
        signatures.push(ServiceSignature {
            service_name: "nats".to_string(),
            probe_name: "NATS".to_string(),
            pattern: r"INFO.*nats.*version.*([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("NATS".to_string()),
                version: Some("$1".to_string()),
                info: Some("Message broker".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:nats:nats-server:$1".to_string()],
            }),
            ports: vec![4222, 6222, 8222],
            protocol: "tcp".to_string(),
        });

        // Apache Pulsar
        signatures.push(ServiceSignature {
            service_name: "pulsar".to_string(),
            probe_name: "Pulsar".to_string(),
            pattern: r"Pulsar".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Apache Pulsar".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:apache:pulsar".to_string()],
            }),
            ports: vec![6650, 8080],
            protocol: "tcp".to_string(),
        });

        // MQTT
        signatures.push(ServiceSignature {
            service_name: "mqtt".to_string(),
            probe_name: "MQTT".to_string(),
            pattern: r"MQTT.*".to_string(),
            version_info: Some(VersionInfo {
                product: Some("MQTT broker".to_string()),
                version: None,
                info: Some("IoT messaging protocol".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:mqtt:mqtt".to_string()],
            }),
            ports: vec![1883, 8883],
            protocol: "tcp".to_string(),
        });

        // Redis Pub/Sub
        signatures.push(ServiceSignature {
            service_name: "redis-pubsub".to_string(),
            probe_name: "Redis".to_string(),
            pattern: r"redis.*pub.*sub".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Redis Pub/Sub".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:redis:redis".to_string()],
            }),
            ports: vec![6379],
            protocol: "tcp".to_string(),
        });

        // ========== PROXIES & LOAD BALANCERS (6) ==========

        // Squid
        signatures.push(ServiceSignature {
            service_name: "http-proxy".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Server: squid/([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Squid http proxy".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:squid-cache:squid:$1".to_string()],
            }),
            ports: vec![3128, 8080],
            protocol: "tcp".to_string(),
        });

        // HAProxy
        signatures.push(ServiceSignature {
            service_name: "http-proxy".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"HAProxy".to_string(),
            version_info: Some(VersionInfo {
                product: Some("HAProxy".to_string()),
                version: None,
                info: Some("load balancer".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:haproxy:haproxy".to_string()],
            }),
            ports: vec![80, 443, 8080],
            protocol: "tcp".to_string(),
        });

        // Varnish
        signatures.push(ServiceSignature {
            service_name: "http-proxy".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"X-Varnish|Via:.*varnish".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Varnish http accelerator".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:varnish-cache:varnish".to_string()],
            }),
            ports: vec![80, 6081, 6082],
            protocol: "tcp".to_string(),
        });

        // Traefik
        signatures.push(ServiceSignature {
            service_name: "http-proxy".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Server: Traefik".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Traefik".to_string()),
                version: None,
                info: Some("Reverse proxy and load balancer".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:traefik:traefik".to_string()],
            }),
            ports: vec![80, 443, 8080],
            protocol: "tcp".to_string(),
        });

        // Envoy
        signatures.push(ServiceSignature {
            service_name: "http-proxy".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"server: envoy".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Envoy proxy".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:envoyproxy:envoy".to_string()],
            }),
            ports: vec![10000, 15000],
            protocol: "tcp".to_string(),
        });

        // Nginx as Reverse Proxy
        signatures.push(ServiceSignature {
            service_name: "http-proxy".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Server: nginx.*X-Proxy".to_string(),
            version_info: Some(VersionInfo {
                product: Some("nginx reverse proxy".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:nginx:nginx".to_string()],
            }),
            ports: vec![80, 443, 8080],
            protocol: "tcp".to_string(),
        });

        // ========== DIRECTORY SERVICES (5) ==========

        // OpenLDAP
        signatures.push(ServiceSignature {
            service_name: "ldap".to_string(),
            probe_name: "LDAP".to_string(),
            pattern: r"OpenLDAP.*([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("OpenLDAP".to_string()),
                version: Some("$1".to_string()),
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:openldap:openldap:$1".to_string()],
            }),
            ports: vec![389, 636],
            protocol: "tcp".to_string(),
        });

        // Active Directory
        signatures.push(ServiceSignature {
            service_name: "ldap".to_string(),
            probe_name: "LDAP".to_string(),
            pattern: r"Active Directory".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Microsoft Active Directory LDAP".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: Some("Windows".to_string()),
                device_type: None,
                cpe: vec!["cpe:/a:microsoft:active_directory".to_string()],
            }),
            ports: vec![389, 636, 3268, 3269],
            protocol: "tcp".to_string(),
        });

        // Kerberos
        signatures.push(ServiceSignature {
            service_name: "kerberos".to_string(),
            probe_name: "Kerberos".to_string(),
            pattern: r"krb5".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Kerberos".to_string()),
                version: None,
                info: Some("Authentication service".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:mit:kerberos".to_string()],
            }),
            ports: vec![88],
            protocol: "tcp".to_string(),
        });

        // NIS
        signatures.push(ServiceSignature {
            service_name: "nis".to_string(),
            probe_name: "NIS".to_string(),
            pattern: r"ypbind".to_string(),
            version_info: Some(VersionInfo {
                product: Some("NIS".to_string()),
                version: None,
                info: Some("Network Information Service".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:nis:nis".to_string()],
            }),
            ports: vec![],
            protocol: "tcp".to_string(),
        });

        // RADIUS
        signatures.push(ServiceSignature {
            service_name: "radius".to_string(),
            probe_name: "RADIUS".to_string(),
            pattern: r".*".to_string(),
            version_info: Some(VersionInfo {
                product: Some("RADIUS".to_string()),
                version: None,
                info: Some("Authentication server".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:radius:radius".to_string()],
            }),
            ports: vec![1812, 1813],
            protocol: "udp".to_string(),
        });

        // ========== MONITORING & MANAGEMENT (8) ==========

        // Nagios
        signatures.push(ServiceSignature {
            service_name: "nagios".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Nagios".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Nagios".to_string()),
                version: None,
                info: Some("Monitoring system".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:nagios:nagios".to_string()],
            }),
            ports: vec![],
            protocol: "tcp".to_string(),
        });

        // Zabbix
        signatures.push(ServiceSignature {
            service_name: "zabbix".to_string(),
            probe_name: "Zabbix".to_string(),
            pattern: r"ZBXD".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Zabbix".to_string()),
                version: None,
                info: Some("Monitoring system".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:zabbix:zabbix".to_string()],
            }),
            ports: vec![10050, 10051],
            protocol: "tcp".to_string(),
        });

        // Prometheus
        signatures.push(ServiceSignature {
            service_name: "prometheus".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"prometheus".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Prometheus".to_string()),
                version: None,
                info: Some("Monitoring system and time series database".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:prometheus:prometheus".to_string()],
            }),
            ports: vec![9090],
            protocol: "tcp".to_string(),
        });

        // Grafana
        signatures.push(ServiceSignature {
            service_name: "grafana".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Grafana".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Grafana".to_string()),
                version: None,
                info: Some("Analytics and monitoring dashboard".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:grafana:grafana".to_string()],
            }),
            ports: vec![3000],
            protocol: "tcp".to_string(),
        });

        // SNMP
        signatures.push(ServiceSignature {
            service_name: "snmp".to_string(),
            probe_name: "SNMPv1GetRequest".to_string(),
            pattern: r".*".to_string(),
            version_info: Some(VersionInfo {
                product: Some("SNMP".to_string()),
                version: None,
                info: Some("Simple Network Management Protocol".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:snmp:snmp".to_string()],
            }),
            ports: vec![161],
            protocol: "udp".to_string(),
        });

        // Netdata
        signatures.push(ServiceSignature {
            service_name: "netdata".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"netdata".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Netdata".to_string()),
                version: None,
                info: Some("Real-time performance monitoring".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:netdata:netdata".to_string()],
            }),
            ports: vec![19999],
            protocol: "tcp".to_string(),
        });

        // Datadog Agent
        signatures.push(ServiceSignature {
            service_name: "datadog".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Datadog".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Datadog Agent".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:datadog:datadog_agent".to_string()],
            }),
            ports: vec![8125, 8126],
            protocol: "tcp".to_string(),
        });

        // New Relic
        signatures.push(ServiceSignature {
            service_name: "newrelic".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"New Relic".to_string(),
            version_info: Some(VersionInfo {
                product: Some("New Relic".to_string()),
                version: None,
                info: Some("Application performance monitoring".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:newrelic:newrelic".to_string()],
            }),
            ports: vec![],
            protocol: "tcp".to_string(),
        });

        // ========== OTHER SERVICES (10) ==========

        // Docker API
        signatures.push(ServiceSignature {
            service_name: "docker".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r#""Platform".*"Name":"Docker""#.to_string(),
            version_info: Some(VersionInfo {
                product: Some("Docker API".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:docker:docker".to_string()],
            }),
            ports: vec![2375, 2376],
            protocol: "tcp".to_string(),
        });

        // Kubernetes API
        signatures.push(ServiceSignature {
            service_name: "kubernetes".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r#""major":"[0-9]+".*"minor":"[0-9]+""#.to_string(),
            version_info: Some(VersionInfo {
                product: Some("Kubernetes API".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:kubernetes:kubernetes".to_string()],
            }),
            ports: vec![6443, 8443, 443],
            protocol: "tcp".to_string(),
        });

        // Git
        signatures.push(ServiceSignature {
            service_name: "git".to_string(),
            probe_name: "Git".to_string(),
            pattern: r"git".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Git".to_string()),
                version: None,
                info: Some("Version control system".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:git:git".to_string()],
            }),
            ports: vec![9418],
            protocol: "tcp".to_string(),
        });

        // Subversion (SVN)
        signatures.push(ServiceSignature {
            service_name: "svn".to_string(),
            probe_name: "SVN".to_string(),
            pattern: r"SVN".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Subversion".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:apache:subversion".to_string()],
            }),
            ports: vec![3690],
            protocol: "tcp".to_string(),
        });

        // Jenkins
        signatures.push(ServiceSignature {
            service_name: "jenkins".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"X-Jenkins.*([0-9.]+)".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Jenkins".to_string()),
                version: Some("$1".to_string()),
                info: Some("Continuous integration server".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:jenkins:jenkins:$1".to_string()],
            }),
            ports: vec![8080, 8081],
            protocol: "tcp".to_string(),
        });

        // GitLab
        signatures.push(ServiceSignature {
            service_name: "gitlab".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"GitLab".to_string(),
            version_info: Some(VersionInfo {
                product: Some("GitLab".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:gitlab:gitlab".to_string()],
            }),
            ports: vec![80, 443],
            protocol: "tcp".to_string(),
        });

        // Consul
        signatures.push(ServiceSignature {
            service_name: "consul".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Consul".to_string(),
            version_info: Some(VersionInfo {
                product: Some("HashiCorp Consul".to_string()),
                version: None,
                info: Some("Service mesh solution".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:hashicorp:consul".to_string()],
            }),
            ports: vec![8500, 8600],
            protocol: "tcp".to_string(),
        });

        // Etcd
        signatures.push(ServiceSignature {
            service_name: "etcd".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r#""etcdserver":"([0-9.]+)""#.to_string(),
            version_info: Some(VersionInfo {
                product: Some("etcd".to_string()),
                version: Some("$1".to_string()),
                info: Some("Distributed key-value store".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:etcd:etcd:$1".to_string()],
            }),
            ports: vec![2379, 2380],
            protocol: "tcp".to_string(),
        });

        // POP3
        signatures.push(ServiceSignature {
            service_name: "pop3".to_string(),
            probe_name: "POP3".to_string(),
            pattern: r"\+OK.*POP3".to_string(),
            version_info: Some(VersionInfo {
                product: Some("POP3 server".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:pop3:pop3_server".to_string()],
            }),
            ports: vec![110, 995],
            protocol: "tcp".to_string(),
        });

        // IMAP
        signatures.push(ServiceSignature {
            service_name: "imap".to_string(),
            probe_name: "IMAP".to_string(),
            pattern: r"\* OK.*IMAP".to_string(),
            version_info: Some(VersionInfo {
                product: Some("IMAP server".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:imap:imap_server".to_string()],
            }),
            ports: vec![143, 993],
            protocol: "tcp".to_string(),
        });

        // DNS
        signatures.push(ServiceSignature {
            service_name: "dns".to_string(),
            probe_name: "DNSVersionBindReq".to_string(),
            pattern: r".*".to_string(),
            version_info: Some(VersionInfo {
                product: Some("DNS server".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:dns:dns_server".to_string()],
            }),
            ports: vec![53],
            protocol: "udp".to_string(),
        });

        // ========== ADDITIONAL SERVICES (10+) ==========

        // Uvicorn (Python ASGI server)
        signatures.push(ServiceSignature {
            service_name: "http".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Server: uvicorn".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Uvicorn".to_string()),
                version: None,
                info: Some("ASGI server".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:uvicorn:uvicorn".to_string()],
            }),
            ports: vec![8000, 8080],
            protocol: "tcp".to_string(),
        });

        // Minecraft Server
        signatures.push(ServiceSignature {
            service_name: "minecraft".to_string(),
            probe_name: "Minecraft".to_string(),
            pattern: r".*".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Minecraft Server".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:mojang:minecraft_server".to_string()],
            }),
            ports: vec![25565],
            protocol: "tcp".to_string(),
        });

        // OpenVPN
        signatures.push(ServiceSignature {
            service_name: "openvpn".to_string(),
            probe_name: "OpenVPN".to_string(),
            pattern: r"OpenVPN".to_string(),
            version_info: Some(VersionInfo {
                product: Some("OpenVPN".to_string()),
                version: None,
                info: Some("VPN service".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:openvpn:openvpn".to_string()],
            }),
            ports: vec![1194],
            protocol: "udp".to_string(),
        });

        // Elasticsearch (alternative pattern)
        signatures.push(ServiceSignature {
            service_name: "elasticsearch".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r#""name"\s*:\s*"[^"]+",\s*"cluster_name""#.to_string(),
            version_info: Some(VersionInfo {
                product: Some("Elasticsearch".to_string()),
                version: None,
                info: Some("Search engine".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:elasticsearch:elasticsearch".to_string()],
            }),
            ports: vec![9200],
            protocol: "tcp".to_string(),
        });

        // Rsync
        signatures.push(ServiceSignature {
            service_name: "rsync".to_string(),
            probe_name: "Rsync".to_string(),
            pattern: r"@RSYNCD:".to_string(),
            version_info: Some(VersionInfo {
                product: Some("rsync".to_string()),
                version: None,
                info: Some("File synchronization".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:rsync:rsync".to_string()],
            }),
            ports: vec![873],
            protocol: "tcp".to_string(),
        });

        // Mumble (VoIP)
        signatures.push(ServiceSignature {
            service_name: "mumble".to_string(),
            probe_name: "Mumble".to_string(),
            pattern: r".*".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Mumble VoIP".to_string()),
                version: None,
                info: Some("Voice chat server".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:mumble:mumble".to_string()],
            }),
            ports: vec![64738],
            protocol: "tcp".to_string(),
        });

        // Elasticsearch Kibana
        signatures.push(ServiceSignature {
            service_name: "kibana".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r#""name":"Kibana""#.to_string(),
            version_info: Some(VersionInfo {
                product: Some("Kibana".to_string()),
                version: None,
                info: Some("Elasticsearch visualization".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:elasticsearch:kibana".to_string()],
            }),
            ports: vec![5601],
            protocol: "tcp".to_string(),
        });

        // Logstash
        signatures.push(ServiceSignature {
            service_name: "logstash".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Logstash".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Logstash".to_string()),
                version: None,
                info: Some("Log processing pipeline".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:elasticsearch:logstash".to_string()],
            }),
            ports: vec![9600],
            protocol: "tcp".to_string(),
        });

        // SonarQube
        signatures.push(ServiceSignature {
            service_name: "sonarqube".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"SonarQube".to_string(),
            version_info: Some(VersionInfo {
                product: Some("SonarQube".to_string()),
                version: None,
                info: Some("Code quality platform".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:sonarsource:sonarqube".to_string()],
            }),
            ports: vec![9000],
            protocol: "tcp".to_string(),
        });

        // Splunk
        signatures.push(ServiceSignature {
            service_name: "splunk".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"Splunk".to_string(),
            version_info: Some(VersionInfo {
                product: Some("Splunk".to_string()),
                version: None,
                info: Some("Log analysis platform".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:splunk:splunk".to_string()],
            }),
            ports: vec![8000, 8089],
            protocol: "tcp".to_string(),
        });

        // InfluxDB (alternative pattern)
        signatures.push(ServiceSignature {
            service_name: "influxdb".to_string(),
            probe_name: "GetRequest".to_string(),
            pattern: r"influxdb".to_string(),
            version_info: Some(VersionInfo {
                product: Some("InfluxDB".to_string()),
                version: None,
                info: Some("Time series database".to_string()),
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:influxdata:influxdb".to_string()],
            }),
            ports: vec![8086, 8088],
            protocol: "tcp".to_string(),
        });

        // qmail
        signatures.push(ServiceSignature {
            service_name: "smtp".to_string(),
            probe_name: "SMTP".to_string(),
            pattern: r"220.*qmail".to_string(),
            version_info: Some(VersionInfo {
                product: Some("qmail smtpd".to_string()),
                version: None,
                info: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:qmail:qmail".to_string()],
            }),
            ports: vec![25, 587],
            protocol: "tcp".to_string(),
        });

        // Build indices
        let mut compiled_patterns = HashMap::new();
        let mut service_index = HashMap::new();
        let mut probe_index = HashMap::new();
        let mut port_index = HashMap::new();

        for (i, sig) in signatures.iter().enumerate() {
            // Compile regex pattern lazily
            if let Ok(regex) = Regex::new(&sig.pattern) {
                compiled_patterns.insert(i, regex);
            }

            // Build service index
            service_index.entry(sig.service_name.clone())
                .or_insert_with(Vec::new)
                .push(i);

            // Build probe index
            probe_index.entry(sig.probe_name.clone())
                .or_insert_with(Vec::new)
                .push(i);

            // Build port index
            for &port in &sig.ports {
                port_index.entry(port)
                    .or_insert_with(Vec::new)
                    .push(i);
            }
        }

        Ok(Self {
            signatures,
            compiled_patterns,
            service_index,
            probe_index,
            port_index,
        })
    }

    pub fn match_banner(&self, banner: &str, port: u16, protocol: &str) -> Result<ServiceInfo> {
        // Try to match banner against all signatures
        // First, try port-specific signatures for better accuracy
        if let Some(indices) = self.port_index.get(&port) {
            for &i in indices {
                let signature = &self.signatures[i];

                if signature.protocol != protocol {
                    continue;
                }

                if let Some(regex) = self.compiled_patterns.get(&i) {
                    if let Some(captures) = regex.captures(banner) {
                        return Ok(self.build_service_info(signature, &captures));
                    }
                }
            }
        }

        // Fall back to trying all signatures
        for (i, signature) in self.signatures.iter().enumerate() {
            if signature.protocol != protocol {
                continue;
            }

            if !signature.ports.is_empty() && !signature.ports.contains(&port) {
                continue;
            }

            if let Some(regex) = self.compiled_patterns.get(&i) {
                if let Some(captures) = regex.captures(banner) {
                    return Ok(self.build_service_info(signature, &captures));
                }
            }
        }

        Err(NmapError::Other("Service not detected".to_string()))
    }

    pub fn match_probe_response(
        &self,
        response: &str,
        probe_name: &str,
        port: u16,
        protocol: &str,
    ) -> Result<ServiceInfo> {
        // Get signatures for this probe
        if let Some(indices) = self.probe_index.get(probe_name) {
            for &i in indices {
                let signature = &self.signatures[i];

                if signature.protocol != protocol {
                    continue;
                }

                if !signature.ports.is_empty() && !signature.ports.contains(&port) {
                    continue;
                }

                if let Some(regex) = self.compiled_patterns.get(&i) {
                    if let Some(captures) = regex.captures(response) {
                        return Ok(self.build_service_info(signature, &captures));
                    }
                }
            }
        }

        Err(NmapError::Other("Service not detected".to_string()))
    }

    fn build_service_info(&self, signature: &ServiceSignature, captures: &regex::Captures) -> ServiceInfo {
        let mut service = ServiceInfo {
            name: signature.service_name.clone(),
            product: None,
            version: None,
            extra_info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: Vec::new(),
            confidence: 95, // High confidence for regex matches
        };

        if let Some(ref version_info) = signature.version_info {
            service.product = version_info.product.as_ref().map(|p| self.substitute_captures(p, captures));
            service.version = version_info.version.as_ref().map(|v| self.substitute_captures(v, captures));
            service.extra_info = version_info.info.as_ref().map(|i| self.substitute_captures(i, captures));
            service.hostname = version_info.hostname.as_ref().map(|h| self.substitute_captures(h, captures));
            service.os_type = version_info.os_type.clone();
            service.device_type = version_info.device_type.clone();

            service.cpe = version_info.cpe.iter()
                .map(|cpe| self.substitute_captures(cpe, captures))
                .collect();
        }

        service
    }

    fn substitute_captures(&self, template: &str, captures: &regex::Captures) -> String {
        let mut result = template.to_string();

        // Replace $1, $2, etc. with capture groups
        for i in 1..captures.len() {
            if let Some(capture) = captures.get(i) {
                let placeholder = format!("${}", i);
                result = result.replace(&placeholder, capture.as_str());
            }
        }

        result
    }

    pub fn get_signatures_for_service(&self, service_name: &str) -> Vec<&ServiceSignature> {
        if let Some(indices) = self.service_index.get(service_name) {
            indices.iter().map(|&i| &self.signatures[i]).collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_signatures_for_probe(&self, probe_name: &str) -> Vec<&ServiceSignature> {
        if let Some(indices) = self.probe_index.get(probe_name) {
            indices.iter().map(|&i| &self.signatures[i]).collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_signatures_for_port(&self, port: u16) -> Vec<&ServiceSignature> {
        if let Some(indices) = self.port_index.get(&port) {
            indices.iter().map(|&i| &self.signatures[i]).collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_all_signatures(&self) -> &[ServiceSignature] {
        &self.signatures
    }

    pub fn get_signature_count(&self) -> usize {
        self.signatures.len()
    }

    pub fn get_service_categories(&self) -> Vec<String> {
        let mut categories: Vec<String> = self.service_index.keys().cloned().collect();
        categories.sort();
        categories
    }
}

impl Clone for SignatureDatabase {
    fn clone(&self) -> Self {
        // Note: Regex doesn't implement Clone, so we need to recompile
        let mut compiled_patterns = HashMap::new();
        for (i, signature) in self.signatures.iter().enumerate() {
            if let Ok(regex) = Regex::new(&signature.pattern) {
                compiled_patterns.insert(i, regex);
            }
        }

        Self {
            signatures: self.signatures.clone(),
            compiled_patterns,
            service_index: self.service_index.clone(),
            probe_index: self.probe_index.clone(),
            port_index: self.port_index.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_database_creation() {
        let db = SignatureDatabase::load_default().unwrap();
        assert!(!db.signatures.is_empty());
        assert!(!db.compiled_patterns.is_empty());
        println!("Loaded {} signatures", db.get_signature_count());
        assert!(db.get_signature_count() >= 100, "Should have 100+ signatures");
    }

    #[test]
    fn test_match_apache_banner() {
        let db = SignatureDatabase::load_default().unwrap();

        let apache_banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n";
        let result = db.match_banner(apache_banner, 80, "tcp");
        assert!(result.is_ok());

        let service = result.unwrap();
        assert_eq!(service.name, "http");
        assert_eq!(service.product, Some("Apache httpd".to_string()));
        assert_eq!(service.version, Some("2.4.41".to_string()));
    }

    #[test]
    fn test_match_nginx_banner() {
        let db = SignatureDatabase::load_default().unwrap();

        let nginx_banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n";
        let result = db.match_banner(nginx_banner, 80, "tcp");
        assert!(result.is_ok());

        let service = result.unwrap();
        assert_eq!(service.name, "http");
        assert_eq!(service.product, Some("nginx".to_string()));
        assert_eq!(service.version, Some("1.18.0".to_string()));
    }

    #[test]
    fn test_match_ssh_banner() {
        let db = SignatureDatabase::load_default().unwrap();

        let ssh_banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3";
        let result = db.match_banner(ssh_banner, 22, "tcp");
        assert!(result.is_ok());

        let service = result.unwrap();
        assert_eq!(service.name, "ssh");
        assert_eq!(service.product, Some("OpenSSH".to_string()));
        assert_eq!(service.version, Some("8.2p1".to_string()));
    }

    #[test]
    fn test_match_mysql_banner() {
        let db = SignatureDatabase::load_default().unwrap();

        let mysql_banner = "5.7.33-0ubuntu0.18.04.1-MySQL";
        let result = db.match_banner(mysql_banner, 3306, "tcp");
        assert!(result.is_ok());

        let service = result.unwrap();
        assert_eq!(service.name, "mysql");
    }

    #[test]
    fn test_match_redis_banner() {
        let db = SignatureDatabase::load_default().unwrap();

        let redis_banner = "$256\r\n# Server\r\nredis_version:6.2.5\r\n";
        let result = db.match_banner(redis_banner, 6379, "tcp");
        assert!(result.is_ok());

        let service = result.unwrap();
        assert_eq!(service.name, "redis");
        assert_eq!(service.product, Some("Redis".to_string()));
        assert_eq!(service.version, Some("6.2.5".to_string()));
    }

    #[test]
    fn test_match_ftp_banners() {
        let db = SignatureDatabase::load_default().unwrap();

        // vsftpd
        let vsftpd_banner = "220 (vsFTPd 3.0.3)";
        let result = db.match_banner(vsftpd_banner, 21, "tcp");
        assert!(result.is_ok());
        let service = result.unwrap();
        assert_eq!(service.product, Some("vsftpd".to_string()));

        // ProFTPD
        let proftpd_banner = "220 ProFTPD 1.3.6 Server";
        let result = db.match_banner(proftpd_banner, 21, "tcp");
        assert!(result.is_ok());
        let service = result.unwrap();
        assert_eq!(service.product, Some("ProFTPD".to_string()));
    }

    #[test]
    fn test_get_signatures_for_port() {
        let db = SignatureDatabase::load_default().unwrap();

        let http_sigs = db.get_signatures_for_port(80);
        assert!(!http_sigs.is_empty());

        let ssh_sigs = db.get_signatures_for_port(22);
        assert!(!ssh_sigs.is_empty());
    }

    #[test]
    fn test_get_service_categories() {
        let db = SignatureDatabase::load_default().unwrap();

        let categories = db.get_service_categories();
        assert!(!categories.is_empty());

        // Should include major service types
        assert!(categories.contains(&"http".to_string()));
        assert!(categories.contains(&"ssh".to_string()));
        assert!(categories.contains(&"ftp".to_string()));
        assert!(categories.contains(&"smtp".to_string()));
        assert!(categories.contains(&"mysql".to_string()));
    }

    #[test]
    fn test_no_match() {
        let db = SignatureDatabase::load_default().unwrap();

        let unknown_banner = "UNKNOWN PROTOCOL XYZ123";
        let result = db.match_banner(unknown_banner, 12345, "tcp");
        assert!(result.is_err());
    }

    #[test]
    fn test_web_server_signatures() {
        let db = SignatureDatabase::load_default().unwrap();

        // Test IIS
        let iis_banner = "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n";
        let result = db.match_banner(iis_banner, 80, "tcp");
        assert!(result.is_ok());
        let service = result.unwrap();
        assert_eq!(service.product, Some("Microsoft IIS httpd".to_string()));
        assert_eq!(service.os_type, Some("Windows".to_string()));

        // Test Tomcat
        let tomcat_banner = "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n";
        let result = db.match_banner(tomcat_banner, 8080, "tcp");
        assert!(result.is_ok());
        let service = result.unwrap();
        assert_eq!(service.product, Some("Apache Tomcat".to_string()));
    }

    #[test]
    fn test_database_signatures() {
        let db = SignatureDatabase::load_default().unwrap();

        // Test PostgreSQL
        let postgres_banner = "PostgreSQL 13.3";
        let result = db.match_banner(postgres_banner, 5432, "tcp");
        assert!(result.is_ok());
        let service = result.unwrap();
        assert_eq!(service.name, "postgresql");
        assert_eq!(service.product, Some("PostgreSQL".to_string()));

        // Test MongoDB
        let mongo_banner = "MongoDB 4.4.6";
        let result = db.match_banner(mongo_banner, 27017, "tcp");
        assert!(result.is_ok());
        let service = result.unwrap();
        assert_eq!(service.name, "mongodb");
    }

    #[test]
    fn test_mail_server_signatures() {
        let db = SignatureDatabase::load_default().unwrap();

        // Test Postfix
        let postfix_banner = "220 mail.example.com ESMTP Postfix";
        let result = db.match_banner(postfix_banner, 25, "tcp");
        assert!(result.is_ok());
        let service = result.unwrap();
        assert_eq!(service.product, Some("Postfix smtpd".to_string()));

        // Test Exim
        let exim_banner = "220 mail.example.com ESMTP Exim 4.94.2";
        let result = db.match_banner(exim_banner, 25, "tcp");
        assert!(result.is_ok());
        let service = result.unwrap();
        assert_eq!(service.product, Some("Exim smtpd".to_string()));
    }
}
