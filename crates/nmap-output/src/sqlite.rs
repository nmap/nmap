use anyhow::Result;
use nmap_net::{Host, HostState, Port, PortState};
use rusqlite::{params, Connection};
use std::path::Path;

pub async fn generate_sqlite_database<P: AsRef<Path>>(
    results: &[Host],
    output_path: P,
    duration: std::time::Duration,
) -> Result<()> {
    let conn = Connection::open(output_path)?;

    // Create schema
    create_schema(&conn)?;

    // Insert scan metadata
    let scan_id = insert_scan_metadata(&conn, results.len(), duration)?;

    // Insert hosts and their data
    for host in results {
        insert_host(&conn, scan_id, host)?;
    }

    // Create indexes for performance
    create_indexes(&conn)?;

    Ok(())
}

fn create_schema(conn: &Connection) -> Result<()> {
    // Scans table - metadata about each scan
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date TEXT NOT NULL,
            scanner_name TEXT NOT NULL,
            scanner_version TEXT NOT NULL,
            duration_seconds REAL NOT NULL,
            total_hosts INTEGER NOT NULL,
            hosts_up INTEGER NOT NULL,
            hosts_down INTEGER NOT NULL,
            total_ports_scanned INTEGER NOT NULL,
            command_line TEXT
        )",
        [],
    )?;

    // Hosts table - discovered hosts
    conn.execute(
        "CREATE TABLE IF NOT EXISTS hosts (
            host_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            hostname TEXT,
            state TEXT NOT NULL,
            mac_address TEXT,
            discovered_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        )",
        [],
    )?;

    // Ports table - port information for each host
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ports (
            port_id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port_number INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            version TEXT,
            reason TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts(host_id) ON DELETE CASCADE
        )",
        [],
    )?;

    // OS information table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS os_info (
            os_id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            os_name TEXT NOT NULL,
            os_family TEXT NOT NULL,
            os_generation TEXT,
            os_vendor TEXT NOT NULL,
            accuracy INTEGER NOT NULL,
            FOREIGN KEY (host_id) REFERENCES hosts(host_id) ON DELETE CASCADE
        )",
        [],
    )?;

    // Vulnerabilities table (for future use)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS vulnerabilities (
            vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port_id INTEGER,
            vuln_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            cve_id TEXT,
            discovered_at TEXT NOT NULL,
            FOREIGN KEY (host_id) REFERENCES hosts(host_id) ON DELETE CASCADE,
            FOREIGN KEY (port_id) REFERENCES ports(port_id) ON DELETE CASCADE
        )",
        [],
    )?;

    // Services table - aggregated service information
    conn.execute(
        "CREATE TABLE IF NOT EXISTS services (
            service_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            service_name TEXT NOT NULL,
            port_number INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            occurrences INTEGER NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        )",
        [],
    )?;

    Ok(())
}

fn create_indexes(conn: &Connection) -> Result<()> {
    // Performance indexes
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_hosts_state ON hosts(state)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ports_host_id ON ports(host_id)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ports_number ON ports(port_number)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ports_state ON ports(state)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ports_service ON ports(service)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_os_host_id ON os_info(host_id)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_vulns_host_id ON vulnerabilities(host_id)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_vulns_port_id ON vulnerabilities(port_id)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_services_scan_id ON services(scan_id)",
        [],
    )?;

    Ok(())
}

fn insert_scan_metadata(
    conn: &Connection,
    total_hosts: usize,
    duration: std::time::Duration,
) -> Result<i64> {
    let scan_date = chrono::Utc::now().to_rfc3339();
    let command_line = std::env::args().collect::<Vec<_>>().join(" ");

    conn.execute(
        "INSERT INTO scans (
            scan_date,
            scanner_name,
            scanner_version,
            duration_seconds,
            total_hosts,
            hosts_up,
            hosts_down,
            total_ports_scanned,
            command_line
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            scan_date,
            nmap_core::RMAP_NAME,
            nmap_core::RMAP_VERSION,
            duration.as_secs_f64(),
            total_hosts,
            0, // Will be updated after counting
            0, // Will be updated after counting
            0, // Will be updated after counting
            command_line,
        ],
    )?;

    let scan_id = conn.last_insert_rowid();

    Ok(scan_id)
}

fn insert_host(conn: &Connection, scan_id: i64, host: &Host) -> Result<()> {
    let discovered_at = chrono::Utc::now().to_rfc3339();

    // Insert host
    conn.execute(
        "INSERT INTO hosts (
            scan_id,
            ip_address,
            hostname,
            state,
            mac_address,
            discovered_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            scan_id,
            host.address.to_string(),
            host.hostname.as_deref(),
            format!("{:?}", host.state),
            host.mac_address.as_deref(),
            discovered_at,
        ],
    )?;

    let host_id = conn.last_insert_rowid();

    // Insert ports
    for port in &host.ports {
        insert_port(conn, host_id, port)?;
    }

    // Insert OS information
    if let Some(os_info) = &host.os_info {
        conn.execute(
            "INSERT INTO os_info (
                host_id,
                os_name,
                os_family,
                os_generation,
                os_vendor,
                accuracy
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                host_id,
                os_info.name,
                os_info.family,
                os_info.generation.as_deref(),
                os_info.vendor,
                os_info.accuracy,
            ],
        )?;
    }

    // Update scan statistics
    update_scan_statistics(conn, scan_id, host)?;

    Ok(())
}

fn insert_port(conn: &Connection, host_id: i64, port: &Port) -> Result<()> {
    conn.execute(
        "INSERT INTO ports (
            host_id,
            port_number,
            protocol,
            state,
            service,
            version,
            reason
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            host_id,
            port.number,
            format!("{:?}", port.protocol),
            format!("{:?}", port.state),
            port.service.as_deref(),
            port.version.as_deref(),
            port.reason.as_deref(),
        ],
    )?;

    Ok(())
}

fn update_scan_statistics(conn: &Connection, scan_id: i64, host: &Host) -> Result<()> {
    // Update host counts
    match host.state {
        HostState::Up => {
            conn.execute(
                "UPDATE scans SET hosts_up = hosts_up + 1 WHERE scan_id = ?1",
                params![scan_id],
            )?;
        }
        HostState::Down => {
            conn.execute(
                "UPDATE scans SET hosts_down = hosts_down + 1 WHERE scan_id = ?1",
                params![scan_id],
            )?;
        }
        _ => {}
    }

    // Update port count
    conn.execute(
        "UPDATE scans SET total_ports_scanned = total_ports_scanned + ?1 WHERE scan_id = ?2",
        params![host.ports.len(), scan_id],
    )?;

    // Update service aggregates
    for port in &host.ports {
        if matches!(port.state, PortState::Open) {
            if let Some(service) = &port.service {
                // Check if service already exists
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM services WHERE scan_id = ?1 AND service_name = ?2 AND port_number = ?3",
                    params![scan_id, service, port.number],
                    |row| row.get(0),
                )?;

                if count > 0 {
                    conn.execute(
                        "UPDATE services SET occurrences = occurrences + 1
                         WHERE scan_id = ?1 AND service_name = ?2 AND port_number = ?3",
                        params![scan_id, service, port.number],
                    )?;
                } else {
                    conn.execute(
                        "INSERT INTO services (scan_id, service_name, port_number, protocol, occurrences)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![scan_id, service, port.number, format!("{:?}", port.protocol), 1],
                    )?;
                }
            }
        }
    }

    Ok(())
}

/// Helper function to query scan results from the database
pub fn query_scan_summary(db_path: &str) -> Result<Vec<ScanSummary>> {
    let conn = Connection::open(db_path)?;

    let mut stmt = conn.prepare(
        "SELECT scan_id, scan_date, scanner_name, scanner_version,
                duration_seconds, total_hosts, hosts_up, hosts_down,
                total_ports_scanned, command_line
         FROM scans
         ORDER BY scan_date DESC",
    )?;

    let summaries = stmt.query_map([], |row| {
        Ok(ScanSummary {
            scan_id: row.get(0)?,
            scan_date: row.get(1)?,
            scanner_name: row.get(2)?,
            scanner_version: row.get(3)?,
            duration_seconds: row.get(4)?,
            total_hosts: row.get(5)?,
            hosts_up: row.get(6)?,
            hosts_down: row.get(7)?,
            total_ports_scanned: row.get(8)?,
            command_line: row.get(9)?,
        })
    })?;

    let mut results = Vec::new();
    for summary in summaries {
        results.push(summary?);
    }

    Ok(results)
}

#[derive(Debug)]
pub struct ScanSummary {
    pub scan_id: i64,
    pub scan_date: String,
    pub scanner_name: String,
    pub scanner_version: String,
    pub duration_seconds: f64,
    pub total_hosts: i64,
    pub hosts_up: i64,
    pub hosts_down: i64,
    pub total_ports_scanned: i64,
    pub command_line: String,
}

/// Query hosts from a specific scan
pub fn query_hosts_by_scan(db_path: &str, scan_id: i64) -> Result<Vec<HostRecord>> {
    let conn = Connection::open(db_path)?;

    let mut stmt = conn.prepare(
        "SELECT host_id, ip_address, hostname, state, mac_address, discovered_at
         FROM hosts
         WHERE scan_id = ?1
         ORDER BY ip_address",
    )?;

    let hosts = stmt.query_map(params![scan_id], |row| {
        Ok(HostRecord {
            host_id: row.get(0)?,
            ip_address: row.get(1)?,
            hostname: row.get(2)?,
            state: row.get(3)?,
            mac_address: row.get(4)?,
            discovered_at: row.get(5)?,
        })
    })?;

    let mut results = Vec::new();
    for host in hosts {
        results.push(host?);
    }

    Ok(results)
}

#[derive(Debug)]
pub struct HostRecord {
    pub host_id: i64,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub state: String,
    pub mac_address: Option<String>,
    pub discovered_at: String,
}

/// Query ports for a specific host
pub fn query_ports_by_host(db_path: &str, host_id: i64) -> Result<Vec<PortRecord>> {
    let conn = Connection::open(db_path)?;

    let mut stmt = conn.prepare(
        "SELECT port_id, port_number, protocol, state, service, version, reason
         FROM ports
         WHERE host_id = ?1
         ORDER BY port_number",
    )?;

    let ports = stmt.query_map(params![host_id], |row| {
        Ok(PortRecord {
            port_id: row.get(0)?,
            port_number: row.get(1)?,
            protocol: row.get(2)?,
            state: row.get(3)?,
            service: row.get(4)?,
            version: row.get(5)?,
            reason: row.get(6)?,
        })
    })?;

    let mut results = Vec::new();
    for port in ports {
        results.push(port?);
    }

    Ok(results)
}

#[derive(Debug)]
pub struct PortRecord {
    pub port_id: i64,
    pub port_number: i64,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub reason: Option<String>,
}

/// Get service statistics for a scan
pub fn query_service_stats(db_path: &str, scan_id: i64) -> Result<Vec<ServiceStats>> {
    let conn = Connection::open(db_path)?;

    let mut stmt = conn.prepare(
        "SELECT service_name, port_number, protocol, occurrences
         FROM services
         WHERE scan_id = ?1
         ORDER BY occurrences DESC",
    )?;

    let stats = stmt.query_map(params![scan_id], |row| {
        Ok(ServiceStats {
            service_name: row.get(0)?,
            port_number: row.get(1)?,
            protocol: row.get(2)?,
            occurrences: row.get(3)?,
        })
    })?;

    let mut results = Vec::new();
    for stat in stats {
        results.push(stat?);
    }

    Ok(results)
}

#[derive(Debug)]
pub struct ServiceStats {
    pub service_name: String,
    pub port_number: i64,
    pub protocol: String,
    pub occurrences: i64,
}
