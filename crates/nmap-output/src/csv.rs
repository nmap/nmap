use anyhow::Result;
use csv::Writer;
use nmap_net::Host;
use serde::Serialize;
use std::fs::File;
use std::path::Path;

#[derive(Debug, Serialize)]
struct CsvRecord {
    #[serde(rename = "IP Address")]
    ip_address: String,

    #[serde(rename = "Hostname")]
    hostname: String,

    #[serde(rename = "Host State")]
    host_state: String,

    #[serde(rename = "Port")]
    port: String,

    #[serde(rename = "Protocol")]
    protocol: String,

    #[serde(rename = "Port State")]
    port_state: String,

    #[serde(rename = "Service")]
    service: String,

    #[serde(rename = "Version")]
    version: String,

    #[serde(rename = "OS Name")]
    os_name: String,

    #[serde(rename = "OS Family")]
    os_family: String,

    #[serde(rename = "OS Vendor")]
    os_vendor: String,

    #[serde(rename = "OS Accuracy")]
    os_accuracy: String,

    #[serde(rename = "MAC Address")]
    mac_address: String,

    #[serde(rename = "Port Reason")]
    port_reason: String,
}

pub async fn generate_csv_report<P: AsRef<Path>>(
    results: &[Host],
    output_path: P,
) -> Result<()> {
    let file = File::create(output_path)?;
    let mut writer = Writer::from_writer(file);

    for host in results {
        // If host has ports, create a row for each port
        if !host.ports.is_empty() {
            for port in &host.ports {
                let record = CsvRecord {
                    ip_address: host.address.to_string(),
                    hostname: host.hostname.clone().unwrap_or_else(|| "N/A".to_string()),
                    host_state: format!("{:?}", host.state),
                    port: port.number.to_string(),
                    protocol: format!("{:?}", port.protocol),
                    port_state: format!("{:?}", port.state),
                    service: port.service.clone().unwrap_or_else(|| "unknown".to_string()),
                    version: port.version.clone().unwrap_or_else(|| "".to_string()),
                    os_name: host
                        .os_info
                        .as_ref()
                        .map(|os| os.name.clone())
                        .unwrap_or_else(|| "Unknown".to_string()),
                    os_family: host
                        .os_info
                        .as_ref()
                        .map(|os| os.family.clone())
                        .unwrap_or_else(|| "Unknown".to_string()),
                    os_vendor: host
                        .os_info
                        .as_ref()
                        .map(|os| os.vendor.clone())
                        .unwrap_or_else(|| "Unknown".to_string()),
                    os_accuracy: host
                        .os_info
                        .as_ref()
                        .map(|os| os.accuracy.to_string())
                        .unwrap_or_else(|| "0".to_string()),
                    mac_address: host.mac_address.clone().unwrap_or_else(|| "N/A".to_string()),
                    port_reason: port.reason.clone().unwrap_or_else(|| "".to_string()),
                };

                writer.serialize(record)?;
            }
        } else {
            // If no ports, create a single row for the host
            let record = CsvRecord {
                ip_address: host.address.to_string(),
                hostname: host.hostname.clone().unwrap_or_else(|| "N/A".to_string()),
                host_state: format!("{:?}", host.state),
                port: "".to_string(),
                protocol: "".to_string(),
                port_state: "".to_string(),
                service: "".to_string(),
                version: "".to_string(),
                os_name: host
                    .os_info
                    .as_ref()
                    .map(|os| os.name.clone())
                    .unwrap_or_else(|| "Unknown".to_string()),
                os_family: host
                    .os_info
                    .as_ref()
                    .map(|os| os.family.clone())
                    .unwrap_or_else(|| "Unknown".to_string()),
                os_vendor: host
                    .os_info
                    .as_ref()
                    .map(|os| os.vendor.clone())
                    .unwrap_or_else(|| "Unknown".to_string()),
                os_accuracy: host
                    .os_info
                    .as_ref()
                    .map(|os| os.accuracy.to_string())
                    .unwrap_or_else(|| "0".to_string()),
                mac_address: host.mac_address.clone().unwrap_or_else(|| "N/A".to_string()),
                port_reason: "".to_string(),
            };

            writer.serialize(record)?;
        }
    }

    writer.flush()?;
    Ok(())
}

/// Alternative export format: Summary CSV (one row per host)
#[derive(Debug, Serialize)]
struct CsvSummaryRecord {
    #[serde(rename = "IP Address")]
    ip_address: String,

    #[serde(rename = "Hostname")]
    hostname: String,

    #[serde(rename = "State")]
    state: String,

    #[serde(rename = "Open Ports Count")]
    open_ports_count: usize,

    #[serde(rename = "Filtered Ports Count")]
    filtered_ports_count: usize,

    #[serde(rename = "Closed Ports Count")]
    closed_ports_count: usize,

    #[serde(rename = "Open Ports List")]
    open_ports_list: String,

    #[serde(rename = "Services")]
    services: String,

    #[serde(rename = "OS")]
    os: String,

    #[serde(rename = "OS Accuracy")]
    os_accuracy: String,

    #[serde(rename = "MAC Address")]
    mac_address: String,
}

pub async fn generate_csv_summary_report<P: AsRef<Path>>(
    results: &[Host],
    output_path: P,
) -> Result<()> {
    let file = File::create(output_path)?;
    let mut writer = Writer::from_writer(file);

    for host in results {
        let open_ports: Vec<String> = host
            .ports
            .iter()
            .filter(|p| matches!(p.state, nmap_net::PortState::Open))
            .map(|p| p.number.to_string())
            .collect();

        let filtered_ports_count = host
            .ports
            .iter()
            .filter(|p| matches!(p.state, nmap_net::PortState::Filtered))
            .count();

        let closed_ports_count = host
            .ports
            .iter()
            .filter(|p| matches!(p.state, nmap_net::PortState::Closed))
            .count();

        let services: Vec<String> = host
            .ports
            .iter()
            .filter(|p| matches!(p.state, nmap_net::PortState::Open))
            .filter_map(|p| p.service.clone())
            .collect();

        let record = CsvSummaryRecord {
            ip_address: host.address.to_string(),
            hostname: host.hostname.clone().unwrap_or_else(|| "N/A".to_string()),
            state: format!("{:?}", host.state),
            open_ports_count: open_ports.len(),
            filtered_ports_count,
            closed_ports_count,
            open_ports_list: open_ports.join("; "),
            services: services.join("; "),
            os: host
                .os_info
                .as_ref()
                .map(|os| os.name.clone())
                .unwrap_or_else(|| "Unknown".to_string()),
            os_accuracy: host
                .os_info
                .as_ref()
                .map(|os| format!("{}%", os.accuracy))
                .unwrap_or_else(|| "0%".to_string()),
            mac_address: host.mac_address.clone().unwrap_or_else(|| "N/A".to_string()),
        };

        writer.serialize(record)?;
    }

    writer.flush()?;
    Ok(())
}

/// Port-focused CSV export (one row per unique port across all hosts)
#[derive(Debug, Serialize)]
struct CsvPortRecord {
    #[serde(rename = "Port")]
    port: u16,

    #[serde(rename = "Protocol")]
    protocol: String,

    #[serde(rename = "Service")]
    service: String,

    #[serde(rename = "Total Occurrences")]
    total_occurrences: usize,

    #[serde(rename = "Open Count")]
    open_count: usize,

    #[serde(rename = "Filtered Count")]
    filtered_count: usize,

    #[serde(rename = "Closed Count")]
    closed_count: usize,

    #[serde(rename = "Hosts with Port Open")]
    hosts_with_port_open: String,
}

pub async fn generate_csv_port_analysis<P: AsRef<Path>>(
    results: &[Host],
    output_path: P,
) -> Result<()> {
    use std::collections::HashMap;

    let file = File::create(output_path)?;
    let mut writer = Writer::from_writer(file);

    // Aggregate port data
    let mut port_data: HashMap<
        (u16, String),
        (String, usize, usize, usize, Vec<String>),
    > = HashMap::new();

    for host in results {
        for port in &host.ports {
            let key = (port.number, format!("{:?}", port.protocol));
            let entry = port_data.entry(key).or_insert((
                port.service.clone().unwrap_or_else(|| "unknown".to_string()),
                0,
                0,
                0,
                Vec::new(),
            ));

            match port.state {
                nmap_net::PortState::Open => {
                    entry.1 += 1;
                    entry.4.push(host.address.to_string());
                }
                nmap_net::PortState::Filtered => entry.2 += 1,
                nmap_net::PortState::Closed => entry.3 += 1,
                _ => {}
            }
        }
    }

    // Convert to records and write
    let mut records: Vec<CsvPortRecord> = port_data
        .into_iter()
        .map(|((port, protocol), (service, open, filtered, closed, hosts))| {
            CsvPortRecord {
                port,
                protocol,
                service,
                total_occurrences: open + filtered + closed,
                open_count: open,
                filtered_count: filtered,
                closed_count: closed,
                hosts_with_port_open: hosts.join("; "),
            }
        })
        .collect();

    // Sort by port number
    records.sort_by(|a, b| a.port.cmp(&b.port));

    for record in records {
        writer.serialize(record)?;
    }

    writer.flush()?;
    Ok(())
}
