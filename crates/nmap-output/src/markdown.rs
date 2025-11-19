use anyhow::Result;
use nmap_net::{Host, HostState, PortState};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub async fn generate_markdown_report<P: AsRef<Path>>(
    results: &[Host],
    output_path: P,
    duration: std::time::Duration,
) -> Result<()> {
    let markdown = build_markdown_content(results, duration)?;

    let mut file = File::create(output_path)?;
    file.write_all(markdown.as_bytes())?;

    Ok(())
}

fn build_markdown_content(results: &[Host], duration: std::time::Duration) -> Result<String> {
    let mut md = String::new();

    // YAML frontmatter
    md.push_str("---\n");
    md.push_str(&format!("title: R-Map Network Scan Report\n"));
    md.push_str(&format!("date: {}\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    md.push_str(&format!("scanner: R-Map v{}\n", nmap_core::RMAP_VERSION));
    md.push_str(&format!("duration: {:.2}s\n", duration.as_secs_f64()));
    md.push_str(&format!("hosts_scanned: {}\n", results.len()));
    md.push_str("---\n\n");

    // Title
    md.push_str("# R-Map Network Scan Report\n\n");

    // Executive Summary
    md.push_str("## Executive Summary\n\n");
    md.push_str(&format!(
        "**Scan Date:** {}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));
    md.push_str(&format!("**Scan Duration:** {:.2} seconds\n\n", duration.as_secs_f64()));
    md.push_str(&format!("**Scanner Version:** R-Map {}\n\n", nmap_core::RMAP_VERSION));

    // Statistics table
    let stats = calculate_statistics(results);
    md.push_str("### Summary Statistics\n\n");
    md.push_str("| Metric | Count |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!("| Total Hosts | {} |\n", stats.hosts_total));
    md.push_str(&format!("| Hosts Up | {} |\n", stats.hosts_up));
    md.push_str(&format!("| Hosts Down | {} |\n", stats.hosts_down));
    md.push_str(&format!("| Open Ports | {} |\n", stats.ports_open));
    md.push_str(&format!("| Filtered Ports | {} |\n", stats.ports_filtered));
    md.push_str(&format!("| Closed Ports | {} |\n", stats.ports_closed));
    md.push_str("\n");

    // Top Ports
    if !stats.top_ports.is_empty() {
        md.push_str("### Top Open Ports\n\n");
        md.push_str("| Port | Protocol | Occurrences |\n");
        md.push_str("|------|----------|-------------|\n");
        for (port, count) in stats.top_ports.iter().take(10) {
            md.push_str(&format!("| {} | TCP | {} |\n", port, count));
        }
        md.push_str("\n");
    }

    // Top Services
    if !stats.top_services.is_empty() {
        md.push_str("### Top Services Detected\n\n");
        md.push_str("| Service | Instances |\n");
        md.push_str("|---------|----------|\n");
        for (service, count) in stats.top_services.iter().take(10) {
            md.push_str(&format!("| {} | {} |\n", service, count));
        }
        md.push_str("\n");
    }

    // Operating Systems
    if !stats.os_distribution.is_empty() {
        md.push_str("### Operating System Distribution\n\n");
        md.push_str("| Operating System | Hosts |\n");
        md.push_str("|-----------------|-------|\n");
        for (os, count) in stats.os_distribution.iter() {
            md.push_str(&format!("| {} | {} |\n", os, count));
        }
        md.push_str("\n");
    }

    // Detailed Host Information
    md.push_str("## Detailed Host Information\n\n");

    for (idx, host) in results.iter().enumerate() {
        md.push_str(&format!("### Host {} - {}\n\n", idx + 1, host.address));

        // Host details
        md.push_str("**Host Details:**\n\n");
        md.push_str(&format!("- **IP Address:** `{}`\n", host.address));
        md.push_str(&format!(
            "- **Hostname:** {}\n",
            host.hostname.as_deref().unwrap_or("N/A")
        ));
        md.push_str(&format!("- **State:** {:?}\n", host.state));

        if let Some(os_info) = &host.os_info {
            md.push_str(&format!("- **Operating System:** {} ({}% accuracy)\n", os_info.name, os_info.accuracy));
            md.push_str(&format!("  - **Family:** {}\n", os_info.family));
            md.push_str(&format!("  - **Vendor:** {}\n", os_info.vendor));
            if let Some(gen) = &os_info.generation {
                md.push_str(&format!("  - **Generation:** {}\n", gen));
            }
        }

        if let Some(mac) = &host.mac_address {
            md.push_str(&format!("- **MAC Address:** `{}`\n", mac));
        }

        md.push_str("\n");

        // Open Ports
        let open_ports: Vec<&nmap_net::Port> = host
            .ports
            .iter()
            .filter(|p| matches!(p.state, PortState::Open))
            .collect();

        if !open_ports.is_empty() {
            md.push_str("**Open Ports:**\n\n");
            md.push_str("| Port | Protocol | State | Service | Version |\n");
            md.push_str("|------|----------|-------|---------|----------|\n");

            for port in &open_ports {
                md.push_str(&format!(
                    "| {} | {:?} | {:?} | {} | {} |\n",
                    port.number,
                    port.protocol,
                    port.state,
                    port.service.as_deref().unwrap_or("unknown"),
                    port.version.as_deref().unwrap_or("-")
                ));
            }
            md.push_str("\n");
        }

        // Filtered Ports
        let filtered_ports: Vec<&nmap_net::Port> = host
            .ports
            .iter()
            .filter(|p| matches!(p.state, PortState::Filtered))
            .collect();

        if !filtered_ports.is_empty() {
            md.push_str(&format!(
                "**Filtered Ports:** {} port(s)\n\n",
                filtered_ports.len()
            ));
        }

        // Service Details with Banners
        let services_with_version: Vec<&nmap_net::Port> = open_ports
            .iter()
            .filter(|p| p.version.is_some())
            .copied()
            .collect();

        if !services_with_version.is_empty() {
            md.push_str("**Service Details:**\n\n");
            for port in services_with_version {
                md.push_str(&format!(
                    "- **Port {}:** {} {}\n",
                    port.number,
                    port.service.as_deref().unwrap_or("unknown"),
                    port.version.as_deref().unwrap_or("")
                ));
            }
            md.push_str("\n");
        }

        md.push_str("---\n\n");
    }

    // Security Notes
    md.push_str("## Security Observations\n\n");
    md.push_str(&generate_security_notes(&stats));

    // Recommendations
    md.push_str("## Recommendations\n\n");
    md.push_str("1. **Review Open Ports:** Disable unnecessary services to reduce attack surface\n");
    md.push_str("2. **Update Systems:** Ensure all detected systems are running latest security patches\n");
    md.push_str("3. **Network Segmentation:** Implement proper network segmentation where applicable\n");
    md.push_str("4. **Access Controls:** Review and strengthen authentication mechanisms\n");
    md.push_str("5. **Monitoring:** Enable comprehensive logging for all detected services\n");
    md.push_str("6. **Regular Audits:** Conduct periodic security assessments\n\n");

    // Appendix
    md.push_str("## Appendix\n\n");
    md.push_str(&format!(
        "**Generated by:** R-Map v{}\n\n",
        nmap_core::RMAP_VERSION
    ));
    md.push_str(&format!("**Project URL:** {}\n\n", nmap_core::RMAP_URL));
    md.push_str(&format!(
        "**Report Generated:** {}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    Ok(md)
}

#[derive(Debug)]
struct Statistics {
    hosts_total: usize,
    hosts_up: usize,
    hosts_down: usize,
    ports_open: usize,
    ports_filtered: usize,
    ports_closed: usize,
    top_ports: Vec<(u16, usize)>,
    top_services: Vec<(String, usize)>,
    os_distribution: Vec<(String, usize)>,
}

fn calculate_statistics(results: &[Host]) -> Statistics {
    let hosts_up = results
        .iter()
        .filter(|h| matches!(h.state, HostState::Up))
        .count();
    let hosts_down = results.len() - hosts_up;

    let mut ports_open = 0;
    let mut ports_filtered = 0;
    let mut ports_closed = 0;
    let mut port_counts: HashMap<u16, usize> = HashMap::new();
    let mut service_counts: HashMap<String, usize> = HashMap::new();
    let mut os_counts: HashMap<String, usize> = HashMap::new();

    for host in results {
        if let Some(os_info) = &host.os_info {
            *os_counts.entry(os_info.name.clone()).or_insert(0) += 1;
        }

        for port in &host.ports {
            match port.state {
                PortState::Open => {
                    ports_open += 1;
                    *port_counts.entry(port.number).or_insert(0) += 1;
                    if let Some(service) = &port.service {
                        *service_counts.entry(service.clone()).or_insert(0) += 1;
                    }
                }
                PortState::Filtered => ports_filtered += 1,
                PortState::Closed => ports_closed += 1,
                _ => {}
            }
        }
    }

    let mut top_ports: Vec<(u16, usize)> = port_counts.into_iter().collect();
    top_ports.sort_by(|a, b| b.1.cmp(&a.1));

    let mut top_services: Vec<(String, usize)> = service_counts.into_iter().collect();
    top_services.sort_by(|a, b| b.1.cmp(&a.1));

    let mut os_distribution: Vec<(String, usize)> = os_counts.into_iter().collect();
    os_distribution.sort_by(|a, b| b.1.cmp(&a.1));

    Statistics {
        hosts_total: results.len(),
        hosts_up,
        hosts_down,
        ports_open,
        ports_filtered,
        ports_closed,
        top_ports,
        top_services,
        os_distribution,
    }
}

fn generate_security_notes(stats: &Statistics) -> String {
    let mut notes = String::new();

    let mut found_issues = false;

    // Check for risky ports
    if stats.top_ports.iter().any(|(p, _)| *p == 23) {
        notes.push_str("- ⚠️ **Telnet (port 23) detected:** Unencrypted protocol, consider switching to SSH\n");
        found_issues = true;
    }

    if stats.top_ports.iter().any(|(p, _)| *p == 21) {
        notes.push_str("- ⚠️ **FTP (port 21) detected:** Unencrypted protocol, consider using SFTP or FTPS\n");
        found_issues = true;
    }

    if stats.top_ports.iter().any(|(p, _)| *p == 445 || *p == 139) {
        notes.push_str("- ⚠️ **SMB ports detected:** Ensure systems are patched against SMB vulnerabilities\n");
        found_issues = true;
    }

    if stats.top_ports.iter().any(|(p, _)| *p == 3389) {
        notes.push_str("- ⚠️ **RDP (port 3389) detected:** Ensure strong authentication and latest patches\n");
        found_issues = true;
    }

    if stats.top_ports.iter().any(|(p, _)| *p == 3306) {
        notes.push_str("- ⚠️ **MySQL (port 3306) exposed:** Database should not be directly accessible\n");
        found_issues = true;
    }

    if stats.top_ports.iter().any(|(p, _)| *p == 5432) {
        notes.push_str("- ⚠️ **PostgreSQL (port 5432) exposed:** Database should not be directly accessible\n");
        found_issues = true;
    }

    if stats.top_ports.iter().any(|(p, _)| *p == 27017) {
        notes.push_str("- ⚠️ **MongoDB (port 27017) exposed:** Database should not be directly accessible\n");
        found_issues = true;
    }

    if !found_issues {
        notes.push_str("- ✅ No obvious high-risk ports detected in the scan results\n");
    }

    notes.push_str(&format!(
        "\n**Overall Security Posture:** {:.1}% of hosts are responding with {} total open ports\n\n",
        (stats.hosts_up as f64 / stats.hosts_total.max(1) as f64 * 100.0),
        stats.ports_open
    ));

    notes
}
