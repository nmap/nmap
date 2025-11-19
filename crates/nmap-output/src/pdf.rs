use anyhow::Result;
use nmap_net::{Host, HostState, Port, PortState};
use printpdf::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

const MARGIN_MM: f32 = 20.0;
const PAGE_WIDTH_MM: f32 = 210.0;  // A4 width
const PAGE_HEIGHT_MM: f32 = 297.0; // A4 height
const LINE_HEIGHT_MM: f32 = 5.0;

pub async fn generate_pdf_report<P: AsRef<Path>>(
    results: &[Host],
    output_path: P,
    duration: std::time::Duration,
) -> Result<()> {
    // Create PDF document
    let (doc, page1_idx, layer1_idx) = PdfDocument::new(
        "R-Map Scan Report",
        Mm(PAGE_WIDTH_MM),
        Mm(PAGE_HEIGHT_MM),
        "Cover",
    );

    // Add built-in fonts to the document
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica)?;

    let current_layer = doc.get_page(page1_idx).get_layer(layer1_idx);

    // Calculate statistics
    let stats = calculate_statistics(results);

    // Generate cover page
    generate_cover_page(&current_layer, &stats, duration, &font_bold, &font_regular)?;

    // Add executive summary page
    let (page2_idx, layer2_idx) = doc.add_page(Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), "Executive Summary");
    let summary_layer = doc.get_page(page2_idx).get_layer(layer2_idx);
    generate_executive_summary(&summary_layer, &stats, &font_bold, &font_regular)?;

    // Add key findings pages
    let (page3_idx, layer3_idx) = doc.add_page(Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), "Key Findings");
    let findings_layer = doc.get_page(page3_idx).get_layer(layer3_idx);
    generate_key_findings(&findings_layer, results, &stats, &font_bold, &font_regular)?;

    // Add detailed host tables (paginated)
    generate_host_details(&doc, results, &font_bold, &font_regular)?;

    // Save PDF
    let file = File::create(output_path)?;
    let mut writer = BufWriter::new(file);
    doc.save(&mut writer)?;

    Ok(())
}

#[derive(Debug)]
struct ScanStatistics {
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

fn calculate_statistics(results: &[Host]) -> ScanStatistics {
    let hosts_up = results.iter().filter(|h| matches!(h.state, HostState::Up)).count();
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
    top_ports.truncate(10);

    let mut top_services: Vec<(String, usize)> = service_counts.into_iter().collect();
    top_services.sort_by(|a, b| b.1.cmp(&a.1));
    top_services.truncate(10);

    let mut os_distribution: Vec<(String, usize)> = os_counts.into_iter().collect();
    os_distribution.sort_by(|a, b| b.1.cmp(&a.1));

    ScanStatistics {
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

fn generate_cover_page(
    layer: &PdfLayerReference,
    stats: &ScanStatistics,
    duration: std::time::Duration,
    font_bold: &IndirectFontRef,
    font_regular: &IndirectFontRef,
) -> Result<()> {
    // Title
    layer.use_text(
        "R-Map Network Scan Report",
        36.0,
        Mm(MARGIN_MM),
        Mm(PAGE_HEIGHT_MM - 50.0),
        font_bold,
    );

    // Subtitle
    let scan_date = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    layer.use_text(
        &format!("Generated: {}", scan_date),
        14.0,
        Mm(MARGIN_MM),
        Mm(PAGE_HEIGHT_MM - 65.0),
        font_regular,
    );

    // Summary box
    let y_start = PAGE_HEIGHT_MM - 100.0;
    let box_items = vec![
        format!("Total Hosts Scanned: {}", stats.hosts_total),
        format!("Hosts Up: {}", stats.hosts_up),
        format!("Hosts Down: {}", stats.hosts_down),
        format!("Total Open Ports: {}", stats.ports_open),
        format!("Scan Duration: {:.2} seconds", duration.as_secs_f64()),
    ];

    for (i, item) in box_items.iter().enumerate() {
        layer.use_text(
            item,
            12.0,
            Mm(MARGIN_MM + 10.0),
            Mm(y_start - (i as f32 * LINE_HEIGHT_MM)),
            font_regular,
        );
    }

    // Footer
    layer.use_text(
        &format!("R-Map v{} - {}", nmap_core::RMAP_VERSION, nmap_core::RMAP_URL),
        10.0,
        Mm(MARGIN_MM),
        Mm(20.0),
        font_regular,
    );

    Ok(())
}

fn generate_executive_summary(
    layer: &PdfLayerReference,
    stats: &ScanStatistics,
    font_bold: &IndirectFontRef,
    font_regular: &IndirectFontRef,
) -> Result<()> {
    let mut y_pos = PAGE_HEIGHT_MM - 40.0;

    // Title
    layer.use_text("Executive Summary", 24.0, Mm(MARGIN_MM), Mm(y_pos), font_bold);
    y_pos -= 15.0;

    // Overview section
    layer.use_text("Scan Overview", 16.0, Mm(MARGIN_MM), Mm(y_pos), font_bold);
    y_pos -= 10.0;

    let overview_text = vec![
        format!("This network scan discovered {} hosts, with {} hosts responding",
                stats.hosts_total, stats.hosts_up),
        format!("and {} hosts unreachable. A total of {} open ports were identified,",
                stats.hosts_down, stats.ports_open),
        format!("along with {} filtered ports and {} closed ports.",
                stats.ports_filtered, stats.ports_closed),
    ];

    for line in overview_text {
        layer.use_text(&line, 11.0, Mm(MARGIN_MM), Mm(y_pos), font_regular);
        y_pos -= LINE_HEIGHT_MM;
    }

    y_pos -= 5.0;

    // Top Ports section
    layer.use_text("Top Open Ports", 16.0, Mm(MARGIN_MM), Mm(y_pos), font_bold);
    y_pos -= 10.0;

    for (port, count) in stats.top_ports.iter().take(5) {
        layer.use_text(
            &format!("Port {}: {} occurrence{}", port, count, if *count == 1 { "" } else { "s" }),
            11.0,
            Mm(MARGIN_MM + 5.0),
            Mm(y_pos),
            font_regular,
        );
        y_pos -= LINE_HEIGHT_MM;
    }

    y_pos -= 5.0;

    // Top Services section
    layer.use_text("Top Services Detected", 16.0, Mm(MARGIN_MM), Mm(y_pos), font_bold);
    y_pos -= 10.0;

    for (service, count) in stats.top_services.iter().take(5) {
        layer.use_text(
            &format!("{}: {} instance{}", service, count, if *count == 1 { "" } else { "s" }),
            11.0,
            Mm(MARGIN_MM + 5.0),
            Mm(y_pos),
            font_regular,
        );
        y_pos -= LINE_HEIGHT_MM;
    }

    // OS Distribution section if available
    if !stats.os_distribution.is_empty() {
        y_pos -= 5.0;
        layer.use_text("Operating Systems Detected", 16.0, Mm(MARGIN_MM), Mm(y_pos), font_bold);
        y_pos -= 10.0;

        for (os, count) in stats.os_distribution.iter().take(5) {
            layer.use_text(
                &format!("{}: {} host{}", os, count, if *count == 1 { "" } else { "s" }),
                11.0,
                Mm(MARGIN_MM + 5.0),
                Mm(y_pos),
                font_regular,
            );
            y_pos -= LINE_HEIGHT_MM;
        }
    }

    // Page number
    layer.use_text("Page 2", 10.0, Mm(PAGE_WIDTH_MM - 40.0), Mm(15.0), font_regular);

    Ok(())
}

fn generate_key_findings(
    layer: &PdfLayerReference,
    results: &[Host],
    stats: &ScanStatistics,
    font_bold: &IndirectFontRef,
    font_regular: &IndirectFontRef,
) -> Result<()> {
    let mut y_pos = PAGE_HEIGHT_MM - 40.0;

    // Title
    layer.use_text("Key Findings", 24.0, Mm(MARGIN_MM), Mm(y_pos), font_bold);
    y_pos -= 15.0;

    // Security observations
    layer.use_text("Security Observations", 16.0, Mm(MARGIN_MM), Mm(y_pos), font_bold);
    y_pos -= 10.0;

    // Check for commonly vulnerable ports
    let mut findings = Vec::new();

    if stats.top_ports.iter().any(|(p, _)| *p == 23) {
        findings.push("Telnet (port 23) detected - unencrypted protocol, security risk");
    }
    if stats.top_ports.iter().any(|(p, _)| *p == 21) {
        findings.push("FTP (port 21) detected - consider using SFTP instead");
    }
    if stats.top_ports.iter().any(|(p, _)| *p == 445 || *p == 139) {
        findings.push("SMB ports detected - ensure proper configuration and patching");
    }
    if stats.top_ports.iter().any(|(p, _)| *p == 3389) {
        findings.push("RDP (port 3389) detected - ensure strong authentication");
    }

    if findings.is_empty() {
        findings.push("No obvious security vulnerabilities detected in open ports");
    }

    for finding in findings {
        let text = format!("- {}", finding);
        layer.use_text(&text, 11.0, Mm(MARGIN_MM + 5.0), Mm(y_pos), font_regular);
        y_pos -= LINE_HEIGHT_MM;
    }

    y_pos -= 5.0;

    // Network topology insights
    layer.use_text("Network Topology", 16.0, Mm(MARGIN_MM), Mm(y_pos), font_bold);
    y_pos -= 10.0;

    let topology_notes = vec![
        format!("- Host availability rate: {:.1}%",
                (stats.hosts_up as f64 / stats.hosts_total as f64 * 100.0)),
        format!("- Average open ports per host: {:.1}",
                stats.ports_open as f64 / stats.hosts_up.max(1) as f64),
        format!("- {} unique services identified", stats.top_services.len()),
    ];

    for note in topology_notes {
        layer.use_text(&note, 11.0, Mm(MARGIN_MM + 5.0), Mm(y_pos), font_regular);
        y_pos -= LINE_HEIGHT_MM;
    }

    y_pos -= 5.0;

    // Recommendations
    layer.use_text("Recommendations", 16.0, Mm(MARGIN_MM), Mm(y_pos), font_bold);
    y_pos -= 10.0;

    let recommendations = vec![
        "- Review all open ports and disable unnecessary services",
        "- Ensure all systems are patched to latest security updates",
        "- Implement network segmentation where appropriate",
        "- Enable logging and monitoring for detected services",
        "- Conduct regular security audits and penetration testing",
    ];

    for rec in recommendations {
        layer.use_text(rec, 11.0, Mm(MARGIN_MM + 5.0), Mm(y_pos), font_regular);
        y_pos -= LINE_HEIGHT_MM;
        if y_pos < 40.0 {
            break; // Prevent overflow
        }
    }

    // Page number
    layer.use_text("Page 3", 10.0, Mm(PAGE_WIDTH_MM - 40.0), Mm(15.0), font_regular);

    Ok(())
}

fn generate_host_details(
    doc: &PdfDocumentReference,
    results: &[Host],
    font_bold: &IndirectFontRef,
    font_regular: &IndirectFontRef,
) -> Result<()> {
    const HOSTS_PER_PAGE: usize = 15;
    let total_pages = (results.len() + HOSTS_PER_PAGE - 1) / HOSTS_PER_PAGE;

    for (page_num, chunk) in results.chunks(HOSTS_PER_PAGE).enumerate() {
        let (page_idx, layer_idx) = doc.add_page(
            Mm(PAGE_WIDTH_MM),
            Mm(PAGE_HEIGHT_MM),
            &format!("Host Details {}", page_num + 1),
        );
        let layer = doc.get_page(page_idx).get_layer(layer_idx);

        let mut y_pos = PAGE_HEIGHT_MM - 40.0;

        // Title
        layer.use_text(
            &format!("Host Details (Page {} of {})", page_num + 4, total_pages + 3),
            18.0,
            Mm(MARGIN_MM),
            Mm(y_pos),
            font_bold,
        );
        y_pos -= 15.0;

        for host in chunk {
            // Host header
            let host_line = format!(
                "{} ({}) - {}",
                host.address,
                host.hostname.as_deref().unwrap_or("N/A"),
                format!("{:?}", host.state)
            );
            layer.use_text(&host_line, 12.0, Mm(MARGIN_MM), Mm(y_pos), font_bold);
            y_pos -= LINE_HEIGHT_MM;

            // OS info if available
            if let Some(os_info) = &host.os_info {
                layer.use_text(
                    &format!("  OS: {} ({}% accuracy)", os_info.name, os_info.accuracy),
                    10.0,
                    Mm(MARGIN_MM + 5.0),
                    Mm(y_pos),
                    font_regular,
                );
                y_pos -= LINE_HEIGHT_MM;
            }

            // Open ports summary
            let open_ports: Vec<&nmap_net::Port> = host.ports.iter()
                .filter(|p| matches!(p.state, PortState::Open))
                .collect();

            if !open_ports.is_empty() {
                layer.use_text(
                    &format!("  Open Ports ({}): ", open_ports.len()),
                    10.0,
                    Mm(MARGIN_MM + 5.0),
                    Mm(y_pos),
                    font_regular,
                );
                y_pos -= LINE_HEIGHT_MM;

                for port in open_ports.iter().take(10) {
                    let port_line = format!(
                        "    {}/{:?} - {}",
                        port.number,
                        port.protocol,
                        port.service.as_deref().unwrap_or("unknown")
                    );
                    layer.use_text(&port_line, 9.0, Mm(MARGIN_MM + 10.0), Mm(y_pos), font_regular);
                    y_pos -= LINE_HEIGHT_MM - 1.0;
                }

                if open_ports.len() > 10 {
                    layer.use_text(
                        &format!("    ... and {} more", open_ports.len() - 10),
                        9.0,
                        Mm(MARGIN_MM + 10.0),
                        Mm(y_pos),
                        font_regular,
                    );
                    y_pos -= LINE_HEIGHT_MM;
                }
            }

            y_pos -= 3.0;

            // Check if we need a new page
            if y_pos < 50.0 {
                break;
            }
        }

        // Page number
        layer.use_text(
            &format!("Page {}", page_num + 4),
            10.0,
            Mm(PAGE_WIDTH_MM - 40.0),
            Mm(15.0),
            font_regular,
        );
    }

    Ok(())
}
