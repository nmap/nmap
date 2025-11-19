use anyhow::Result;
use nmap_net::{Host, HostState, PortState};
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize)]
struct HtmlReport {
    scan_id: String,
    scan_name: String,
    scan_date: String,
    scan_duration: String,
    hosts_total: usize,
    hosts_up: usize,
    hosts_down: usize,
    ports_open: usize,
    ports_filtered: usize,
    ports_closed: usize,
    hosts: Vec<HostData>,
    port_distribution: Vec<PortDistribution>,
    service_distribution: Vec<ServiceDistribution>,
}

#[derive(Debug, Serialize)]
struct HostData {
    ip: String,
    hostname: String,
    state: String,
    os: String,
    mac: String,
    ports: Vec<PortData>,
    open_ports_count: usize,
}

#[derive(Debug, Serialize)]
struct PortData {
    number: u16,
    protocol: String,
    state: String,
    service: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct PortDistribution {
    port: u16,
    count: usize,
}

#[derive(Debug, Serialize)]
struct ServiceDistribution {
    service: String,
    count: usize,
}

pub async fn generate_html_report<P: AsRef<Path>>(
    results: &[Host],
    output_path: P,
    duration: std::time::Duration,
) -> Result<()> {
    let report = build_report_data(results, duration);
    let html = generate_html_content(&report)?;

    let mut file = File::create(output_path)?;
    file.write_all(html.as_bytes())?;

    Ok(())
}

fn build_report_data(results: &[Host], duration: std::time::Duration) -> HtmlReport {
    let hosts_up = results.iter().filter(|h| matches!(h.state, HostState::Up)).count();
    let hosts_down = results.len() - hosts_up;

    let mut ports_open = 0;
    let mut ports_filtered = 0;
    let mut ports_closed = 0;
    let mut port_counts: HashMap<u16, usize> = HashMap::new();
    let mut service_counts: HashMap<String, usize> = HashMap::new();

    let hosts: Vec<HostData> = results
        .iter()
        .map(|host| {
            let mut host_open = 0;
            let ports: Vec<PortData> = host
                .ports
                .iter()
                .map(|port| {
                    match port.state {
                        PortState::Open => {
                            ports_open += 1;
                            host_open += 1;
                            *port_counts.entry(port.number).or_insert(0) += 1;
                            if let Some(service) = &port.service {
                                *service_counts.entry(service.clone()).or_insert(0) += 1;
                            }
                        }
                        PortState::Filtered => ports_filtered += 1,
                        PortState::Closed => ports_closed += 1,
                        _ => {}
                    }

                    PortData {
                        number: port.number,
                        protocol: format!("{:?}", port.protocol),
                        state: format!("{:?}", port.state),
                        service: port.service.clone().unwrap_or_else(|| "unknown".to_string()),
                        version: port.version.clone().unwrap_or_else(|| "".to_string()),
                    }
                })
                .collect();

            HostData {
                ip: host.address.to_string(),
                hostname: host.hostname.clone().unwrap_or_else(|| "N/A".to_string()),
                state: format!("{:?}", host.state),
                os: host.os_info.as_ref().map(|os| os.name.clone()).unwrap_or_else(|| "Unknown".to_string()),
                mac: host.mac_address.clone().unwrap_or_else(|| "N/A".to_string()),
                ports,
                open_ports_count: host_open,
            }
        })
        .collect();

    let mut port_distribution: Vec<PortDistribution> = port_counts
        .into_iter()
        .map(|(port, count)| PortDistribution { port, count })
        .collect();
    port_distribution.sort_by(|a, b| b.count.cmp(&a.count));
    port_distribution.truncate(20); // Top 20 ports

    let mut service_distribution: Vec<ServiceDistribution> = service_counts
        .into_iter()
        .map(|(service, count)| ServiceDistribution { service, count })
        .collect();
    service_distribution.sort_by(|a, b| b.count.cmp(&a.count));
    service_distribution.truncate(15); // Top 15 services

    HtmlReport {
        scan_id: uuid::Uuid::new_v4().to_string(),
        scan_name: format!("{} Scan Report", nmap_core::RMAP_NAME),
        scan_date: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        scan_duration: format!("{:.2}s", duration.as_secs_f64()),
        hosts_total: results.len(),
        hosts_up,
        hosts_down,
        ports_open,
        ports_filtered,
        ports_closed,
        hosts,
        port_distribution,
        service_distribution,
    }
}

fn generate_html_content(report: &HtmlReport) -> Result<String> {
    let port_labels: Vec<String> = report.port_distribution.iter().map(|p| p.port.to_string()).collect();
    let port_data: Vec<usize> = report.port_distribution.iter().map(|p| p.count).collect();

    let service_labels: Vec<String> = report.service_distribution.iter().map(|s| s.service.clone()).collect();
    let service_data: Vec<usize> = report.service_distribution.iter().map(|s| s.count).collect();

    let hosts_rows: String = report.hosts.iter().map(|host| {
        let ports_preview = if host.open_ports_count > 0 {
            format!("{} open port{}", host.open_ports_count, if host.open_ports_count == 1 { "" } else { "s" })
        } else {
            "No open ports".to_string()
        };

        let state_badge = match host.state.as_str() {
            "Up" => "badge bg-success",
            _ => "badge bg-secondary",
        };

        format!(
            r#"<tr>
                <td>{}</td>
                <td>{}</td>
                <td><span class="{}">{}</span></td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>"#,
            host.ip, host.hostname, state_badge, host.state, ports_preview, host.os, host.mac
        )
    }).collect::<Vec<_>>().join("\n");

    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{scan_name}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
    <style>
        body {{
            background-color: #f8f9fa;
            transition: background-color 0.3s, color 0.3s;
        }}
        .dark-mode {{
            background-color: #1a1a1a;
            color: #e0e0e0;
        }}
        .dark-mode .card {{
            background-color: #2d2d2d;
            color: #e0e0e0;
        }}
        .dark-mode .table {{
            color: #e0e0e0;
        }}
        .dark-mode .table-striped tbody tr:nth-of-type(odd) {{
            background-color: rgba(255, 255, 255, 0.05);
        }}
        .stats-card {{
            border-left: 4px solid;
            transition: transform 0.2s;
        }}
        .stats-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }}
        .stats-card.primary {{ border-color: #0d6efd; }}
        .stats-card.success {{ border-color: #198754; }}
        .stats-card.danger {{ border-color: #dc3545; }}
        .stats-card.warning {{ border-color: #ffc107; }}
        .stats-card.info {{ border-color: #0dcaf0; }}
        .stats-number {{
            font-size: 2.5rem;
            font-weight: bold;
            margin: 0;
        }}
        .stats-label {{
            color: #6c757d;
            font-size: 0.9rem;
            text-transform: uppercase;
        }}
        .chart-container {{
            position: relative;
            height: 400px;
            margin: 20px 0;
        }}
        .dark-mode-toggle {{
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
        }}
        .print-section {{
            margin: 20px 0;
        }}
        @media print {{
            .dark-mode-toggle, .no-print {{ display: none; }}
            .stats-card {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <button class="btn btn-sm btn-outline-secondary dark-mode-toggle no-print" onclick="toggleDarkMode()">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
            <path d="M8 11a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm0 1a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM8 0a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 0zm0 13a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 13zm8-5a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2a.5.5 0 0 1 .5.5zM3 8a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2A.5.5 0 0 1 3 8zm10.657-5.657a.5.5 0 0 1 0 .707l-1.414 1.415a.5.5 0 1 1-.707-.708l1.414-1.414a.5.5 0 0 1 .707 0zm-9.193 9.193a.5.5 0 0 1 0 .707L3.05 13.657a.5.5 0 0 1-.707-.707l1.414-1.414a.5.5 0 0 1 .707 0zm9.193 2.121a.5.5 0 0 1-.707 0l-1.414-1.414a.5.5 0 0 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .707zM4.464 4.465a.5.5 0 0 1-.707 0L2.343 3.05a.5.5 0 1 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .708z"/>
        </svg>
    </button>

    <div class="container-fluid py-4">
        <div class="row mb-4">
            <div class="col">
                <h1 class="display-4">{scan_name}</h1>
                <p class="lead text-muted">Generated on {scan_date} | Duration: {scan_duration}</p>
                <button class="btn btn-primary no-print" onclick="window.print()">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                        <path d="M2.5 8a.5.5 0 1 0 0-1 .5.5 0 0 0 0 1z"/>
                        <path d="M5 1a2 2 0 0 0-2 2v2H2a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2h1v1a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2v-1h1a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-1V3a2 2 0 0 0-2-2H5zM4 3a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2H4V3zm1 5a2 2 0 0 0-2 2v1H2a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v-1a2 2 0 0 0-2-2H5zm7 2v3a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1z"/>
                    </svg>
                    Export to PDF
                </button>
            </div>
        </div>

        <!-- Executive Summary Cards -->
        <div class="row g-4 mb-4">
            <div class="col-md-4">
                <div class="card stats-card primary">
                    <div class="card-body">
                        <p class="stats-label">Total Hosts</p>
                        <p class="stats-number">{hosts_total}</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card stats-card success">
                    <div class="card-body">
                        <p class="stats-label">Hosts Up</p>
                        <p class="stats-number">{hosts_up}</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card stats-card danger">
                    <div class="card-body">
                        <p class="stats-label">Hosts Down</p>
                        <p class="stats-number">{hosts_down}</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card stats-card success">
                    <div class="card-body">
                        <p class="stats-label">Open Ports</p>
                        <p class="stats-number">{ports_open}</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card stats-card warning">
                    <div class="card-body">
                        <p class="stats-label">Filtered Ports</p>
                        <p class="stats-number">{ports_filtered}</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card stats-card info">
                    <div class="card-body">
                        <p class="stats-label">Closed Ports</p>
                        <p class="stats-number">{ports_closed}</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts -->
        <div class="row g-4 mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Top Ports Distribution</h5>
                        <div class="chart-container">
                            <canvas id="portChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Service Distribution</h5>
                        <div class="chart-container">
                            <canvas id="serviceChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Host Table -->
        <div class="row">
            <div class="col">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Discovered Hosts</h5>
                        <div class="table-responsive">
                            <table id="hostsTable" class="table table-striped table-hover">
                                <thead>
                                    <tr>
                                        <th>IP Address</th>
                                        <th>Hostname</th>
                                        <th>State</th>
                                        <th>Open Ports</th>
                                        <th>OS</th>
                                        <th>MAC Address</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {hosts_rows}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Dark Mode Toggle
        function toggleDarkMode() {{
            document.body.classList.toggle('dark-mode');
            const isDark = document.body.classList.contains('dark-mode');
            localStorage.setItem('darkMode', isDark);
            updateCharts();
        }}

        // Load dark mode preference
        if (localStorage.getItem('darkMode') === 'true') {{
            document.body.classList.add('dark-mode');
        }}

        // Initialize DataTable
        $(document).ready(function() {{
            $('#hostsTable').DataTable({{
                order: [[2, 'desc']], // Sort by state
                pageLength: 25,
                responsive: true
            }});
        }});

        // Chart.js configuration
        const isDarkMode = () => document.body.classList.contains('dark-mode');

        const getChartColors = () => ({{
            textColor: isDarkMode() ? '#e0e0e0' : '#666',
            gridColor: isDarkMode() ? '#444' : '#e0e0e0'
        }});

        // Port Distribution Chart
        const portCtx = document.getElementById('portChart').getContext('2d');
        let portChart = new Chart(portCtx, {{
            type: 'bar',
            data: {{
                labels: {port_labels},
                datasets: [{{
                    label: 'Occurrences',
                    data: {port_data},
                    backgroundColor: 'rgba(13, 110, 253, 0.8)',
                    borderColor: 'rgba(13, 110, 253, 1)',
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        labels: {{
                            color: getChartColors().textColor
                        }}
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            color: getChartColors().textColor
                        }},
                        grid: {{
                            color: getChartColors().gridColor
                        }}
                    }},
                    x: {{
                        ticks: {{
                            color: getChartColors().textColor
                        }},
                        grid: {{
                            color: getChartColors().gridColor
                        }}
                    }}
                }}
            }}
        }});

        // Service Distribution Chart
        const serviceCtx = document.getElementById('serviceChart').getContext('2d');
        let serviceChart = new Chart(serviceCtx, {{
            type: 'doughnut',
            data: {{
                labels: {service_labels},
                datasets: [{{
                    data: {service_data},
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.8)',
                        'rgba(54, 162, 235, 0.8)',
                        'rgba(255, 206, 86, 0.8)',
                        'rgba(75, 192, 192, 0.8)',
                        'rgba(153, 102, 255, 0.8)',
                        'rgba(255, 159, 64, 0.8)',
                        'rgba(199, 199, 199, 0.8)',
                        'rgba(83, 102, 255, 0.8)',
                        'rgba(255, 99, 255, 0.8)',
                        'rgba(99, 255, 132, 0.8)',
                        'rgba(255, 206, 199, 0.8)',
                        'rgba(132, 99, 255, 0.8)',
                        'rgba(206, 255, 86, 0.8)',
                        'rgba(99, 132, 255, 0.8)',
                        'rgba(255, 132, 99, 0.8)'
                    ],
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'right',
                        labels: {{
                            color: getChartColors().textColor
                        }}
                    }}
                }}
            }}
        }});

        function updateCharts() {{
            const colors = getChartColors();

            // Update port chart
            portChart.options.plugins.legend.labels.color = colors.textColor;
            portChart.options.scales.y.ticks.color = colors.textColor;
            portChart.options.scales.y.grid.color = colors.gridColor;
            portChart.options.scales.x.ticks.color = colors.textColor;
            portChart.options.scales.x.grid.color = colors.gridColor;
            portChart.update();

            // Update service chart
            serviceChart.options.plugins.legend.labels.color = colors.textColor;
            serviceChart.update();
        }}
    </script>
</body>
</html>"#,
        scan_name = report.scan_name,
        scan_date = report.scan_date,
        scan_duration = report.scan_duration,
        hosts_total = report.hosts_total,
        hosts_up = report.hosts_up,
        hosts_down = report.hosts_down,
        ports_open = report.ports_open,
        ports_filtered = report.ports_filtered,
        ports_closed = report.ports_closed,
        hosts_rows = hosts_rows,
        port_labels = serde_json::to_string(&port_labels)?,
        port_data = serde_json::to_string(&port_data)?,
        service_labels = serde_json::to_string(&service_labels)?,
        service_data = serde_json::to_string(&service_data)?,
    );

    Ok(html)
}
