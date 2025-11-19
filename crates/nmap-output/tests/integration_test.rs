use nmap_net::{Host, HostState, Port, PortState, Protocol, OsInfo};
use nmap_output::*;
use std::net::IpAddr;
use std::time::Duration;

fn create_test_data() -> Vec<Host> {
    vec![
        Host {
            address: "192.168.1.1".parse::<IpAddr>().unwrap(),
            hostname: Some("router.local".to_string()),
            state: HostState::Up,
            ports: vec![
                Port {
                    number: 80,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("http".to_string()),
                    version: Some("Apache 2.4.41".to_string()),
                    reason: Some("syn-ack".to_string()),
                },
                Port {
                    number: 443,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("https".to_string()),
                    version: Some("Apache 2.4.41 OpenSSL/1.1.1".to_string()),
                    reason: Some("syn-ack".to_string()),
                },
                Port {
                    number: 22,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("ssh".to_string()),
                    version: Some("OpenSSH 8.2p1 Ubuntu".to_string()),
                    reason: Some("syn-ack".to_string()),
                },
            ],
            os_info: Some(OsInfo {
                name: "Linux 5.4".to_string(),
                family: "Linux".to_string(),
                generation: Some("5.x".to_string()),
                vendor: "Ubuntu".to_string(),
                accuracy: 95,
            }),
            mac_address: Some("00:11:22:33:44:55".to_string()),
        },
        Host {
            address: "192.168.1.10".parse::<IpAddr>().unwrap(),
            hostname: Some("webserver.local".to_string()),
            state: HostState::Up,
            ports: vec![
                Port {
                    number: 80,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("http".to_string()),
                    version: Some("nginx 1.18.0".to_string()),
                    reason: Some("syn-ack".to_string()),
                },
                Port {
                    number: 443,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("https".to_string()),
                    version: Some("nginx 1.18.0".to_string()),
                    reason: Some("syn-ack".to_string()),
                },
                Port {
                    number: 3306,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("mysql".to_string()),
                    version: Some("MySQL 8.0.23".to_string()),
                    reason: Some("syn-ack".to_string()),
                },
            ],
            os_info: Some(OsInfo {
                name: "Linux 5.10".to_string(),
                family: "Linux".to_string(),
                generation: Some("5.x".to_string()),
                vendor: "Debian".to_string(),
                accuracy: 92,
            }),
            mac_address: Some("AA:BB:CC:DD:EE:FF".to_string()),
        },
        Host {
            address: "192.168.1.20".parse::<IpAddr>().unwrap(),
            hostname: Some("fileserver.local".to_string()),
            state: HostState::Up,
            ports: vec![
                Port {
                    number: 445,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("microsoft-ds".to_string()),
                    version: Some("SMB 3.1.1".to_string()),
                    reason: Some("syn-ack".to_string()),
                },
                Port {
                    number: 139,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("netbios-ssn".to_string()),
                    version: None,
                    reason: Some("syn-ack".to_string()),
                },
            ],
            os_info: Some(OsInfo {
                name: "Windows Server 2019".to_string(),
                family: "Windows".to_string(),
                generation: Some("2019".to_string()),
                vendor: "Microsoft".to_string(),
                accuracy: 98,
            }),
            mac_address: Some("11:22:33:44:55:66".to_string()),
        },
        Host {
            address: "192.168.1.100".parse::<IpAddr>().unwrap(),
            hostname: None,
            state: HostState::Down,
            ports: vec![],
            os_info: None,
            mac_address: None,
        },
    ]
}

#[tokio::test]
async fn test_html_generation() {
    let data = create_test_data();
    let duration = Duration::from_secs(45);

    let result = generate_html_report(&data, "/tmp/test_report.html", duration).await;
    assert!(result.is_ok(), "HTML generation failed: {:?}", result.err());

    // Verify file was created
    assert!(std::path::Path::new("/tmp/test_report.html").exists());

    // Check file size is reasonable
    let metadata = std::fs::metadata("/tmp/test_report.html").unwrap();
    assert!(metadata.len() > 1000, "HTML file too small");

    println!("✓ HTML report generated successfully: {} bytes", metadata.len());
}

#[tokio::test]
async fn test_pdf_generation() {
    let data = create_test_data();
    let duration = Duration::from_secs(45);

    let result = generate_pdf_report(&data, "/tmp/test_report.pdf", duration).await;
    assert!(result.is_ok(), "PDF generation failed: {:?}", result.err());

    // Verify file was created
    assert!(std::path::Path::new("/tmp/test_report.pdf").exists());

    // Check file size is reasonable
    let metadata = std::fs::metadata("/tmp/test_report.pdf").unwrap();
    assert!(metadata.len() > 500, "PDF file too small");

    println!("✓ PDF report generated successfully: {} bytes", metadata.len());
}

#[tokio::test]
async fn test_markdown_generation() {
    let data = create_test_data();
    let duration = Duration::from_secs(45);

    let result = generate_markdown_report(&data, "/tmp/test_report.md", duration).await;
    assert!(result.is_ok(), "Markdown generation failed: {:?}", result.err());

    // Verify file was created
    assert!(std::path::Path::new("/tmp/test_report.md").exists());

    // Check file content
    let content = std::fs::read_to_string("/tmp/test_report.md").unwrap();
    assert!(content.contains("# R-Map Network Scan Report"));
    assert!(content.contains("## Executive Summary"));

    println!("✓ Markdown report generated successfully: {} bytes", content.len());
}

#[tokio::test]
async fn test_csv_generation() {
    let data = create_test_data();

    let result = generate_csv_report(&data, "/tmp/test_report.csv").await;
    assert!(result.is_ok(), "CSV generation failed: {:?}", result.err());

    // Verify file was created
    assert!(std::path::Path::new("/tmp/test_report.csv").exists());

    // Check file content
    let content = std::fs::read_to_string("/tmp/test_report.csv").unwrap();
    assert!(content.contains("IP Address"));
    assert!(content.contains("192.168.1.1"));

    println!("✓ CSV report generated successfully: {} bytes", content.len());
}

#[tokio::test]
async fn test_csv_summary_generation() {
    let data = create_test_data();

    let result = generate_csv_summary_report(&data, "/tmp/test_summary.csv").await;
    assert!(result.is_ok(), "CSV summary generation failed: {:?}", result.err());

    // Verify file was created
    assert!(std::path::Path::new("/tmp/test_summary.csv").exists());

    // Check file content
    let content = std::fs::read_to_string("/tmp/test_summary.csv").unwrap();
    assert!(content.contains("Open Ports Count"));

    println!("✓ CSV summary generated successfully: {} bytes", content.len());
}

#[tokio::test]
async fn test_csv_port_analysis() {
    let data = create_test_data();

    let result = generate_csv_port_analysis(&data, "/tmp/test_ports.csv").await;
    assert!(result.is_ok(), "CSV port analysis failed: {:?}", result.err());

    // Verify file was created
    assert!(std::path::Path::new("/tmp/test_ports.csv").exists());

    // Check file content
    let content = std::fs::read_to_string("/tmp/test_ports.csv").unwrap();
    assert!(content.contains("Port,Protocol"));

    println!("✓ CSV port analysis generated successfully: {} bytes", content.len());
}

#[tokio::test]
async fn test_sqlite_generation() {
    let data = create_test_data();
    let duration = Duration::from_secs(45);

    let result = generate_sqlite_database(&data, "/tmp/test_report.db", duration).await;
    assert!(result.is_ok(), "SQLite generation failed: {:?}", result.err());

    // Verify file was created
    assert!(std::path::Path::new("/tmp/test_report.db").exists());

    // Check file size
    let metadata = std::fs::metadata("/tmp/test_report.db").unwrap();
    assert!(metadata.len() > 1000, "Database file too small");

    println!("✓ SQLite database generated successfully: {} bytes", metadata.len());
}

#[tokio::test]
async fn test_sqlite_queries() {
    let data = create_test_data();
    let duration = Duration::from_secs(45);
    let db_path = format!("/tmp/test_query_{}.db", std::process::id());

    // Remove old database if exists
    let _ = std::fs::remove_file(&db_path);

    // Generate database
    generate_sqlite_database(&data, &db_path, duration).await.unwrap();

    // Query scan summary
    let summaries = query_scan_summary(&db_path).unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].total_hosts, 4);
    assert_eq!(summaries[0].hosts_up, 3);

    // Query hosts
    let hosts = query_hosts_by_scan(&db_path, summaries[0].scan_id).unwrap();
    assert_eq!(hosts.len(), 4);

    // Query ports for first host
    let ports = query_ports_by_host(&db_path, 1).unwrap();
    assert!(ports.len() > 0);

    // Query service stats
    let services = query_service_stats(&db_path, summaries[0].scan_id).unwrap();
    assert!(services.len() > 0);

    println!("✓ SQLite queries successful");
    println!("  - Scans: {}", summaries.len());
    println!("  - Hosts: {}", hosts.len());
    println!("  - Services: {}", services.len());
}

#[tokio::test]
async fn test_performance_large_dataset() {
    // Create a larger dataset for performance testing
    let mut large_data = Vec::new();
    for i in 0..100 {
        let mut host = Host {
            address: format!("192.168.1.{}", i).parse::<IpAddr>().unwrap(),
            hostname: Some(format!("host{}.local", i)),
            state: HostState::Up,
            ports: vec![],
            os_info: Some(OsInfo {
                name: "Linux 5.10".to_string(),
                family: "Linux".to_string(),
                generation: Some("5.x".to_string()),
                vendor: "Generic".to_string(),
                accuracy: 90,
            }),
            mac_address: Some(format!("00:11:22:33:44:{:02x}", i)),
        };

        // Add some ports
        for port_num in [22, 80, 443, 3306, 8080] {
            if i % 5 == 0 || port_num == 80 {
                host.ports.push(Port {
                    number: port_num,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some(format!("service-{}", port_num)),
                    version: Some(format!("v{}.0", i % 5)),
                    reason: Some("syn-ack".to_string()),
                });
            }
        }

        large_data.push(host);
    }

    let duration = Duration::from_secs(120);

    // Test HTML performance
    let start = std::time::Instant::now();
    generate_html_report(&large_data, "/tmp/perf_test.html", duration).await.unwrap();
    let html_time = start.elapsed();
    println!("✓ HTML generation (100 hosts): {:.3}s", html_time.as_secs_f64());

    // Test PDF performance
    let start = std::time::Instant::now();
    generate_pdf_report(&large_data, "/tmp/perf_test.pdf", duration).await.unwrap();
    let pdf_time = start.elapsed();
    println!("✓ PDF generation (100 hosts): {:.3}s", pdf_time.as_secs_f64());

    // Test Markdown performance
    let start = std::time::Instant::now();
    generate_markdown_report(&large_data, "/tmp/perf_test.md", duration).await.unwrap();
    let md_time = start.elapsed();
    println!("✓ Markdown generation (100 hosts): {:.3}s", md_time.as_secs_f64());

    // Test CSV performance
    let start = std::time::Instant::now();
    generate_csv_report(&large_data, "/tmp/perf_test.csv").await.unwrap();
    let csv_time = start.elapsed();
    println!("✓ CSV generation (100 hosts): {:.3}s", csv_time.as_secs_f64());

    // Test SQLite performance
    let start = std::time::Instant::now();
    generate_sqlite_database(&large_data, "/tmp/perf_test.db", duration).await.unwrap();
    let sqlite_time = start.elapsed();
    println!("✓ SQLite generation (100 hosts): {:.3}s", sqlite_time.as_secs_f64());

    // Print file sizes
    println!("\nFile sizes:");
    println!("  HTML:     {} bytes", std::fs::metadata("/tmp/perf_test.html").unwrap().len());
    println!("  PDF:      {} bytes", std::fs::metadata("/tmp/perf_test.pdf").unwrap().len());
    println!("  Markdown: {} bytes", std::fs::metadata("/tmp/perf_test.md").unwrap().len());
    println!("  CSV:      {} bytes", std::fs::metadata("/tmp/perf_test.csv").unwrap().len());
    println!("  SQLite:   {} bytes", std::fs::metadata("/tmp/perf_test.db").unwrap().len());

    // Verify all formats completed in reasonable time for 100 hosts
    assert!(html_time.as_secs() < 5, "HTML generation too slow");
    assert!(pdf_time.as_secs() < 10, "PDF generation too slow");
    assert!(md_time.as_secs() < 5, "Markdown generation too slow");
    assert!(csv_time.as_secs() < 5, "CSV generation too slow");
    assert!(sqlite_time.as_secs() < 15, "SQLite generation too slow"); // SQLite has more overhead due to transactions
}
