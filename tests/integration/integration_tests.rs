// End-to-End Integration tests for R-Map
// These tests run against real Docker containers to validate full scanning workflow

use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;

/// Helper to run R-Map binary with arguments
fn run_rmap(args: &[&str]) -> std::process::Output {
    Command::new("cargo")
        .arg("run")
        .arg("--release")
        .arg("--bin")
        .arg("rmap")
        .arg("--")
        .args(args)
        .output()
        .expect("Failed to execute rmap")
}

/// Wait for Docker services to be ready
async fn wait_for_services() {
    println!("Waiting for test services to be ready...");
    sleep(Duration::from_secs(15)).await;
}

#[tokio::test]
#[ignore] // Run with: cargo test --test integration -- --ignored
async fn test_http_port_detection() {
    wait_for_services().await;

    let output = run_rmap(&["localhost", "-p", "8080", "--format", "json"]);

    assert!(output.status.success(), "Scan should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("8080"), "Should detect port 8080");
    assert!(stdout.contains("open") || stdout.contains("Open"), "Port should be open");
}

#[tokio::test]
#[ignore]
async fn test_ssh_service_detection() {
    wait_for_services().await;

    let output = run_rmap(&["localhost", "-p", "2222", "-sV", "--format", "json"]);

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("2222"), "Should detect port 2222");
    assert!(stdout.contains("ssh") || stdout.contains("SSH"), "Should identify SSH service");
}

#[tokio::test]
#[ignore]
async fn test_mysql_banner_grab() {
    wait_for_services().await;

    let output = run_rmap(&["localhost", "-p", "3306", "-sV", "--format", "json"]);

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("3306"), "Should detect MySQL port");
    assert!(stdout.contains("mysql") || stdout.contains("MySQL"), "Should identify MySQL");
}

#[tokio::test]
#[ignore]
async fn test_multiple_ports_scan() {
    wait_for_services().await;

    let output = run_rmap(&["localhost", "-p", "8080,2222,3306,6379,5432", "--format", "json"]);

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should detect all open ports
    assert!(stdout.contains("8080"), "Should detect HTTP");
    assert!(stdout.contains("2222"), "Should detect SSH");
    assert!(stdout.contains("3306"), "Should detect MySQL");
    assert!(stdout.contains("6379"), "Should detect Redis");
    assert!(stdout.contains("5432"), "Should detect PostgreSQL");
}

#[tokio::test]
#[ignore]
async fn test_closed_port_detection() {
    wait_for_services().await;

    let output = run_rmap(&["localhost", "-p", "9999", "--format", "json"]);

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("closed") || stdout.contains("Closed") || stdout.contains("filtered"),
            "Port 9999 should be closed or filtered");
}

#[tokio::test]
#[ignore]
async fn test_json_output_format() {
    wait_for_services().await;

    let output = run_rmap(&["localhost", "-p", "8080", "--format", "json"]);

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify it's valid JSON
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(parsed.is_ok(), "Output should be valid JSON");

    if let Ok(json) = parsed {
        assert!(json.is_array() || json.is_object(), "JSON should be array or object");
    }
}

#[tokio::test]
#[ignore]
async fn test_xml_output_format() {
    wait_for_services().await;

    let output = run_rmap(&["localhost", "-p", "8080", "--format", "xml"]);

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify XML structure
    assert!(stdout.contains("<?xml"), "Should have XML declaration");
    assert!(stdout.contains("<nmaprun"), "Should have nmaprun root element");
    assert!(stdout.contains("</nmaprun>"), "Should close nmaprun element");
}

#[tokio::test]
#[ignore]
async fn test_service_version_detection() {
    wait_for_services().await;

    let output = run_rmap(&["localhost", "-p", "8080,2222,21,3306", "-sV"]);

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain service names
    let stdout_lower = stdout.to_lowercase();
    assert!(stdout_lower.contains("http") || stdout_lower.contains("nginx"),
            "Should detect HTTP/nginx");
}

#[tokio::test]
#[ignore]
async fn test_tcp_connect_scan() {
    wait_for_services().await;

    let output = run_rmap(&["localhost", "-p", "8080", "--scan", "connect"]);

    assert!(output.status.success(), "TCP connect scan should work");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("8080"), "Should scan port 8080");
}

#[tokio::test]
#[ignore]
async fn test_udp_scan_dns() {
    wait_for_services().await;

    let output = run_rmap(&["localhost", "-p", "53", "--scan", "udp"]);

    // UDP scan might require root, so we accept either success or permission error
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let output_combined = format!("{}{}", stdout, stderr);
    assert!(
        output_combined.contains("53") || output_combined.contains("Permission") || output_combined.contains("privileges"),
        "Should attempt UDP scan or report permission issue"
    );
}

#[tokio::test]
#[ignore]
async fn test_port_range_scan() {
    wait_for_services().await;

    let output = run_rmap(&["localhost", "-p", "8000-8100", "--format", "json"]);

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("8080"), "Should find port 8080 in range");
}

#[tokio::test]
#[ignore]
async fn test_timing_options() {
    wait_for_services().await;

    let output = run_rmap(&["localhost", "-p", "8080", "--timeout", "5"]);

    assert!(output.status.success(), "Scan with custom timeout should work");
}

#[tokio::test]
#[ignore]
async fn test_verbose_output() {
    wait_for_services().await;

    let output = run_rmap(&["localhost", "-p", "8080", "-v"]);

    assert!(output.status.success());

    // Verbose mode might produce additional output
    let combined = format!("{}{}",
                          String::from_utf8_lossy(&output.stdout),
                          String::from_utf8_lossy(&output.stderr));
    assert!(!combined.is_empty(), "Verbose mode should produce output");
}

#[tokio::test]
#[ignore]
async fn test_invalid_target_handling() {
    let output = run_rmap(&["invalid.local.nonexistent", "-p", "80"]);

    // Should either fail gracefully or report DNS resolution error
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.contains("Failed") || combined.contains("error") || combined.contains("resolve"),
        "Should report error for invalid target"
    );
}

#[tokio::test]
#[ignore]
async fn test_connection_refused_handling() {
    let output = run_rmap(&["localhost", "-p", "9999"]);

    assert!(output.status.success(), "Should handle connection refused gracefully");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("closed") || stdout.contains("Closed") || stdout.contains("filtered"),
            "Should report port as closed or filtered");
}

/// Integration test for the full scan workflow
#[tokio::test]
#[ignore]
async fn test_full_scan_workflow() {
    wait_for_services().await;

    // 1. Quick port scan
    let scan_output = run_rmap(&["localhost", "-p", "8080,2222,3306", "--format", "json"]);
    assert!(scan_output.status.success(), "Initial scan should succeed");

    // 2. Service detection scan
    let service_output = run_rmap(&["localhost", "-p", "8080,2222,3306", "-sV", "--format", "json"]);
    assert!(service_output.status.success(), "Service detection should succeed");

    // 3. Verify output is parseable
    let stdout = String::from_utf8_lossy(&service_output.stdout);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(parsed.is_ok(), "Service detection output should be valid JSON");
}

#[tokio::test]
#[ignore]
async fn test_concurrent_scans() {
    wait_for_services().await;

    // Run two scans concurrently
    let handle1 = tokio::spawn(async {
        run_rmap(&["localhost", "-p", "8080"])
    });

    let handle2 = tokio::spawn(async {
        run_rmap(&["localhost", "-p", "2222"])
    });

    let (result1, result2) = tokio::join!(handle1, handle2);

    assert!(result1.is_ok() && result2.is_ok(), "Concurrent scans should both succeed");
    assert!(result1.unwrap().status.success());
    assert!(result2.unwrap().status.success());
}

#[test]
fn test_help_command() {
    let output = run_rmap(&["--help"]);

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage") || stdout.contains("USAGE"), "Should show usage");
    assert!(stdout.contains("--help"), "Should show help flag");
}

#[test]
fn test_version_command() {
    let output = run_rmap(&["--version"]);

    let combined = format!("{}{}",
                          String::from_utf8_lossy(&output.stdout),
                          String::from_utf8_lossy(&output.stderr));
    assert!(combined.contains("R-Map") || combined.contains("version") || combined.contains("0."),
            "Should show version information");
}
