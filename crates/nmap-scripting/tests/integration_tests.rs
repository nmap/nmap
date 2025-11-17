/// Integration tests for the scripting framework
use nmap_scripting::*;
use std::collections::HashMap;
use std::net::IpAddr;

#[tokio::test]
async fn test_script_engine_creation() {
    let engine = ScriptEngine::new();
    let scripts = engine.list_scripts().await;
    assert_eq!(scripts.len(), 0, "New engine should have no scripts");
}

#[tokio::test]
async fn test_register_all_scripts() {
    let engine = ScriptEngine::new();
    let result = register_all_scripts(&engine).await;

    assert!(result.is_ok(), "Script registration should succeed");

    let scripts = engine.list_scripts().await;
    assert!(scripts.len() >= 25, "Should have at least 25 scripts registered, got {}", scripts.len());
}

#[tokio::test]
async fn test_script_categories() {
    let engine = ScriptEngine::new();
    register_all_scripts(&engine).await.unwrap();

    let categories = engine.list_categories().await;
    assert!(!categories.is_empty(), "Should have script categories");

    // Verify key categories exist
    assert!(categories.contains(&ScriptCategory::Vuln), "Should have Vuln category");
    assert!(categories.contains(&ScriptCategory::Safe), "Should have Safe category");
}

#[tokio::test]
async fn test_http_title_script() {
    let engine = ScriptEngine::new();
    register_all_scripts(&engine).await.unwrap();

    let context = ScriptContext {
        target_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        target_port: Some(80),
        protocol: Some("tcp".to_string()),
        service: Some("http".to_string()),
        version: None,
        os_info: None,
        timing: ScriptTiming::default(),
        user_args: HashMap::new(),
    };

    // This will fail to connect to localhost:80, but tests the script execution path
    let result = engine.execute_script("http-title", &context).await;
    assert!(result.is_ok(), "Script execution should return a result");
}

#[tokio::test]
async fn test_parallel_execution() {
    let engine = ScriptEngine::new();
    register_all_scripts(&engine).await.unwrap();

    let context = ScriptContext {
        target_ip: "192.0.2.1".parse::<IpAddr>().unwrap(), // TEST-NET-1
        target_port: Some(80),
        protocol: Some("tcp".to_string()),
        service: Some("http".to_string()),
        version: None,
        os_info: None,
        timing: ScriptTiming::default(),
        user_args: HashMap::new(),
    };

    let script_names = vec![
        "http-title".to_string(),
        "http-security-headers".to_string(),
    ];

    let results = engine.execute_scripts_parallel(script_names, &context).await;
    assert_eq!(results.len(), 2, "Should execute 2 scripts");
}

#[tokio::test]
async fn test_service_based_execution() {
    let engine = ScriptEngine::new();
    register_all_scripts(&engine).await.unwrap();

    let context = ScriptContext {
        target_ip: "192.0.2.1".parse::<IpAddr>().unwrap(),
        target_port: Some(22),
        protocol: Some("tcp".to_string()),
        service: Some("ssh".to_string()),
        version: None,
        os_info: None,
        timing: ScriptTiming::default(),
        user_args: HashMap::new(),
    };

    let result = engine.execute_for_service("ssh", &context).await;
    assert!(result.is_ok(), "Service-based execution should succeed");
}

#[tokio::test]
async fn test_vulnerability_severity_ordering() {
    use VulnerabilitySeverity::*;

    // Test that we can compare severities
    let critical = Critical;
    let high = High;
    let medium = Medium;

    assert!(format!("{}", critical).contains("CRITICAL"));
    assert!(format!("{}", high).contains("HIGH"));
    assert!(format!("{}", medium).contains("MEDIUM"));
}

#[tokio::test]
async fn test_script_result_builder() {
    let result = ScriptResult::success("Test output".to_string());
    assert!(result.success);
    assert_eq!(result.output, "Test output");

    let failure = ScriptResult::failure("Test error".to_string());
    assert!(!failure.success);
    assert_eq!(failure.output, "Test error");
}

#[tokio::test]
async fn test_vulnerability_result() {
    let vuln = Vulnerability {
        id: "TEST-001".to_string(),
        title: "Test Vulnerability".to_string(),
        severity: VulnerabilitySeverity::High,
        description: "This is a test".to_string(),
        references: vec!["https://example.com".to_string()],
        cvss_score: Some(7.5),
    };

    let result = ScriptResult::success("Found vuln".to_string())
        .with_vulnerability(vuln.clone());

    assert_eq!(result.vulnerabilities.len(), 1);
    assert_eq!(result.vulnerabilities[0].id, "TEST-001");
}

#[test]
fn test_get_scripts_for_service() {
    use nmap_scripting::registry::get_scripts_for_service;

    let http_scripts = get_scripts_for_service("http");
    assert!(!http_scripts.is_empty());
    assert!(http_scripts.contains(&"http-title"));
    assert!(http_scripts.contains(&"http-security-headers"));

    let ssh_scripts = get_scripts_for_service("ssh");
    assert!(ssh_scripts.contains(&"ssh-weak-algorithms"));

    let unknown_scripts = get_scripts_for_service("unknown-service");
    assert_eq!(unknown_scripts.len(), 0);
}

#[test]
fn test_get_vulnerability_scripts() {
    use nmap_scripting::registry::get_vulnerability_scripts;

    let vuln_scripts = get_vulnerability_scripts();
    assert_eq!(vuln_scripts.len(), 20);

    // Verify some key vulnerabilities
    assert!(vuln_scripts.contains(&"ssl-heartbleed"));
    assert!(vuln_scripts.contains(&"smb-vuln-ms17-010"));
    assert!(vuln_scripts.contains(&"http-vuln-cve2021-41773"));
}

#[test]
fn test_get_safe_scripts() {
    use nmap_scripting::registry::get_safe_scripts;

    let safe_scripts = get_safe_scripts();
    assert!(!safe_scripts.is_empty());

    // Safe scripts should not include intrusive tests
    assert!(!safe_scripts.contains(&"http-sql-injection"));
    assert!(!safe_scripts.contains(&"smtp-open-relay"));
}

#[cfg(test)]
mod common_tests {
    use nmap_scripting::common::*;

    #[test]
    fn test_version_compare() {
        assert_eq!(version_compare("1.0.0", "1.0.0"), std::cmp::Ordering::Equal);
        assert_eq!(version_compare("1.0.0", "2.0.0"), std::cmp::Ordering::Less);
        assert_eq!(version_compare("2.0.0", "1.0.0"), std::cmp::Ordering::Greater);
        assert_eq!(version_compare("1.2.3", "1.2.4"), std::cmp::Ordering::Less);
        assert_eq!(version_compare("2.4.49", "2.4.50"), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_is_version_vulnerable() {
        assert!(is_version_vulnerable("1.0.0", "2.0.0"));
        assert!(!is_version_vulnerable("2.0.0", "1.0.0"));
        assert!(!is_version_vulnerable("1.0.0", "1.0.0"));
        assert!(is_version_vulnerable("2.4.49", "2.4.51"));
    }

    #[test]
    fn test_sanitize_output() {
        let dirty = "Hello\x00\x1b[31mWorld";
        let clean = sanitize_output(dirty);
        assert!(!clean.contains('\x00'));
    }

    #[test]
    fn test_parse_version() {
        assert_eq!(
            parse_version("Apache/2.4.49", "Apache"),
            Some("2.4.49".to_string())
        );
        assert_eq!(
            parse_version("nginx/1.18.0", "nginx"),
            Some("1.18.0".to_string())
        );
        assert_eq!(
            parse_version("OpenSSH_7.4", "OpenSSH"),
            Some("7.4".to_string())
        );
    }

    #[test]
    fn test_extract_http_headers() {
        let response = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\nContent-Type: text/html\r\n\r\n";
        let headers = extract_http_headers(response);

        assert_eq!(headers.get("server"), Some(&"Apache/2.4.49".to_string()));
        assert_eq!(headers.get("content-type"), Some(&"text/html".to_string()));
    }
}
