/// Network Service Vulnerability Detection Scripts (DNS, SMTP, NTP, SNMP, RDP)
use super::engine::*;
use super::common::*;
use anyhow::Result;

/// DNS Zone Transfer Detection
pub struct DNSZoneTransfer;

#[async_trait::async_trait]
impl Script for DNSZoneTransfer {
    fn name(&self) -> &str { "dns-zone-transfer" }
    fn description(&self) -> &str { "Checks if DNS server allows zone transfers (AXFR)" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Discovery, ScriptCategory::Intrusive]
    }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("dns") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(53);
        let addr = format!("{}:{}", context.target_ip, port);

        // Build AXFR query for a common domain
        let axfr_query = build_dns_axfr_query("example.com");

        // Zone transfers use TCP
        match tcp_connect(&addr, 5).await {
            Ok(mut stream) => {
                // Send length-prefixed query (TCP DNS format)
                let len = (axfr_query.len() as u16).to_be_bytes();
                let mut tcp_query = Vec::new();
                tcp_query.extend_from_slice(&len);
                tcp_query.extend_from_slice(&axfr_query);

                if tcp_write(&mut stream, &tcp_query, 5).await.is_err() {
                    return Ok(ScriptResult::failure("Failed to send AXFR query".to_string()));
                }

                // Read response
                let mut buffer = vec![0u8; 4096];
                match tcp_read(&mut stream, &mut buffer, 10).await {
                    Ok(n) => {
                        if n > 12 {
                            // Check response code (RCODE in DNS header)
                            let rcode = buffer[3] & 0x0f;

                            if rcode == 0 {
                                // NOERROR - zone transfer may have succeeded
                                let vuln = Vulnerability {
                                    id: "DNS-ZONE-TRANSFER".to_string(),
                                    title: "DNS Zone Transfer Allowed".to_string(),
                                    severity: VulnerabilitySeverity::High,
                                    description: "DNS server allows zone transfers (AXFR), potentially exposing domain structure".to_string(),
                                    references: vec![
                                        "https://www.ietf.org/rfc/rfc5936.txt".to_string(),
                                    ],
                                    cvss_score: Some(7.5),
                                };

                                return Ok(ScriptResult::success(
                                    "VULNERABLE: DNS zone transfer allowed".to_string()
                                ).with_vulnerability(vuln));
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
            Err(_) => {
                return Ok(ScriptResult::failure("TCP connection failed".to_string()));
            }
        }

        Ok(ScriptResult::success("Zone transfer not allowed".to_string()))
    }
}

/// SMTP Open Relay Detection
pub struct SMTPOpenRelay;

#[async_trait::async_trait]
impl Script for SMTPOpenRelay {
    fn name(&self) -> &str { "smtp-open-relay" }
    fn description(&self) -> &str { "Tests if SMTP server is an open relay" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Intrusive]
    }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("smtp") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(25);
        let addr = format!("{}:{}", context.target_ip, port);

        match tcp_connect(&addr, 5).await {
            Ok(mut stream) => {
                // Read banner
                let mut buffer = vec![0u8; 1024];
                let _ = tcp_read(&mut stream, &mut buffer, 5).await?;

                // SMTP conversation to test relay
                let commands: Vec<&[u8]> = vec![
                    b"HELO rmap.test\r\n",
                    b"MAIL FROM:<test@external.com>\r\n",
                    b"RCPT TO:<abuse@external.com>\r\n",
                ];

                for cmd in commands {
                    tcp_write(&mut stream, cmd, 5).await?;

                    let mut resp = vec![0u8; 1024];
                    let n = tcp_read(&mut stream, &mut resp, 5).await?;
                    let response = String::from_utf8_lossy(&resp[..n]);

                    // Check for rejection codes (5xx)
                    if response.starts_with('5') {
                        return Ok(ScriptResult::success(
                            "Not an open relay - relay rejected".to_string()
                        ));
                    }

                    // If we get to RCPT TO with 2xx code, it's likely an open relay
                    if cmd.starts_with(b"RCPT TO") && response.starts_with('2') {
                        let vuln = Vulnerability {
                            id: "SMTP-OPEN-RELAY".to_string(),
                            title: "SMTP Open Relay".to_string(),
                            severity: VulnerabilitySeverity::High,
                            description: "SMTP server accepts mail for external domains without authentication".to_string(),
                            references: vec![],
                            cvss_score: Some(7.0),
                        };

                        // Send QUIT
                        let _ = tcp_write(&mut stream, b"QUIT\r\n", 5).await;

                        return Ok(ScriptResult::success(
                            "VULNERABLE: SMTP open relay detected".to_string()
                        ).with_vulnerability(vuln));
                    }
                }
            }
            Err(e) => {
                return Ok(ScriptResult::failure(format!("Connection failed: {}", e)));
            }
        }

        Ok(ScriptResult::success("Not an open relay".to_string()))
    }
}

/// NTP Monlist Detection
pub struct NTPMonlist;

#[async_trait::async_trait]
impl Script for NTPMonlist {
    fn name(&self) -> &str { "ntp-monlist" }
    fn description(&self) -> &str { "Checks if NTP server is vulnerable to monlist command (CVE-2013-5211)" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Safe]
    }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("ntp") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(123);
        let addr = format!("{}:{}", context.target_ip, port);

        // Build NTP monlist request (mode 7, private)
        let monlist_request = build_ntp_monlist_request();

        match udp_exchange(&addr, &monlist_request, 5).await {
            Ok(response) => {
                // Check if we got a valid monlist response
                if response.len() > 48 && is_ntp_monlist_response(&response) {
                    let vuln = Vulnerability {
                        id: "CVE-2013-5211".to_string(),
                        title: "NTP Monlist Amplification".to_string(),
                        severity: VulnerabilitySeverity::High,
                        description: "NTP server responds to monlist queries, can be used for DDoS amplification".to_string(),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2013-5211".to_string(),
                        ],
                        cvss_score: Some(7.5),
                    };

                    return Ok(ScriptResult::success(
                        format!("VULNERABLE: NTP monlist enabled (amplification factor: ~{}x)",
                                response.len() / monlist_request.len())
                    ).with_vulnerability(vuln));
                }
            }
            Err(_) => {
                return Ok(ScriptResult::failure("No response from NTP server".to_string()));
            }
        }

        Ok(ScriptResult::success("NTP monlist disabled".to_string()))
    }
}

/// SNMP Default Community Strings
pub struct SNMPDefaultCommunity;

#[async_trait::async_trait]
impl Script for SNMPDefaultCommunity {
    fn name(&self) -> &str { "snmp-default-community" }
    fn description(&self) -> &str { "Tests for default SNMP community strings" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Auth, ScriptCategory::Intrusive]
    }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("snmp") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(161);
        let addr = format!("{}:{}", context.target_ip, port);

        // Common default community strings
        let communities = vec!["public", "private", "community", "snmp"];

        for community in communities {
            let snmp_request = build_snmp_get_request(community);

            match udp_exchange(&addr, &snmp_request, 3).await {
                Ok(response) => {
                    // Check if we got a valid SNMP response (not an error)
                    if is_valid_snmp_response(&response) {
                        let vuln = Vulnerability {
                            id: "SNMP-DEFAULT-COMMUNITY".to_string(),
                            title: "Default SNMP Community String".to_string(),
                            severity: VulnerabilitySeverity::High,
                            description: format!(
                                "SNMP service uses default community string: {}",
                                community
                            ),
                            references: vec![],
                            cvss_score: Some(7.5),
                        };

                        return Ok(ScriptResult::success(
                            format!("VULNERABLE: Default community string found: {}", community)
                        ).with_vulnerability(vuln));
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(ScriptResult::success("No default community strings found".to_string()))
    }
}

/// RDP MS12-020 Vulnerability
pub struct RDPMS12020;

#[async_trait::async_trait]
impl Script for RDPMS12020 {
    fn name(&self) -> &str { "rdp-vuln-ms12-020" }
    fn description(&self) -> &str { "Detects MS12-020 RDP vulnerability" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Safe]
    }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("ms-wbt-server") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(3389);
        let addr = format!("{}:{}", context.target_ip, port);

        // RDP Connection Request
        let rdp_conn_request = build_rdp_connection_request();

        match tcp_connect(&addr, 5).await {
            Ok(mut stream) => {
                if tcp_write(&mut stream, &rdp_conn_request, 5).await.is_err() {
                    return Ok(ScriptResult::failure("Failed to send RDP request".to_string()));
                }

                let mut buffer = vec![0u8; 4096];
                match tcp_read(&mut stream, &mut buffer, 5).await {
                    Ok(n) => {
                        if n > 0 && is_rdp_response(&buffer[..n]) {
                            // Try to trigger vulnerability with multiple user requests
                            let user_request = build_rdp_user_request();

                            // Send multiple requests (MS12-020 vulnerability)
                            for _ in 0..5 {
                                if tcp_write(&mut stream, &user_request, 5).await.is_err() {
                                    break;
                                }
                            }

                            // Check if server crashes or responds abnormally
                            let mut resp = vec![0u8; 1024];
                            match tcp_read(&mut stream, &mut resp, 3).await {
                                Ok(0) => {
                                    // Connection closed - might be vulnerable
                                    let vuln = Vulnerability {
                                        id: "MS12-020".to_string(),
                                        title: "RDP Remote Code Execution Vulnerability".to_string(),
                                        severity: VulnerabilitySeverity::Critical,
                                        description: "RDP service may be vulnerable to MS12-020".to_string(),
                                        references: vec![
                                            "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-020".to_string(),
                                        ],
                                        cvss_score: Some(9.3),
                                    };

                                    return Ok(ScriptResult::success(
                                        "POSSIBLY VULNERABLE: MS12-020 indicators detected".to_string()
                                    ).with_vulnerability(vuln));
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
            Err(e) => {
                return Ok(ScriptResult::failure(format!("Connection failed: {}", e)));
            }
        }

        Ok(ScriptResult::success("Not vulnerable to MS12-020".to_string()))
    }
}

/// XSS Detection (Basic)
pub struct HttpXSSDetection;

#[async_trait::async_trait]
impl Script for HttpXSSDetection {
    fn name(&self) -> &str { "http-xss-detection" }
    fn description(&self) -> &str { "Basic cross-site scripting (XSS) vulnerability detection" }
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

        // XSS test payloads
        let payloads = vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        ];

        for payload in payloads {
            let url = format!("http://{}:{}/?test={}",
                            context.target_ip, port,
                            urlencoding::encode(payload));

            match http_request(&client, &url, "GET", 10).await {
                Ok(response) => {
                    let body = response.text().await.unwrap_or_default();

                    // Check if payload is reflected unencoded
                    if body.contains("<script>") || body.contains("onerror=") {
                        let vuln = Vulnerability {
                            id: "XSS-REFLECTED".to_string(),
                            title: "Reflected Cross-Site Scripting".to_string(),
                            severity: VulnerabilitySeverity::High,
                            description: format!("XSS vulnerability detected with payload: {}", payload),
                            references: vec![
                                "https://owasp.org/www-community/attacks/xss/".to_string(),
                            ],
                            cvss_score: Some(7.5),
                        };

                        return Ok(ScriptResult::success(
                            "VULNERABLE: XSS vulnerability detected".to_string()
                        ).with_vulnerability(vuln));
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(ScriptResult::success("No XSS vulnerability detected".to_string()))
    }
}

// Helper functions

fn build_dns_axfr_query(domain: &str) -> Vec<u8> {
    let mut query = vec![
        0x00, 0x01, // Transaction ID
        0x00, 0x00, // Flags: Standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
    ];

    // Encode domain name
    for part in domain.split('.') {
        query.push(part.len() as u8);
        query.extend_from_slice(part.as_bytes());
    }
    query.push(0x00); // End of name

    query.extend_from_slice(&[
        0x00, 0xfc, // Type: AXFR (252)
        0x00, 0x01, // Class: IN
    ]);

    query
}

fn build_ntp_monlist_request() -> Vec<u8> {
    vec![
        0x17, 0x00, 0x03, 0x2a, // LI, VN, Mode=7 (private), Request code=42 (monlist)
        0x00, 0x00, 0x00, 0x00, // Rest of header
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]
}

fn is_ntp_monlist_response(data: &[u8]) -> bool {
    data.len() > 8 && (data[0] & 0x07) == 0x07 && data[1] == 0x00
}

fn build_snmp_get_request(community: &str) -> Vec<u8> {
    let mut request = vec![
        0x30, // SEQUENCE
        0x26, // Length (will be adjusted)
        0x02, 0x01, 0x00, // Version: SNMPv1
        0x04, community.len() as u8, // OCTET STRING
    ];
    request.extend_from_slice(community.as_bytes());

    request.extend_from_slice(&[
        0xa0, 0x19, // GetRequest PDU
        0x02, 0x01, 0x01, // Request ID
        0x02, 0x01, 0x00, // Error Status: 0
        0x02, 0x01, 0x00, // Error Index: 0
        0x30, 0x0e, // Variable bindings
        0x30, 0x0c, // Variable
        0x06, 0x08, // OID
        0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // sysDescr
        0x05, 0x00, // NULL
    ]);

    request
}

fn is_valid_snmp_response(data: &[u8]) -> bool {
    data.len() > 10 && data[0] == 0x30 && data[2] == 0x02
}

fn build_rdp_connection_request() -> Vec<u8> {
    vec![
        0x03, 0x00, 0x00, 0x13, // TPKT Header
        0x0e, 0xe0, 0x00, 0x00, // X.224 Connection Request
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x08, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ]
}

fn build_rdp_user_request() -> Vec<u8> {
    vec![
        0x03, 0x00, 0x00, 0x08, // TPKT
        0x02, 0xf0, 0x80, // X.224 Data
        0x00, // User request
    ]
}

fn is_rdp_response(data: &[u8]) -> bool {
    data.len() > 4 && data[0] == 0x03 && data[1] == 0x00
}
