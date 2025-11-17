/// Service-Specific Vulnerability Detection Scripts (SSH, FTP, Database)
use super::engine::*;
use super::common::*;
use anyhow::Result;

/// SSH Weak Algorithms Detection
pub struct SSHWeakAlgorithms;

#[async_trait::async_trait]
impl Script for SSHWeakAlgorithms {
    fn name(&self) -> &str { "ssh-weak-algorithms" }
    fn description(&self) -> &str { "Detects weak cryptographic algorithms in SSH" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Safe, ScriptCategory::Discovery]
    }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("ssh") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(22);
        let addr = format!("{}:{}", context.target_ip, port);

        match tcp_connect(&addr, 5).await {
            Ok(mut stream) => {
                // Read SSH banner
                let mut buffer = vec![0u8; 2048];
                match tcp_read(&mut stream, &mut buffer, 5).await {
                    Ok(n) => {
                        let banner = String::from_utf8_lossy(&buffer[..n]);

                        // Check for weak SSH versions
                        if banner.starts_with("SSH-1") {
                            let vuln = Vulnerability {
                                id: "SSH-WEAK-VERSION".to_string(),
                                title: "Weak SSH Protocol Version".to_string(),
                                severity: VulnerabilitySeverity::High,
                                description: "Server supports SSH protocol version 1.x which has known vulnerabilities".to_string(),
                                references: vec![
                                    "https://www.openssh.com/legacy.html".to_string(),
                                ],
                                cvss_score: Some(7.0),
                            };

                            return Ok(ScriptResult::success(
                                format!("VULNERABLE: Weak SSH version detected - {}", banner.trim())
                            ).with_vulnerability(vuln));
                        }

                        // Send SSH key exchange to get supported algorithms
                        let kex_init = build_ssh_kex_init();
                        if tcp_write(&mut stream, &kex_init, 5).await.is_ok() {
                            let mut kex_buffer = vec![0u8; 4096];
                            if let Ok(kex_n) = tcp_read(&mut stream, &mut kex_buffer, 5).await {
                                let weak_algos = check_weak_ssh_algorithms(&kex_buffer[..kex_n]);

                                if !weak_algos.is_empty() {
                                    let vuln = Vulnerability {
                                        id: "SSH-WEAK-ALGORITHMS".to_string(),
                                        title: "Weak SSH Cryptographic Algorithms".to_string(),
                                        severity: VulnerabilitySeverity::Medium,
                                        description: format!(
                                            "Server supports weak algorithms: {}",
                                            weak_algos.join(", ")
                                        ),
                                        references: vec![],
                                        cvss_score: Some(5.0),
                                    };

                                    return Ok(ScriptResult::success(
                                        format!("Weak algorithms found: {}", weak_algos.join(", "))
                                    ).with_vulnerability(vuln));
                                }
                            }
                        }

                        Ok(ScriptResult::success("No weak algorithms detected".to_string()))
                    }
                    Err(e) => Ok(ScriptResult::failure(format!("Failed to read banner: {}", e))),
                }
            }
            Err(e) => Ok(ScriptResult::failure(format!("Connection failed: {}", e))),
        }
    }
}

/// FTP Anonymous Login Detection
pub struct FTPAnonymous;

#[async_trait::async_trait]
impl Script for FTPAnonymous {
    fn name(&self) -> &str { "ftp-anon" }
    fn description(&self) -> &str { "Detects anonymous FTP access" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Auth, ScriptCategory::Safe]
    }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("ftp") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(21);
        let addr = format!("{}:{}", context.target_ip, port);

        match tcp_connect(&addr, 5).await {
            Ok(mut stream) => {
                // Read welcome banner
                let mut buffer = vec![0u8; 1024];
                match tcp_read(&mut stream, &mut buffer, 5).await {
                    Ok(n) => {
                        let _banner = String::from_utf8_lossy(&buffer[..n]);

                        // Send USER anonymous
                        let user_cmd = b"USER anonymous\r\n";
                        if tcp_write(&mut stream, user_cmd, 5).await.is_err() {
                            return Ok(ScriptResult::failure("Failed to send USER command".to_string()));
                        }

                        // Read response
                        let mut resp = vec![0u8; 1024];
                        if let Ok(resp_n) = tcp_read(&mut stream, &mut resp, 5).await {
                            let _response = String::from_utf8_lossy(&resp[..resp_n]);

                            // Send PASS
                            let pass_cmd = b"PASS anonymous@example.com\r\n";
                            if tcp_write(&mut stream, pass_cmd, 5).await.is_err() {
                                return Ok(ScriptResult::failure("Failed to send PASS command".to_string()));
                            }

                            // Check login response
                            let mut login_resp = vec![0u8; 1024];
                            if let Ok(login_n) = tcp_read(&mut stream, &mut login_resp, 5).await {
                                let login_response = String::from_utf8_lossy(&login_resp[..login_n]);

                                // Check for successful login (230 code)
                                if login_response.starts_with("230") {
                                    let vuln = Vulnerability {
                                        id: "FTP-ANON-ACCESS".to_string(),
                                        title: "Anonymous FTP Access Enabled".to_string(),
                                        severity: VulnerabilitySeverity::Medium,
                                        description: "FTP server allows anonymous login".to_string(),
                                        references: vec![],
                                        cvss_score: Some(5.0),
                                    };

                                    return Ok(ScriptResult::success(
                                        "VULNERABLE: Anonymous FTP login allowed".to_string()
                                    ).with_vulnerability(vuln));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        return Ok(ScriptResult::failure(format!("Failed to read banner: {}", e)));
                    }
                }
            }
            Err(e) => {
                return Ok(ScriptResult::failure(format!("Connection failed: {}", e)));
            }
        }

        Ok(ScriptResult::success("Anonymous FTP not allowed".to_string()))
    }
}

/// MySQL Empty Password Detection
pub struct MySQLEmptyPassword;

#[async_trait::async_trait]
impl Script for MySQLEmptyPassword {
    fn name(&self) -> &str { "mysql-empty-password" }
    fn description(&self) -> &str { "Checks for MySQL root account with empty password" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Auth, ScriptCategory::Intrusive]
    }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("mysql") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(3306);
        let addr = format!("{}:{}", context.target_ip, port);

        match tcp_connect(&addr, 5).await {
            Ok(mut stream) => {
                // Read MySQL greeting
                let mut buffer = vec![0u8; 1024];
                match tcp_read(&mut stream, &mut buffer, 5).await {
                    Ok(n) => {
                        if n < 10 || buffer[4] != 10 {
                            return Ok(ScriptResult::failure("Invalid MySQL greeting".to_string()));
                        }

                        // Build login packet with empty password
                        let login_packet = build_mysql_login_packet("root", "");

                        // Send login attempt
                        if tcp_write(&mut stream, &login_packet, 5).await.is_err() {
                            return Ok(ScriptResult::failure("Failed to send login packet".to_string()));
                        }

                        // Read response
                        let mut resp = vec![0u8; 1024];
                        if let Ok(resp_n) = tcp_read(&mut stream, &mut resp, 5).await {
                            // Check for OK packet (0x00) which indicates successful auth
                            if resp_n > 4 && resp[4] == 0x00 {
                                let vuln = Vulnerability {
                                    id: "MYSQL-EMPTY-PASSWORD".to_string(),
                                    title: "MySQL Empty Root Password".to_string(),
                                    severity: VulnerabilitySeverity::Critical,
                                    description: "MySQL root account has an empty password".to_string(),
                                    references: vec![],
                                    cvss_score: Some(9.0),
                                };

                                return Ok(ScriptResult::success(
                                    "VULNERABLE: MySQL root account has empty password".to_string()
                                ).with_vulnerability(vuln));
                            }
                        }
                    }
                    Err(e) => {
                        return Ok(ScriptResult::failure(format!("Failed to read greeting: {}", e)));
                    }
                }
            }
            Err(e) => {
                return Ok(ScriptResult::failure(format!("Connection failed: {}", e)));
            }
        }

        Ok(ScriptResult::success("MySQL root password is set".to_string()))
    }
}

/// Telnet Encryption Check
pub struct TelnetEncryption;

#[async_trait::async_trait]
impl Script for TelnetEncryption {
    fn name(&self) -> &str { "telnet-encryption" }
    fn description(&self) -> &str { "Checks if Telnet service uses encryption" }
    fn categories(&self) -> Vec<ScriptCategory> {
        vec![ScriptCategory::Vuln, ScriptCategory::Safe, ScriptCategory::Discovery]
    }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("telnet") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(23);
        let addr = format!("{}:{}", context.target_ip, port);

        match tcp_connect(&addr, 5).await {
            Ok(mut stream) => {
                // Read initial Telnet negotiation
                let mut buffer = vec![0u8; 1024];
                match tcp_read(&mut stream, &mut buffer, 3).await {
                    Ok(n) => {
                        // Check for encryption option (ENCRYPT - option 38)
                        let has_encryption = buffer[..n].windows(3).any(|w| {
                            w[0] == 0xff && // IAC
                            (w[1] == 0xfd || w[1] == 0xfb) && // DO or WILL
                            w[2] == 38 // ENCRYPT option
                        });

                        if !has_encryption {
                            let vuln = Vulnerability {
                                id: "TELNET-NO-ENCRYPTION".to_string(),
                                title: "Telnet Service Without Encryption".to_string(),
                                severity: VulnerabilitySeverity::High,
                                description: "Telnet service does not support encryption - all traffic sent in cleartext".to_string(),
                                references: vec![
                                    "https://tools.ietf.org/html/rfc2946".to_string(),
                                ],
                                cvss_score: Some(7.5),
                            };

                            return Ok(ScriptResult::success(
                                "VULNERABLE: Telnet does not use encryption".to_string()
                            ).with_vulnerability(vuln));
                        }

                        Ok(ScriptResult::success("Telnet encryption option available".to_string()))
                    }
                    Err(e) => Ok(ScriptResult::failure(format!("Failed to read: {}", e))),
                }
            }
            Err(e) => Ok(ScriptResult::failure(format!("Connection failed: {}", e))),
        }
    }
}

// Helper functions

fn build_ssh_kex_init() -> Vec<u8> {
    // Simplified SSH Key Exchange Init packet
    vec![
        0x00, 0x00, 0x00, 0x1c, // Packet Length
        0x0a, // Padding Length
        0x14, // Message Type: SSH_MSG_KEXINIT
        // Random cookie (16 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Padding
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]
}

fn check_weak_ssh_algorithms(data: &[u8]) -> Vec<String> {
    let mut weak = Vec::new();

    // Check for weak algorithms in the response
    let data_str = String::from_utf8_lossy(data).to_lowercase();

    let weak_patterns = vec![
        ("arcfour", "Weak cipher"),
        ("des", "Weak cipher"),
        ("md5", "Weak MAC"),
        ("sha1", "Weak MAC"),
        ("diffie-hellman-group1", "Weak key exchange"),
    ];

    for (pattern, _desc) in weak_patterns {
        if data_str.contains(pattern) {
            weak.push(pattern.to_string());
        }
    }

    weak
}

fn build_mysql_login_packet(username: &str, password: &str) -> Vec<u8> {
    // Simplified MySQL authentication packet
    let mut packet = vec![
        0x85, 0xa6, 0x03, 0x00, // Client capabilities
        0x00, 0x00, 0x00, 0x01, // Max packet size
        0x21, // Charset (utf8)
        // Reserved (23 bytes of 0x00)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // Add username (null-terminated)
    packet.extend_from_slice(username.as_bytes());
    packet.push(0x00);

    // Add password length and password
    if password.is_empty() {
        packet.push(0x00); // Empty password
    } else {
        packet.push(password.len() as u8);
        packet.extend_from_slice(password.as_bytes());
    }

    // Prepend packet length
    let len = (packet.len() as u32).to_le_bytes();
    let mut final_packet = vec![len[0], len[1], len[2], 0x01]; // Sequence number = 1
    final_packet.extend_from_slice(&packet);

    final_packet
}
