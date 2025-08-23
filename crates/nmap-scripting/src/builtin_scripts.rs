use super::engine::*;
use anyhow::Result;
use std::collections::HashMap;
use tokio::time::{timeout, Duration};

/// Built-in scripts that replace common NSE functionality

pub struct HttpTitleScript;

#[async_trait::async_trait]
impl Script for HttpTitleScript {
    fn name(&self) -> &str { "http-title" }
    fn description(&self) -> &str { "Retrieves the title of the root page of a web server" }
    fn categories(&self) -> Vec<ScriptCategory> { vec![ScriptCategory::Default, ScriptCategory::Discovery, ScriptCategory::Safe] }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("http") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(80);
        let url = format!("http://{}:{}/", context.target_ip, port);

        match timeout(context.timing.timeout, reqwest::get(&url)).await {
            Ok(Ok(response)) => {
                let text = response.text().await?;
                if let Some(title) = extract_title(&text) {
                    Ok(ScriptResult::success(format!("Title: {}", title))
                        .with_data("title".to_string(), serde_json::Value::String(title)))
                } else {
                    Ok(ScriptResult::success("No title found".to_string()))
                }
            }
            Ok(Err(e)) => Ok(ScriptResult::failure(format!("HTTP request failed: {}", e))),
            Err(_) => Ok(ScriptResult::failure("Request timed out".to_string())),
        }
    }
}

pub struct SshVersionScript;

#[async_trait::async_trait]
impl Script for SshVersionScript {
    fn name(&self) -> &str { "ssh-version" }
    fn description(&self) -> &str { "Detects SSH version and banner information" }
    fn categories(&self) -> Vec<ScriptCategory> { vec![ScriptCategory::Default, ScriptCategory::Version, ScriptCategory::Safe] }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("ssh") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(22);
        let addr = format!("{}:{}", context.target_ip, port);

        match timeout(context.timing.timeout, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                
                let mut buffer = [0; 1024];
                match stream.read(&mut buffer).await {
                    Ok(n) => {
                        let banner = String::from_utf8_lossy(&buffer[..n]);
                        let version_info = parse_ssh_banner(&banner);
                        
                        Ok(ScriptResult::success(format!("SSH Banner: {}", banner.trim()))
                            .with_data("banner".to_string(), serde_json::Value::String(banner.trim().to_string()))
                            .with_data("version_info".to_string(), serde_json::to_value(version_info)?))
                    }
                    Err(e) => Ok(ScriptResult::failure(format!("Failed to read SSH banner: {}", e))),
                }
            }
            Ok(Err(e)) => Ok(ScriptResult::failure(format!("Connection failed: {}", e))),
            Err(_) => Ok(ScriptResult::failure("Connection timed out".to_string())),
        }
    }
}

pub struct FtpBannerScript;

#[async_trait::async_trait]
impl Script for FtpBannerScript {
    fn name(&self) -> &str { "ftp-banner" }
    fn description(&self) -> &str { "Retrieves FTP banner information" }
    fn categories(&self) -> Vec<ScriptCategory> { vec![ScriptCategory::Default, ScriptCategory::Version, ScriptCategory::Safe] }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("ftp") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(21);
        let addr = format!("{}:{}", context.target_ip, port);

        match timeout(context.timing.timeout, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                
                let mut buffer = [0; 1024];
                match stream.read(&mut buffer).await {
                    Ok(n) => {
                        let banner = String::from_utf8_lossy(&buffer[..n]);
                        
                        Ok(ScriptResult::success(format!("FTP Banner: {}", banner.trim()))
                            .with_data("banner".to_string(), serde_json::Value::String(banner.trim().to_string())))
                    }
                    Err(e) => Ok(ScriptResult::failure(format!("Failed to read FTP banner: {}", e))),
                }
            }
            Ok(Err(e)) => Ok(ScriptResult::failure(format!("Connection failed: {}", e))),
            Err(_) => Ok(ScriptResult::failure("Connection timed out".to_string())),
        }
    }
}

pub struct SmtpCommandsScript;

#[async_trait::async_trait]
impl Script for SmtpCommandsScript {
    fn name(&self) -> &str { "smtp-commands" }
    fn description(&self) -> &str { "Attempts to use EHLO and HELP to gather SMTP commands" }
    fn categories(&self) -> Vec<ScriptCategory> { vec![ScriptCategory::Default, ScriptCategory::Discovery, ScriptCategory::Safe] }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("smtp") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(25);
        let addr = format!("{}:{}", context.target_ip, port);

        match timeout(context.timing.timeout, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                
                // Read initial banner
                let mut buffer = [0; 1024];
                let _ = stream.read(&mut buffer).await?;
                
                // Send EHLO command
                stream.write_all(b"EHLO rmap.local\r\n").await?;
                let mut response = [0; 2048];
                let n = stream.read(&mut response).await?;
                let ehlo_response = String::from_utf8_lossy(&response[..n]);
                
                let commands = parse_smtp_commands(&ehlo_response);
                
                Ok(ScriptResult::success(format!("SMTP Commands: {}", commands.join(", ")))
                    .with_data("commands".to_string(), serde_json::Value::Array(
                        commands.into_iter().map(serde_json::Value::String).collect()
                    )))
            }
            Ok(Err(e)) => Ok(ScriptResult::failure(format!("Connection failed: {}", e))),
            Err(_) => Ok(ScriptResult::failure("Connection timed out".to_string())),
        }
    }
}

pub struct DnsVersionScript;

#[async_trait::async_trait]
impl Script for DnsVersionScript {
    fn name(&self) -> &str { "dns-version" }
    fn description(&self) -> &str { "Attempts to determine DNS server version" }
    fn categories(&self) -> Vec<ScriptCategory> { vec![ScriptCategory::Default, ScriptCategory::Version, ScriptCategory::Safe] }
    fn author(&self) -> &str { "R-Map Contributors" }
    fn license(&self) -> &str { "MIT OR Apache-2.0" }

    fn requires_port(&self) -> bool { true }
    fn requires_service(&self) -> Option<&str> { Some("dns") }

    async fn execute(&self, context: &ScriptContext) -> Result<ScriptResult> {
        let port = context.target_port.unwrap_or(53);
        
        // Create a simple DNS query for version.bind CH TXT
        let query = create_dns_version_query();
        
        match timeout(
            context.timing.timeout,
            tokio::net::UdpSocket::bind("0.0.0.0:0")
        ).await {
            Ok(Ok(socket)) => {
                let addr = format!("{}:{}", context.target_ip, port);
                match socket.send_to(&query, &addr).await {
                    Ok(_) => {
                        let mut buffer = [0; 512];
                        match socket.recv(&mut buffer).await {
                            Ok(n) => {
                                let response = parse_dns_version_response(&buffer[..n]);
                                Ok(ScriptResult::success(format!("DNS Version: {}", response))
                                    .with_data("version".to_string(), serde_json::Value::String(response)))
                            }
                            Err(e) => Ok(ScriptResult::failure(format!("Failed to receive DNS response: {}", e))),
                        }
                    }
                    Err(e) => Ok(ScriptResult::failure(format!("Failed to send DNS query: {}", e))),
                }
            }
            Ok(Err(e)) => Ok(ScriptResult::failure(format!("Failed to create UDP socket: {}", e))),
            Err(_) => Ok(ScriptResult::failure("Operation timed out".to_string())),
        }
    }
}

// Helper functions

fn extract_title(html: &str) -> Option<String> {
    let title_start = html.find("<title>")?;
    let title_end = html.find("</title>")?;
    if title_end > title_start {
        let title = &html[title_start + 7..title_end];
        Some(title.trim().to_string())
    } else {
        None
    }
}

fn parse_ssh_banner(banner: &str) -> HashMap<String, String> {
    let mut info = HashMap::new();
    
    if let Some(version_line) = banner.lines().next() {
        if version_line.starts_with("SSH-") {
            let parts: Vec<&str> = version_line.split('-').collect();
            if parts.len() >= 3 {
                info.insert("protocol_version".to_string(), parts[1].to_string());
                info.insert("software_version".to_string(), parts[2].to_string());
            }
        }
    }
    
    info
}

fn parse_smtp_commands(response: &str) -> Vec<String> {
    let mut commands = Vec::new();
    
    for line in response.lines() {
        if line.starts_with("250-") || line.starts_with("250 ") {
            let command = line[4..].trim();
            if !command.is_empty() && command.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
                commands.push(command.to_string());
            }
        }
    }
    
    commands
}

fn create_dns_version_query() -> Vec<u8> {
    // Simple DNS query for version.bind CH TXT
    // This is a basic implementation - a full DNS library would be better
    vec![
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Query: version.bind
        0x07, b'v', b'e', b'r', b's', b'i', b'o', b'n',
        0x04, b'b', b'i', b'n', b'd',
        0x00, // End of name
        0x00, 0x10, // Type: TXT
        0x00, 0x03, // Class: CH (Chaos)
    ]
}

fn parse_dns_version_response(response: &[u8]) -> String {
    // Basic DNS response parsing
    if response.len() < 12 {
        return "Invalid response".to_string();
    }
    
    // Check if it's a response and has answers
    let flags = u16::from_be_bytes([response[2], response[3]]);
    let answers = u16::from_be_bytes([response[6], response[7]]);
    
    if (flags & 0x8000) != 0 && answers > 0 {
        // Try to extract version string from TXT record
        // This is simplified - real DNS parsing is more complex
        if let Some(txt_start) = response.windows(7).position(|w| w == b"version") {
            if let Some(version_data) = response.get(txt_start + 20..) {
                if let Some(len) = version_data.get(0) {
                    if let Some(version_bytes) = version_data.get(1..=*len as usize) {
                        return String::from_utf8_lossy(version_bytes).to_string();
                    }
                }
            }
        }
    }
    
    "Version not available".to_string()
}

/// Register all built-in scripts with the engine
pub async fn register_builtin_scripts(engine: &ScriptEngine) -> Result<()> {
    engine.register_script(Box::new(HttpTitleScript)).await?;
    engine.register_script(Box::new(SshVersionScript)).await?;
    engine.register_script(Box::new(FtpBannerScript)).await?;
    engine.register_script(Box::new(SmtpCommandsScript)).await?;
    engine.register_script(Box::new(DnsVersionScript)).await?;
    
    Ok(())
}