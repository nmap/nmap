use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use std::io::{Read, Write};
use tokio::time::timeout;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 R-Map - Service Detection Demo");
    println!("===========================================\n");

    // Demo targets
    let targets = vec![
        (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), "localhost"),
        (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), "Google DNS"),
        (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), "Cloudflare DNS"),
    ];

    // Common ports to scan
    let ports = vec![21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080];

    for (target_ip, name) in targets {
        println!("🎯 Scanning target: {} ({})", target_ip, name);
        println!("{}", "─".repeat(50));
        
        let start_time = Instant::now();
        let mut open_ports = Vec::new();
        
        // Port scan
        println!("📡 Port Discovery:");
        for port in &ports {
            if is_port_open(target_ip, *port).await {
                open_ports.push(*port);
                println!("   {}/tcp - open", port);
            }
        }
        
        if open_ports.is_empty() {
            println!("   No open ports found");
        } else {
            println!("   Found {} open ports", open_ports.len());
        }
        
        // Service detection
        println!("\n🔧 Service Detection:");
        for port in &open_ports {
            match detect_service(target_ip, *port).await {
                Ok(service_info) => {
                    println!("   {}/tcp - {}", port, service_info);
                }
                Err(e) => {
                    println!("   {}/tcp - detection failed: {}", port, e);
                }
            }
        }
        
        let scan_time = start_time.elapsed();
        println!("\n📊 Scan completed in {:.2}s", scan_time.as_secs_f64());
        println!("{}\n", "=".repeat(60));
    }

    println!("✅ Demo completed successfully!");
    Ok(())
}

async fn is_port_open(ip: IpAddr, port: u16) -> bool {
    let addr = SocketAddr::new(ip, port);
    match timeout(Duration::from_millis(1000), TcpStream::connect(addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

async fn detect_service(ip: IpAddr, port: u16) -> Result<String, Box<dyn std::error::Error>> {
    let addr = SocketAddr::new(ip, port);
    
    // Try to connect and grab banner
    match timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            // Send appropriate probe based on port
            let probe = get_probe_for_port(port);
            
            if !probe.is_empty() {
                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(probe).await;
            }
            
            // Try to read banner
            let mut buffer = [0u8; 1024];
            use tokio::io::AsyncReadExt;
            match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buffer[..n]);
                    analyze_banner(&banner, port)
                }
                _ => {
                    // No banner, try to guess based on port
                    Ok(guess_service_by_port(port))
                }
            }
        }
        _ => Err("Connection failed".into()),
    }
}

fn get_probe_for_port(port: u16) -> &'static [u8] {
    match port {
        21 => b"", // FTP - just connect
        22 => b"", // SSH - just connect  
        25 => b"EHLO nmap\r\n", // SMTP
        80 | 8080 => b"GET / HTTP/1.0\r\n\r\n", // HTTP
        110 => b"", // POP3 - just connect
        143 => b"", // IMAP - just connect
        443 => b"", // HTTPS - would need TLS
        993 => b"", // IMAPS - would need TLS
        995 => b"", // POP3S - would need TLS
        _ => b"", // Generic - just connect
    }
}

fn analyze_banner(banner: &str, port: u16) -> Result<String, Box<dyn std::error::Error>> {
    let banner_lower = banner.to_lowercase();
    
    // HTTP detection
    if banner_lower.contains("http/") {
        if banner_lower.contains("apache") {
            if let Some(version) = extract_version(&banner_lower, "apache/") {
                return Ok(format!("http Apache httpd {}", version));
            }
            return Ok("http Apache httpd".to_string());
        } else if banner_lower.contains("nginx") {
            if let Some(version) = extract_version(&banner_lower, "nginx/") {
                return Ok(format!("http nginx {}", version));
            }
            return Ok("http nginx".to_string());
        } else if banner_lower.contains("iis") {
            return Ok("http Microsoft IIS".to_string());
        }
        return Ok("http".to_string());
    }
    
    // SSH detection
    if banner_lower.starts_with("ssh-") {
        if banner_lower.contains("openssh") {
            if let Some(version) = extract_ssh_version(&banner) {
                return Ok(format!("ssh OpenSSH {}", version));
            }
            return Ok("ssh OpenSSH".to_string());
        }
        return Ok("ssh".to_string());
    }
    
    // FTP detection
    if banner_lower.contains("ftp") {
        if banner_lower.contains("vsftpd") {
            if let Some(version) = extract_version(&banner_lower, "vsftpd ") {
                return Ok(format!("ftp vsftpd {}", version));
            }
            return Ok("ftp vsftpd".to_string());
        } else if banner_lower.contains("proftpd") {
            return Ok("ftp ProFTPD".to_string());
        }
        return Ok("ftp".to_string());
    }
    
    // SMTP detection
    if banner_lower.contains("smtp") || banner_lower.contains("mail") {
        if banner_lower.contains("postfix") {
            return Ok("smtp Postfix".to_string());
        } else if banner_lower.contains("sendmail") {
            return Ok("smtp Sendmail".to_string());
        } else if banner_lower.contains("exim") {
            return Ok("smtp Exim".to_string());
        }
        return Ok("smtp".to_string());
    }
    
    // POP3 detection
    if banner_lower.contains("pop3") || banner_lower.contains("+ok") {
        if banner_lower.contains("dovecot") {
            return Ok("pop3 Dovecot".to_string());
        }
        return Ok("pop3".to_string());
    }
    
    // IMAP detection
    if banner_lower.contains("imap") || banner_lower.contains("* ok") {
        if banner_lower.contains("dovecot") {
            return Ok("imap Dovecot".to_string());
        } else if banner_lower.contains("courier") {
            return Ok("imap Courier".to_string());
        }
        return Ok("imap".to_string());
    }
    
    // Telnet detection
    if banner_lower.contains("login:") || banner_lower.contains("username:") {
        return Ok("telnet".to_string());
    }
    
    // If we can't identify from banner, fall back to port-based guess
    Ok(format!("{} (banner: {})", 
        guess_service_by_port(port), 
        banner.chars().take(50).collect::<String>().replace('\n', "\\n")))
}

fn extract_version(text: &str, prefix: &str) -> Option<String> {
    if let Some(start) = text.find(prefix) {
        let version_start = start + prefix.len();
        let version_part = &text[version_start..];
        
        // Extract version until space or special character
        let version: String = version_part
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
            .collect();
            
        if !version.is_empty() {
            Some(version)
        } else {
            None
        }
    } else {
        None
    }
}

fn extract_ssh_version(banner: &str) -> Option<String> {
    // SSH banner format: SSH-2.0-OpenSSH_8.2p1
    if let Some(openssh_pos) = banner.find("OpenSSH_") {
        let version_start = openssh_pos + 8; // "OpenSSH_".len()
        let version_part = &banner[version_start..];
        
        let version: String = version_part
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect();
            
        if !version.is_empty() {
            Some(version)
        } else {
            None
        }
    } else {
        None
    }
}

fn guess_service_by_port(port: u16) -> String {
    match port {
        21 => "ftp".to_string(),
        22 => "ssh".to_string(),
        23 => "telnet".to_string(),
        25 => "smtp".to_string(),
        53 => "domain".to_string(),
        80 => "http".to_string(),
        110 => "pop3".to_string(),
        143 => "imap".to_string(),
        443 => "https".to_string(),
        993 => "imaps".to_string(),
        995 => "pop3s".to_string(),
        8080 => "http-proxy".to_string(),
        _ => "unknown".to_string(),
    }
}