/// Common utilities for vulnerability scripts
use anyhow::Result;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Maximum response size to prevent memory exhaustion
pub const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1MB

/// HTTP client builder with security defaults
pub fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .danger_accept_invalid_certs(true) // For vulnerability scanning
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {}", e))
}

/// Send HTTP request with timeout
pub async fn http_request(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    timeout_secs: u64,
) -> Result<reqwest::Response> {
    let request = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "HEAD" => client.head(url),
        "OPTIONS" => client.request(reqwest::Method::OPTIONS, url),
        _ => return Err(anyhow::anyhow!("Unsupported HTTP method: {}", method)),
    };

    let result = timeout(
        Duration::from_secs(timeout_secs),
        request.send(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Request timed out"))??;

    Ok(result)
}

/// Connect to TCP service with timeout
pub async fn tcp_connect(
    addr: &str,
    timeout_secs: u64,
) -> Result<TcpStream> {
    timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timed out"))?
    .map_err(|e| anyhow::anyhow!("Connection failed: {}", e))
}

/// Read data from TCP stream with timeout
pub async fn tcp_read(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    timeout_secs: u64,
) -> Result<usize> {
    timeout(
        Duration::from_secs(timeout_secs),
        stream.read(buffer),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Read timed out"))?
    .map_err(|e| anyhow::anyhow!("Read failed: {}", e))
}

/// Write data to TCP stream with timeout
pub async fn tcp_write(
    stream: &mut TcpStream,
    data: &[u8],
    timeout_secs: u64,
) -> Result<()> {
    timeout(
        Duration::from_secs(timeout_secs),
        stream.write_all(data),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Write timed out"))?
    .map_err(|e| anyhow::anyhow!("Write failed: {}", e))
}

/// Send and receive data over TCP
pub async fn tcp_exchange(
    addr: &str,
    send_data: &[u8],
    timeout_secs: u64,
) -> Result<Vec<u8>> {
    let mut stream = tcp_connect(addr, timeout_secs).await?;

    tcp_write(&mut stream, send_data, timeout_secs).await?;

    let mut buffer = vec![0u8; 4096];
    let n = tcp_read(&mut stream, &mut buffer, timeout_secs).await?;
    buffer.truncate(n);

    Ok(buffer)
}

/// Send and receive data over UDP
pub async fn udp_exchange(
    target_addr: &str,
    send_data: &[u8],
    timeout_secs: u64,
) -> Result<Vec<u8>> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;

    socket.send_to(send_data, target_addr).await?;

    let mut buffer = vec![0u8; 4096];
    let (n, _) = timeout(
        Duration::from_secs(timeout_secs),
        socket.recv_from(&mut buffer),
    )
    .await
    .map_err(|_| anyhow::anyhow!("UDP receive timed out"))??;

    buffer.truncate(n);
    Ok(buffer)
}

/// Extract HTTP headers from response
pub fn extract_http_headers(response: &str) -> std::collections::HashMap<String, String> {
    let mut headers = std::collections::HashMap::new();

    for line in response.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some(pos) = line.find(':') {
            let key = line[..pos].trim().to_lowercase();
            let value = line[pos + 1..].trim().to_string();
            headers.insert(key, value);
        }
    }

    headers
}

/// Check if a port is open
pub async fn is_port_open(addr: &str, timeout_secs: u64) -> bool {
    match tcp_connect(addr, timeout_secs).await {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Sanitize output for display (prevent injection attacks)
pub fn sanitize_output(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(1024) // Limit length
        .collect()
}

/// Parse version string from banner
pub fn parse_version(banner: &str, product: &str) -> Option<String> {
    // Try with / separator first (e.g., Apache/2.4.49)
    let pattern = format!(r"{}/([0-9]+\.[0-9]+[0-9.]*)", regex::escape(product));
    if let Ok(re) = regex::Regex::new(&pattern) {
        if let Some(caps) = re.captures(banner) {
            return caps.get(1).map(|m| m.as_str().to_string());
        }
    }

    // Try with whitespace separator (e.g., OpenSSH 7.4)
    let pattern = format!(r"{}\s+([0-9]+\.[0-9]+[0-9.]*)", regex::escape(product));
    if let Ok(re) = regex::Regex::new(&pattern) {
        if let Some(caps) = re.captures(banner) {
            return caps.get(1).map(|m| m.as_str().to_string());
        }
    }

    // Try with underscore separator (e.g., OpenSSH_7.4)
    let pattern = format!(r"{}_([0-9]+\.[0-9]+[0-9.]*)", regex::escape(product));
    if let Ok(re) = regex::Regex::new(&pattern) {
        if let Some(caps) = re.captures(banner) {
            return caps.get(1).map(|m| m.as_str().to_string());
        }
    }

    None
}

/// Compare version strings
pub fn version_compare(v1: &str, v2: &str) -> std::cmp::Ordering {
    let v1_parts: Vec<u32> = v1.split('.').filter_map(|s| s.parse().ok()).collect();
    let v2_parts: Vec<u32> = v2.split('.').filter_map(|s| s.parse().ok()).collect();

    for i in 0..std::cmp::max(v1_parts.len(), v2_parts.len()) {
        let p1 = v1_parts.get(i).unwrap_or(&0);
        let p2 = v2_parts.get(i).unwrap_or(&0);

        match p1.cmp(p2) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }

    std::cmp::Ordering::Equal
}

/// Check if version is vulnerable (less than threshold)
pub fn is_version_vulnerable(version: &str, threshold: &str) -> bool {
    matches!(version_compare(version, threshold), std::cmp::Ordering::Less)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_output() {
        let input = "Hello\x1b[31mWorld\x00";
        let output = sanitize_output(input);
        assert!(!output.contains('\x00'));
    }

    #[test]
    fn test_version_compare() {
        assert_eq!(version_compare("1.0.0", "1.0.0"), std::cmp::Ordering::Equal);
        assert_eq!(version_compare("1.0.0", "2.0.0"), std::cmp::Ordering::Less);
        assert_eq!(version_compare("2.0.0", "1.0.0"), std::cmp::Ordering::Greater);
        assert_eq!(version_compare("1.2.3", "1.2.4"), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_is_version_vulnerable() {
        assert!(is_version_vulnerable("1.0.0", "2.0.0"));
        assert!(!is_version_vulnerable("2.0.0", "1.0.0"));
        assert!(!is_version_vulnerable("1.0.0", "1.0.0"));
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
    }
}
