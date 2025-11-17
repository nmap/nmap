use nmap_core::{NmapError, Result};
use nmap_net::Host;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use tokio::time::{timeout, Duration};

pub mod probes;
pub mod signatures;
pub mod version_detect;

pub use probes::*;
pub use signatures::*;
pub use version_detect::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    pub hostname: Option<String>,
    pub os_type: Option<String>,
    pub device_type: Option<String>,
    pub cpe: Vec<String>,
    pub confidence: u8,
}

#[derive(Debug, Clone)]
pub struct ServiceDetectionResult {
    pub target: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<ServiceInfo>,
    pub banner: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ServiceDetectionOptions {
    pub version_intensity: u8,
    pub version_light: bool,
    pub version_all: bool,
    pub version_trace: bool,
    pub rpc_scan: bool,
    pub timeout: Duration,
}

impl Default for ServiceDetectionOptions {
    fn default() -> Self {
        Self {
            version_intensity: 7,
            version_light: false,
            version_all: false,
            version_trace: false,
            rpc_scan: false,
            timeout: Duration::from_secs(5),
        }
    }
}

pub struct ServiceDetector {
    probe_db: ProbeDatabase,
    signature_db: SignatureDatabase,
    options: ServiceDetectionOptions,
}

impl ServiceDetector {
    pub fn new() -> Result<Self> {
        Ok(Self {
            probe_db: ProbeDatabase::load_default()?,
            signature_db: SignatureDatabase::load_default()?,
            options: ServiceDetectionOptions::default(),
        })
    }

    pub fn with_options(mut self, options: ServiceDetectionOptions) -> Self {
        self.options = options;
        self
    }

    pub async fn detect_service(
        &self,
        target: &Host,
        port: u16,
        protocol: &str,
    ) -> Result<ServiceDetectionResult> {
        let ip = target.address;
        
        // Start with basic service detection
        let mut result = ServiceDetectionResult {
            target: ip,
            port,
            protocol: protocol.to_string(),
            state: "unknown".to_string(),
            service: None,
            banner: None,
            fingerprint: None,
        };

        // Check if port is open first
        if !self.is_port_open(ip, port, protocol).await? {
            result.state = "closed".to_string();
            return Ok(result);
        }

        result.state = "open".to_string();

        // Try to grab banner
        if let Ok(banner) = self.grab_banner(ip, port, protocol).await {
            result.banner = Some(banner.clone());
            
            // Try to identify service from banner
            if let Ok(service) = self.signature_db.match_banner(&banner, port, protocol) {
                result.service = Some(service);
                return Ok(result);
            }
        }

        // If banner matching failed, try probes
        if let Ok(service) = self.run_probes(ip, port, protocol).await {
            result.service = Some(service.0);
            result.fingerprint = service.1;
        }

        Ok(result)
    }

    pub async fn detect_services_batch(
        &self,
        target: &Host,
        ports: &[(u16, String)],
    ) -> Result<Vec<ServiceDetectionResult>> {
        let mut results = Vec::new();
        let mut handles = Vec::new();

        // Launch concurrent service detection for all ports
        for (port, protocol) in ports {
            let detector = self.clone();
            let target = target.clone();
            let port = *port;
            let protocol = protocol.clone();

            let handle = tokio::spawn(async move {
                detector.detect_service(&target, port, &protocol).await
            });
            handles.push(handle);
        }

        // Collect results
        for handle in handles {
            match handle.await {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(e)) => log::warn!("Service detection failed: {:?}", e),
                Err(e) => log::warn!("Task failed: {:?}", e),
            }
        }

        Ok(results)
    }

    async fn is_port_open(&self, ip: IpAddr, port: u16, protocol: &str) -> Result<bool> {
        match protocol {
            "tcp" => {
                let addr = SocketAddr::new(ip, port);
                match timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(addr)).await {
                    Ok(Ok(_)) => Ok(true),
                    _ => Ok(false),
                }
            }
            "udp" => {
                // UDP port checking is more complex
                // For now, assume it's open if we can bind to it
                Ok(true)
            }
            _ => Err(NmapError::Other("Unsupported protocol".to_string())),
        }
    }

    async fn grab_banner(&self, ip: IpAddr, port: u16, protocol: &str) -> Result<String> {
        match protocol {
            "tcp" => self.grab_tcp_banner(ip, port).await,
            "udp" => self.grab_udp_banner(ip, port).await,
            _ => Err(NmapError::Other("Unsupported protocol".to_string())),
        }
    }

    async fn grab_tcp_banner(&self, ip: IpAddr, port: u16) -> Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        let addr = SocketAddr::new(ip, port);
        let mut stream = timeout(
            self.options.timeout,
            tokio::net::TcpStream::connect(addr)
        ).await.map_err(|_| NmapError::Timeout("Connection timeout".to_string()))??;

        // Send a simple probe
        let probe: &[u8] = match port {
            21 => b"", // FTP - just connect
            22 => b"", // SSH - just connect
            25 => b"EHLO nmap\r\n", // SMTP
            53 => b"", // DNS - would need special handling
            80 => b"GET / HTTP/1.0\r\n\r\n", // HTTP
            110 => b"", // POP3 - just connect
            143 => b"", // IMAP - just connect
            443 => b"", // HTTPS - would need TLS
            993 => b"", // IMAPS - would need TLS
            995 => b"", // POP3S - would need TLS
            _ => b"", // Generic - just connect
        };

        if !probe.is_empty() {
            stream.write_all(probe).await.map_err(|_| NmapError::Network("Send failed".to_string()))?;
        }

        // Read response
        let mut buffer = vec![0u8; 1024];
        let n = timeout(
            Duration::from_secs(2),
            stream.read(&mut buffer)
        ).await.map_err(|_| NmapError::Timeout("Read timeout".to_string()))?.map_err(|_| NmapError::Network("Receive failed".to_string()))?;

        if n > 0 {
            buffer.truncate(n);
            Ok(String::from_utf8_lossy(&buffer).to_string())
        } else {
            Err(NmapError::Network("No banner received".to_string()))
        }
    }

    async fn grab_udp_banner(&self, _ip: IpAddr, _port: u16) -> Result<String> {
        // UDP banner grabbing is more complex and service-specific
        // For now, return an error
        Err(NmapError::Other("UDP banner grabbing not yet supported".to_string()))
    }

    async fn run_probes(&self, ip: IpAddr, port: u16, protocol: &str) -> Result<(ServiceInfo, Option<String>)> {
        let probes = self.probe_db.get_probes_for_port(port, protocol);

        for probe in probes {
            if let Ok(response) = self.send_probe(ip, port, protocol, &probe).await {
                if let Ok(service) = self.signature_db.match_probe_response(&response, &probe.name, port, protocol) {
                    return Ok((service, Some(response)));
                }
            }
        }

        Err(NmapError::Other("Service not detected".to_string()))
    }

    async fn send_probe(&self, ip: IpAddr, port: u16, protocol: &str, probe: &Probe) -> Result<String> {
        match protocol {
            "tcp" => self.send_tcp_probe(ip, port, probe).await,
            "udp" => self.send_udp_probe(ip, port, probe).await,
            _ => Err(NmapError::Other("Unsupported protocol".to_string())),
        }
    }

    async fn send_tcp_probe(&self, ip: IpAddr, port: u16, probe: &Probe) -> Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let addr = SocketAddr::new(ip, port);
        let mut stream = timeout(
            self.options.timeout,
            tokio::net::TcpStream::connect(addr)
        ).await.map_err(|_| NmapError::Timeout("Connection timeout".to_string()))??;

        // Send probe data
        stream.write_all(&probe.data).await.map_err(|_| NmapError::Network("Send failed".to_string()))?;

        // Read response
        let mut buffer = vec![0u8; 4096];
        let n = timeout(
            Duration::from_secs(2),
            stream.read(&mut buffer)
        ).await.map_err(|_| NmapError::Timeout("Read timeout".to_string()))?.map_err(|_| NmapError::Network("Receive failed".to_string()))?;

        if n > 0 {
            buffer.truncate(n);
            Ok(String::from_utf8_lossy(&buffer).to_string())
        } else {
            Err(NmapError::Network("No response".to_string()))
        }
    }

    async fn send_udp_probe(&self, _ip: IpAddr, _port: u16, _probe: &Probe) -> Result<String> {
        // UDP probe implementation would go here
        Err(NmapError::Other("UDP probes not yet supported".to_string()))
    }
}

impl Clone for ServiceDetector {
    fn clone(&self) -> Self {
        Self {
            probe_db: self.probe_db.clone(),
            signature_db: self.signature_db.clone(),
            options: self.options.clone(),
        }
    }
}

impl Default for ServiceDetector {
    fn default() -> Self {
        Self::new().expect("Failed to create default service detector")
    }
}