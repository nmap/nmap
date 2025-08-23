use crate::ServiceInfo;
use nmap_core::{NmapError, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSignature {
    pub service_name: String,
    pub probe_name: String,
    pub pattern: String,
    pub version_info: Option<VersionInfo>,
    pub ports: Vec<u16>,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub product: Option<String>,
    pub version: Option<String>,
    pub info: Option<String>,
    pub hostname: Option<String>,
    pub os_type: Option<String>,
    pub device_type: Option<String>,
    pub cpe: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SignatureDatabase {
    signatures: Vec<ServiceSignature>,
    compiled_patterns: HashMap<usize, Regex>,
    service_index: HashMap<String, Vec<usize>>,
    probe_index: HashMap<String, Vec<usize>>,
}

impl SignatureDatabase {
    pub fn load_default() -> Result<Self> {
        // In a real implementation, this would load from nmap-service-probes
        // For now, we'll create signatures for common services
        let signatures = vec![
            // HTTP signatures
            ServiceSignature {
                service_name: "http".to_string(),
                probe_name: "GetRequest".to_string(),
                pattern: r"HTTP/1\.[01] \d+ ".to_string(),
                version_info: Some(VersionInfo {
                    product: Some("HTTP server".to_string()),
                    version: None,
                    info: None,
                    hostname: None,
                    os_type: None,
                    device_type: None,
                    cpe: vec!["cpe:/a:http:http_server".to_string()],
                }),
                ports: vec![80, 8080, 8000, 8008],
                protocol: "tcp".to_string(),
            },
            
            // Apache HTTP Server
            ServiceSignature {
                service_name: "http".to_string(),
                probe_name: "GetRequest".to_string(),
                pattern: r"Server: Apache/([0-9.]+)".to_string(),
                version_info: Some(VersionInfo {
                    product: Some("Apache httpd".to_string()),
                    version: Some("$1".to_string()),
                    info: None,
                    hostname: None,
                    os_type: None,
                    device_type: None,
                    cpe: vec!["cpe:/a:apache:http_server:$1".to_string()],
                }),
                ports: vec![80, 8080, 443],
                protocol: "tcp".to_string(),
            },
            
            // Nginx
            ServiceSignature {
                service_name: "http".to_string(),
                probe_name: "GetRequest".to_string(),
                pattern: r"Server: nginx/([0-9.]+)".to_string(),
                version_info: Some(VersionInfo {
                    product: Some("nginx".to_string()),
                    version: Some("$1".to_string()),
                    info: None,
                    hostname: None,
                    os_type: None,
                    device_type: None,
                    cpe: vec!["cpe:/a:nginx:nginx:$1".to_string()],
                }),
                ports: vec![80, 8080, 443],
                protocol: "tcp".to_string(),
            },
            
            // SSH signatures
            ServiceSignature {
                service_name: "ssh".to_string(),
                probe_name: "NULL".to_string(),
                pattern: r"SSH-([0-9.]+)-(.+)".to_string(),
                version_info: Some(VersionInfo {
                    product: Some("$2".to_string()),
                    version: Some("protocol $1".to_string()),
                    info: None,
                    hostname: None,
                    os_type: None,
                    device_type: None,
                    cpe: vec!["cpe:/a:ssh:ssh:$1".to_string()],
                }),
                ports: vec![22],
                protocol: "tcp".to_string(),
            },
            
            // OpenSSH
            ServiceSignature {
                service_name: "ssh".to_string(),
                probe_name: "NULL".to_string(),
                pattern: r"SSH-2\.0-OpenSSH_([0-9.]+)".to_string(),
                version_info: Some(VersionInfo {
                    product: Some("OpenSSH".to_string()),
                    version: Some("$1".to_string()),
                    info: None,
                    hostname: None,
                    os_type: None,
                    device_type: None,
                    cpe: vec!["cpe:/a:openbsd:openssh:$1".to_string()],
                }),
                ports: vec![22],
                protocol: "tcp".to_string(),
            },
            
            // FTP signatures
            ServiceSignature {
                service_name: "ftp".to_string(),
                probe_name: "NULL".to_string(),
                pattern: r"220.*FTP".to_string(),
                version_info: Some(VersionInfo {
                    product: Some("FTP server".to_string()),
                    version: None,
                    info: None,
                    hostname: None,
                    os_type: None,
                    device_type: None,
                    cpe: vec!["cpe:/a:ftp:ftp_server".to_string()],
                }),
                ports: vec![21],
                protocol: "tcp".to_string(),
            },
            
            // vsftpd
            ServiceSignature {
                service_name: "ftp".to_string(),
                probe_name: "NULL".to_string(),
                pattern: r"220.*vsftpd ([0-9.]+)".to_string(),
                version_info: Some(VersionInfo {
                    product: Some("vsftpd".to_string()),
                    version: Some("$1".to_string()),
                    info: None,
                    hostname: None,
                    os_type: None,
                    device_type: None,
                    cpe: vec!["cpe:/a:vsftpd:vsftpd:$1".to_string()],
                }),
                ports: vec![21],
                protocol: "tcp".to_string(),
            },
            
            // SMTP signatures
            ServiceSignature {
                service_name: "smtp".to_string(),
                probe_name: "NULL".to_string(),
                pattern: r"220.*SMTP".to_string(),
                version_info: Some(VersionInfo {
                    product: Some("SMTP server".to_string()),
                    version: None,
                    info: None,
                    hostname: None,
                    os_type: None,
                    device_type: None,
                    cpe: vec!["cpe:/a:smtp:smtp_server".to_string()],
                }),
                ports: vec![25, 587],
                protocol: "tcp".to_string(),
            },
            
            // Postfix
            ServiceSignature {
                service_name: "smtp".to_string(),
                probe_name: "SMTP".to_string(),
                pattern: r"220.*Postfix".to_string(),
                version_info: Some(VersionInfo {
                    product: Some("Postfix smtpd".to_string()),
                    version: None,
                    info: None,
                    hostname: None,
                    os_type: None,
                    device_type: None,
                    cpe: vec!["cpe:/a:postfix:postfix".to_string()],
                }),
                ports: vec![25, 587],
                protocol: "tcp".to_string(),
            },
            
            // Telnet
            ServiceSignature {
                service_name: "telnet".to_string(),
                probe_name: "NULL".to_string(),
                pattern: r".*login:.*".to_string(),
                version_info: Some(VersionInfo {
                    product: Some("Telnet server".to_string()),
                    version: None,
                    info: None,
                    hostname: None,
                    os_type: None,
                    device_type: None,
                    cpe: vec!["cpe:/a:telnet:telnet_server".to_string()],
                }),
                ports: vec![23],
                protocol: "tcp".to_string(),
            },
        ];

        let mut compiled_patterns = HashMap::new();
        let mut service_index = HashMap::new();
        let mut probe_index = HashMap::new();

        for (i, sig) in signatures.iter().enumerate() {
            // Compile regex pattern
            if let Ok(regex) = Regex::new(&sig.pattern) {
                compiled_patterns.insert(i, regex);
            }

            // Build service index
            service_index.entry(sig.service_name.clone())
                .or_insert_with(Vec::new)
                .push(i);

            // Build probe index
            probe_index.entry(sig.probe_name.clone())
                .or_insert_with(Vec::new)
                .push(i);
        }

        Ok(Self {
            signatures,
            compiled_patterns,
            service_index,
            probe_index,
        })
    }

    pub fn match_banner(&self, banner: &str, port: u16, protocol: &str) -> Result<ServiceInfo> {
        // Try to match banner against all signatures
        for (i, signature) in self.signatures.iter().enumerate() {
            if signature.protocol != protocol {
                continue;
            }

            if !signature.ports.is_empty() && !signature.ports.contains(&port) {
                continue;
            }

            if let Some(regex) = self.compiled_patterns.get(&i) {
                if let Some(captures) = regex.captures(banner) {
                    return Ok(self.build_service_info(signature, &captures));
                }
            }
        }

        Err(NmapError::ServiceNotDetected)
    }

    pub fn match_probe_response(
        &self,
        response: &str,
        probe_name: &str,
        port: u16,
        protocol: &str,
    ) -> Result<ServiceInfo> {
        // Get signatures for this probe
        if let Some(indices) = self.probe_index.get(probe_name) {
            for &i in indices {
                let signature = &self.signatures[i];
                
                if signature.protocol != protocol {
                    continue;
                }

                if !signature.ports.is_empty() && !signature.ports.contains(&port) {
                    continue;
                }

                if let Some(regex) = self.compiled_patterns.get(&i) {
                    if let Some(captures) = regex.captures(response) {
                        return Ok(self.build_service_info(signature, &captures));
                    }
                }
            }
        }

        Err(NmapError::ServiceNotDetected)
    }

    fn build_service_info(&self, signature: &ServiceSignature, captures: &regex::Captures) -> ServiceInfo {
        let mut service = ServiceInfo {
            name: signature.service_name.clone(),
            product: None,
            version: None,
            extra_info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: Vec::new(),
            confidence: 95, // High confidence for regex matches
        };

        if let Some(ref version_info) = signature.version_info {
            service.product = version_info.product.as_ref().map(|p| self.substitute_captures(p, captures));
            service.version = version_info.version.as_ref().map(|v| self.substitute_captures(v, captures));
            service.extra_info = version_info.info.as_ref().map(|i| self.substitute_captures(i, captures));
            service.hostname = version_info.hostname.as_ref().map(|h| self.substitute_captures(h, captures));
            service.os_type = version_info.os_type.clone();
            service.device_type = version_info.device_type.clone();
            
            service.cpe = version_info.cpe.iter()
                .map(|cpe| self.substitute_captures(cpe, captures))
                .collect();
        }

        service
    }

    fn substitute_captures(&self, template: &str, captures: &regex::Captures) -> String {
        let mut result = template.to_string();
        
        // Replace $1, $2, etc. with capture groups
        for i in 1..captures.len() {
            if let Some(capture) = captures.get(i) {
                let placeholder = format!("${}", i);
                result = result.replace(&placeholder, capture.as_str());
            }
        }
        
        result
    }

    pub fn get_signatures_for_service(&self, service_name: &str) -> Vec<&ServiceSignature> {
        if let Some(indices) = self.service_index.get(service_name) {
            indices.iter().map(|&i| &self.signatures[i]).collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_signatures_for_probe(&self, probe_name: &str) -> Vec<&ServiceSignature> {
        if let Some(indices) = self.probe_index.get(probe_name) {
            indices.iter().map(|&i| &self.signatures[i]).collect()
        } else {
            Vec::new()
        }
    }
}

impl Clone for SignatureDatabase {
    fn clone(&self) -> Self {
        // Note: Regex doesn't implement Clone, so we need to recompile
        let mut compiled_patterns = HashMap::new();
        for (i, signature) in self.signatures.iter().enumerate() {
            if let Ok(regex) = Regex::new(&signature.pattern) {
                compiled_patterns.insert(i, regex);
            }
        }

        Self {
            signatures: self.signatures.clone(),
            compiled_patterns,
            service_index: self.service_index.clone(),
            probe_index: self.probe_index.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_database_creation() {
        let db = SignatureDatabase::load_default().unwrap();
        assert!(!db.signatures.is_empty());
        assert!(!db.compiled_patterns.is_empty());
    }

    #[test]
    fn test_match_banner() {
        let db = SignatureDatabase::load_default().unwrap();
        
        // Test Apache banner
        let apache_banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n";
        let result = db.match_banner(apache_banner, 80, "tcp");
        assert!(result.is_ok());
        
        let service = result.unwrap();
        assert_eq!(service.name, "http");
        assert_eq!(service.product, Some("Apache httpd".to_string()));
        assert_eq!(service.version, Some("2.4.41".to_string()));
    }

    #[test]
    fn test_match_ssh_banner() {
        let db = SignatureDatabase::load_default().unwrap();
        
        let ssh_banner = "SSH-2.0-OpenSSH_8.2p1";
        let result = db.match_banner(ssh_banner, 22, "tcp");
        assert!(result.is_ok());
        
        let service = result.unwrap();
        assert_eq!(service.name, "ssh");
        assert_eq!(service.product, Some("OpenSSH".to_string()));
        assert_eq!(service.version, Some("8.2p1".to_string()));
    }

    #[test]
    fn test_no_match() {
        let db = SignatureDatabase::load_default().unwrap();
        
        let unknown_banner = "UNKNOWN PROTOCOL";
        let result = db.match_banner(unknown_banner, 12345, "tcp");
        assert!(result.is_err());
    }
}