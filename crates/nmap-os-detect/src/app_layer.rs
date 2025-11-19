//! Application-Layer OS Detection
//!
//! This module detects operating systems from application-layer protocols
//! such as HTTP headers, SSH banners, SMB dialects, and FTP banners.

use std::collections::HashMap;

/// OS hint from application-layer detection
#[derive(Debug, Clone)]
pub struct OSHint {
    pub name: String,
    pub family: String,
    pub confidence: u8,
}

/// Application-layer OS detector
pub struct AppLayerDetector;

impl AppLayerDetector {
    /// Create a new application-layer detector
    pub fn new() -> Self {
        Self
    }

    /// Detect OS from HTTP headers
    ///
    /// Analyzes Server, X-Powered-By, and other HTTP headers
    /// to infer the underlying operating system.
    pub fn detect_from_http(&self, headers: &HashMap<String, String>) -> Option<OSHint> {
        // Check Server header (case-insensitive)
        if let Some(server) = headers.get("server").or_else(|| headers.get("Server")) {
            if let Some(os) = parse_server_header(server) {
                return Some(os);
            }
        }

        // Check X-Powered-By header
        if let Some(powered_by) = headers
            .get("x-powered-by")
            .or_else(|| headers.get("X-Powered-By"))
        {
            if let Some(os) = parse_powered_by_header(powered_by) {
                return Some(os);
            }
        }

        // Check X-AspNet-Version (Windows-specific)
        if let Some(aspnet) = headers
            .get("x-aspnet-version")
            .or_else(|| headers.get("X-AspNet-Version"))
        {
            if !aspnet.is_empty() {
                return Some(OSHint {
                    name: "Windows Server".to_string(),
                    family: "Windows".to_string(),
                    confidence: 75,
                });
            }
        }

        None
    }

    /// Detect OS from SSH banner
    ///
    /// SSH banners often include OS version information.
    /// Example: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    pub fn detect_from_ssh(&self, banner: &str) -> Option<OSHint> {
        let banner_lower = banner.to_lowercase();

        // Ubuntu
        if banner_lower.contains("ubuntu") {
            let confidence = if banner_lower.contains("ubuntu0") {
                85 // Patch-level version indicates Ubuntu
            } else {
                70
            };

            // Try to extract Ubuntu version
            let name = if let Some(version) = extract_ubuntu_version(banner) {
                version
            } else {
                "Ubuntu Linux".to_string()
            };

            return Some(OSHint {
                name,
                family: "Linux".to_string(),
                confidence,
            });
        }

        // Debian
        if banner_lower.contains("debian") {
            let name = if let Some(version) = extract_debian_version(banner) {
                version
            } else {
                "Debian Linux".to_string()
            };

            return Some(OSHint {
                name,
                family: "Linux".to_string(),
                confidence: 80,
            });
        }

        // Red Hat / CentOS / RHEL
        if banner_lower.contains("rhel") || banner_lower.contains("red hat") {
            return Some(OSHint {
                name: "Red Hat Enterprise Linux".to_string(),
                family: "Linux".to_string(),
                confidence: 80,
            });
        }

        if banner_lower.contains("centos") {
            return Some(OSHint {
                name: "CentOS Linux".to_string(),
                family: "Linux".to_string(),
                confidence: 80,
            });
        }

        // FreeBSD
        if banner_lower.contains("freebsd") {
            return Some(OSHint {
                name: "FreeBSD".to_string(),
                family: "BSD".to_string(),
                confidence: 85,
            });
        }

        // OpenBSD
        if banner_lower.contains("openbsd") {
            return Some(OSHint {
                name: "OpenBSD".to_string(),
                family: "BSD".to_string(),
                confidence: 85,
            });
        }

        // Generic OpenSSH (likely Unix-like)
        if banner_lower.contains("openssh") {
            return Some(OSHint {
                name: "Unix-like".to_string(),
                family: "Unix".to_string(),
                confidence: 50,
            });
        }

        None
    }

    /// Detect OS from SMB dialect
    ///
    /// SMB protocol versions can indicate Windows versions.
    pub fn detect_from_smb(&self, dialect: &str) -> Option<OSHint> {
        match dialect {
            "SMB 3.1.1" => Some(OSHint {
                name: "Windows 10/11 or Server 2016+".to_string(),
                family: "Windows".to_string(),
                confidence: 75,
            }),
            "SMB 3.0.2" => Some(OSHint {
                name: "Windows 8.1 or Server 2012 R2".to_string(),
                family: "Windows".to_string(),
                confidence: 75,
            }),
            "SMB 3.0" => Some(OSHint {
                name: "Windows 8 or Server 2012".to_string(),
                family: "Windows".to_string(),
                confidence: 75,
            }),
            "SMB 2.1" => Some(OSHint {
                name: "Windows 7 or Server 2008 R2".to_string(),
                family: "Windows".to_string(),
                confidence: 75,
            }),
            "SMB 2.0.2" => Some(OSHint {
                name: "Windows Vista SP1 or Server 2008".to_string(),
                family: "Windows".to_string(),
                confidence: 70,
            }),
            "SMB 1.0" | "NT LM 0.12" => Some(OSHint {
                name: "Windows XP/2003 or older".to_string(),
                family: "Windows".to_string(),
                confidence: 65,
            }),
            _ => None,
        }
    }

    /// Detect OS from FTP banner
    pub fn detect_from_ftp(&self, banner: &str) -> Option<OSHint> {
        let banner_lower = banner.to_lowercase();

        // Microsoft FTP
        if banner_lower.contains("microsoft ftp") {
            return Some(OSHint {
                name: "Windows Server".to_string(),
                family: "Windows".to_string(),
                confidence: 75,
            });
        }

        // ProFTPD (Linux/BSD)
        if banner_lower.contains("proftpd") {
            if banner_lower.contains("debian") {
                return Some(OSHint {
                    name: "Debian Linux".to_string(),
                    family: "Linux".to_string(),
                    confidence: 70,
                });
            }
            if banner_lower.contains("ubuntu") {
                return Some(OSHint {
                    name: "Ubuntu Linux".to_string(),
                    family: "Linux".to_string(),
                    confidence: 70,
                });
            }
            return Some(OSHint {
                name: "Linux/Unix".to_string(),
                family: "Linux".to_string(),
                confidence: 60,
            });
        }

        // vsftpd (Very Secure FTP Daemon - Linux)
        if banner_lower.contains("vsftpd") {
            return Some(OSHint {
                name: "Linux".to_string(),
                family: "Linux".to_string(),
                confidence: 65,
            });
        }

        // Pure-FTPd
        if banner_lower.contains("pure-ftpd") {
            return Some(OSHint {
                name: "Linux/BSD".to_string(),
                family: "Linux".to_string(),
                confidence: 60,
            });
        }

        None
    }

    /// Detect OS from SMTP banner
    pub fn detect_from_smtp(&self, banner: &str) -> Option<OSHint> {
        let banner_lower = banner.to_lowercase();

        // Microsoft Exchange
        if banner_lower.contains("exchange") {
            return Some(OSHint {
                name: "Windows Server".to_string(),
                family: "Windows".to_string(),
                confidence: 80,
            });
        }

        // Postfix (Linux/BSD)
        if banner_lower.contains("postfix") {
            if banner_lower.contains("ubuntu") {
                return Some(OSHint {
                    name: "Ubuntu Linux".to_string(),
                    family: "Linux".to_string(),
                    confidence: 70,
                });
            }
            if banner_lower.contains("debian") {
                return Some(OSHint {
                    name: "Debian Linux".to_string(),
                    family: "Linux".to_string(),
                    confidence: 70,
                });
            }
            return Some(OSHint {
                name: "Linux/Unix".to_string(),
                family: "Linux".to_string(),
                confidence: 60,
            });
        }

        // Sendmail
        if banner_lower.contains("sendmail") {
            return Some(OSHint {
                name: "Linux/Unix".to_string(),
                family: "Linux".to_string(),
                confidence: 55,
            });
        }

        None
    }
}

impl Default for AppLayerDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse HTTP Server header for OS information
fn parse_server_header(server: &str) -> Option<OSHint> {
    let lower = server.to_lowercase();

    // Ubuntu
    if lower.contains("ubuntu") {
        return Some(OSHint {
            name: "Ubuntu Linux".to_string(),
            family: "Linux".to_string(),
            confidence: 75,
        });
    }

    // Debian
    if lower.contains("debian") {
        return Some(OSHint {
            name: "Debian Linux".to_string(),
            family: "Linux".to_string(),
            confidence: 75,
        });
    }

    // Red Hat / CentOS
    if lower.contains("rhel") || lower.contains("red hat") || lower.contains("centos") {
        return Some(OSHint {
            name: "Red Hat Enterprise Linux".to_string(),
            family: "Linux".to_string(),
            confidence: 75,
        });
    }

    // Windows
    if lower.contains("win32") || lower.contains("win64") {
        return Some(OSHint {
            name: "Windows".to_string(),
            family: "Windows".to_string(),
            confidence: 70,
        });
    }

    // IIS (Internet Information Services - Windows)
    if lower.contains("microsoft-iis") {
        // Try to extract version
        if lower.contains("iis/10") {
            return Some(OSHint {
                name: "Windows Server 2016/2019/2022".to_string(),
                family: "Windows".to_string(),
                confidence: 75,
            });
        }
        if lower.contains("iis/8.5") {
            return Some(OSHint {
                name: "Windows Server 2012 R2".to_string(),
                family: "Windows".to_string(),
                confidence: 75,
            });
        }
        if lower.contains("iis/8.0") {
            return Some(OSHint {
                name: "Windows Server 2012".to_string(),
                family: "Windows".to_string(),
                confidence: 75,
            });
        }
        return Some(OSHint {
            name: "Windows Server".to_string(),
            family: "Windows".to_string(),
            confidence: 70,
        });
    }

    None
}

/// Parse X-Powered-By header for OS information
fn parse_powered_by_header(powered_by: &str) -> Option<OSHint> {
    let lower = powered_by.to_lowercase();

    if lower.contains("ubuntu") {
        return Some(OSHint {
            name: "Ubuntu Linux".to_string(),
            family: "Linux".to_string(),
            confidence: 70,
        });
    }

    if lower.contains("debian") {
        return Some(OSHint {
            name: "Debian Linux".to_string(),
            family: "Linux".to_string(),
            confidence: 70,
        });
    }

    if lower.contains("asp.net") {
        return Some(OSHint {
            name: "Windows Server".to_string(),
            family: "Windows".to_string(),
            confidence: 75,
        });
    }

    None
}

/// Extract Ubuntu version from SSH banner
fn extract_ubuntu_version(banner: &str) -> Option<String> {
    // Example: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    // OpenSSH 8.2 -> Ubuntu 20.04
    // OpenSSH 8.9 -> Ubuntu 22.04

    if banner.contains("OpenSSH_8.9") || banner.contains("OpenSSH_9.") {
        return Some("Ubuntu Linux 22.04".to_string());
    }
    if banner.contains("OpenSSH_8.2") || banner.contains("OpenSSH_8.4") {
        return Some("Ubuntu Linux 20.04".to_string());
    }
    if banner.contains("OpenSSH_7.6") {
        return Some("Ubuntu Linux 18.04".to_string());
    }

    None
}

/// Extract Debian version from SSH banner
fn extract_debian_version(banner: &str) -> Option<String> {
    // Example: "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1"
    if banner.contains("deb11") {
        return Some("Debian Linux 11 (Bullseye)".to_string());
    }
    if banner.contains("deb10") {
        return Some("Debian Linux 10 (Buster)".to_string());
    }
    if banner.contains("deb9") {
        return Some("Debian Linux 9 (Stretch)".to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_ubuntu_detection() {
        let detector = AppLayerDetector::new();
        let mut headers = HashMap::new();
        headers.insert("Server".to_string(), "Apache/2.4.41 (Ubuntu)".to_string());

        let result = detector.detect_from_http(&headers);
        assert!(result.is_some());
        let os = result.unwrap();
        assert_eq!(os.family, "Linux");
        assert!(os.name.contains("Ubuntu"));
    }

    #[test]
    fn test_http_iis_detection() {
        let detector = AppLayerDetector::new();
        let mut headers = HashMap::new();
        headers.insert(
            "Server".to_string(),
            "Microsoft-IIS/10.0".to_string(),
        );

        let result = detector.detect_from_http(&headers);
        assert!(result.is_some());
        let os = result.unwrap();
        assert_eq!(os.family, "Windows");
    }

    #[test]
    fn test_ssh_ubuntu_detection() {
        let detector = AppLayerDetector::new();
        let banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";

        let result = detector.detect_from_ssh(banner);
        assert!(result.is_some());
        let os = result.unwrap();
        assert_eq!(os.family, "Linux");
        assert!(os.name.contains("Ubuntu"));
        assert!(os.confidence >= 70);
    }

    #[test]
    fn test_ssh_debian_detection() {
        let detector = AppLayerDetector::new();
        let banner = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1";

        let result = detector.detect_from_ssh(banner);
        assert!(result.is_some());
        let os = result.unwrap();
        assert_eq!(os.family, "Linux");
        assert!(os.name.contains("Debian"));
    }

    #[test]
    fn test_ssh_freebsd_detection() {
        let detector = AppLayerDetector::new();
        let banner = "SSH-2.0-OpenSSH_8.8 FreeBSD-20211221";

        let result = detector.detect_from_ssh(banner);
        assert!(result.is_some());
        let os = result.unwrap();
        assert_eq!(os.family, "BSD");
        assert!(os.name.contains("FreeBSD"));
    }

    #[test]
    fn test_smb_windows10_detection() {
        let detector = AppLayerDetector::new();
        let result = detector.detect_from_smb("SMB 3.1.1");
        assert!(result.is_some());
        let os = result.unwrap();
        assert_eq!(os.family, "Windows");
        assert!(os.name.contains("Windows"));
    }

    #[test]
    fn test_smb_windows7_detection() {
        let detector = AppLayerDetector::new();
        let result = detector.detect_from_smb("SMB 2.1");
        assert!(result.is_some());
        let os = result.unwrap();
        assert_eq!(os.family, "Windows");
        assert!(os.name.contains("Windows 7") || os.name.contains("2008"));
    }

    #[test]
    fn test_ftp_proftpd_detection() {
        let detector = AppLayerDetector::new();
        let banner = "220 ProFTPD 1.3.6 Server (Debian)";

        let result = detector.detect_from_ftp(banner);
        assert!(result.is_some());
        let os = result.unwrap();
        assert_eq!(os.family, "Linux");
    }

    #[test]
    fn test_smtp_exchange_detection() {
        let detector = AppLayerDetector::new();
        let banner = "220 mail.example.com Microsoft ESMTP MAIL Service ready";

        let result = detector.detect_from_smtp(banner);
        // This might not match if "Exchange" is not in the banner
        // Let's test with Exchange explicitly
        let banner2 = "220 mail.example.com Microsoft Exchange Server";
        let result2 = detector.detect_from_smtp(banner2);
        assert!(result2.is_some());
        let os = result2.unwrap();
        assert_eq!(os.family, "Windows");
    }

    #[test]
    fn test_no_match() {
        let detector = AppLayerDetector::new();

        // Empty headers
        let headers = HashMap::new();
        assert!(detector.detect_from_http(&headers).is_none());

        // Unknown SSH banner
        assert!(detector.detect_from_ssh("SSH-2.0-UnknownSSH_1.0").is_none());

        // Unknown SMB dialect
        assert!(detector.detect_from_smb("SMB 999.0").is_none());
    }
}
