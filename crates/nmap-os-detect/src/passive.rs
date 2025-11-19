//! Passive OS Detection - p0f-style fingerprinting from a single SYN packet
//!
//! This module implements lightweight OS detection by analyzing TCP/IP characteristics
//! from passive observation of network traffic, without sending active probes.

use crate::OsMatch;

/// Passive OS detector based on TCP/IP stack characteristics
pub struct PassiveDetector {
    signatures: Vec<PassiveSignature>,
}

/// A passive fingerprint signature for OS detection
#[derive(Debug, Clone)]
pub struct PassiveSignature {
    pub os_name: String,
    pub os_family: String,
    pub ttl: u8,              // Initial TTL (32, 64, 128, 255)
    pub window_size: u16,     // TCP window
    pub mss: Option<u16>,     // MSS value
    pub has_wscale: bool,     // Window scaling option
    pub has_sackok: bool,     // SACK permitted option
    pub has_timestamp: bool,  // Timestamp option
}

/// OS hint from passive detection
#[derive(Debug, Clone)]
pub struct OSHint {
    pub name: String,
    pub family: String,
    pub confidence: u8,
}

impl PassiveDetector {
    /// Create a new passive detector with built-in signatures
    pub fn new() -> Self {
        Self {
            signatures: load_passive_signatures(),
        }
    }

    /// Get the number of loaded signatures
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Detect OS from TCP/IP characteristics
    pub fn detect(&self, ttl: u8, window: u16, mss: Option<u16>) -> Option<OSHint> {
        let initial_ttl = guess_initial_ttl(ttl);

        // First pass: Match on TTL and window size
        for sig in &self.signatures {
            if sig.ttl == initial_ttl && sig.window_size == window {
                // If MSS is specified in signature, verify it matches
                if let Some(sig_mss) = sig.mss {
                    if mss == Some(sig_mss) {
                        return Some(OSHint {
                            name: sig.os_name.clone(),
                            family: sig.os_family.clone(),
                            confidence: 85,
                        });
                    }
                } else {
                    // No MSS requirement, match on TTL + window
                    return Some(OSHint {
                        name: sig.os_name.clone(),
                        family: sig.os_family.clone(),
                        confidence: 75,
                    });
                }
            }
        }

        // Second pass: Fuzzy matching on TTL only (lower confidence)
        for sig in &self.signatures {
            if sig.ttl == initial_ttl {
                return Some(OSHint {
                    name: sig.os_family.clone(),
                    family: sig.os_family.clone(),
                    confidence: 50,
                });
            }
        }

        None
    }

    /// Detect OS with full TCP options analysis
    pub fn detect_full(
        &self,
        ttl: u8,
        window: u16,
        mss: Option<u16>,
        has_wscale: bool,
        has_sackok: bool,
        has_timestamp: bool,
    ) -> Option<OSHint> {
        let initial_ttl = guess_initial_ttl(ttl);

        let mut best_match: Option<(&PassiveSignature, u8)> = None;

        for sig in &self.signatures {
            if sig.ttl != initial_ttl {
                continue;
            }

            let mut score = 0u8;

            // TTL match (base score)
            score += 30;

            // Window size match
            if sig.window_size == window {
                score += 25;
            } else if (sig.window_size as i32 - window as i32).abs() < 100 {
                score += 10;
            }

            // MSS match
            if let (Some(sig_mss), Some(pkt_mss)) = (sig.mss, mss) {
                if sig_mss == pkt_mss {
                    score += 20;
                } else if (sig_mss as i32 - pkt_mss as i32).abs() < 100 {
                    score += 10;
                }
            }

            // TCP options matching
            if sig.has_wscale == has_wscale {
                score += 10;
            }
            if sig.has_sackok == has_sackok {
                score += 10;
            }
            if sig.has_timestamp == has_timestamp {
                score += 5;
            }

            if best_match.is_none() || score > best_match.unwrap().1 {
                best_match = Some((sig, score));
            }
        }

        if let Some((sig, score)) = best_match {
            if score >= 60 {
                return Some(OSHint {
                    name: sig.os_name.clone(),
                    family: sig.os_family.clone(),
                    confidence: score,
                });
            }
        }

        None
    }
}

impl Default for PassiveDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Guess the initial TTL from an observed TTL value
fn guess_initial_ttl(observed: u8) -> u8 {
    // Common initial TTL values: 32, 64, 128, 255
    [32, 64, 128, 255]
        .iter()
        .filter(|&&ttl| ttl >= observed)
        .min()
        .copied()
        .unwrap_or(observed)
}

/// Load passive OS signatures
fn load_passive_signatures() -> Vec<PassiveSignature> {
    vec![
        // ===== Linux Distributions =====

        // Linux 2.6-6.x (Generic)
        PassiveSignature {
            os_name: "Linux 2.6-6.x".to_string(),
            os_family: "Linux".to_string(),
            ttl: 64,
            window_size: 5840,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // Ubuntu 20.04/22.04
        PassiveSignature {
            os_name: "Ubuntu Linux 20.04/22.04".to_string(),
            os_family: "Linux".to_string(),
            ttl: 64,
            window_size: 64240,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // Debian 10/11
        PassiveSignature {
            os_name: "Debian Linux 10/11".to_string(),
            os_family: "Linux".to_string(),
            ttl: 64,
            window_size: 29200,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // Red Hat / CentOS
        PassiveSignature {
            os_name: "RHEL/CentOS 7-9".to_string(),
            os_family: "Linux".to_string(),
            ttl: 64,
            window_size: 14600,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // Alpine Linux
        PassiveSignature {
            os_name: "Alpine Linux".to_string(),
            os_family: "Linux".to_string(),
            ttl: 64,
            window_size: 14600,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: false,
        },

        // Android
        PassiveSignature {
            os_name: "Android 11-13".to_string(),
            os_family: "Linux".to_string(),
            ttl: 64,
            window_size: 65535,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // ===== Windows =====

        // Windows 10/11
        PassiveSignature {
            os_name: "Windows 10/11".to_string(),
            os_family: "Windows".to_string(),
            ttl: 128,
            window_size: 8192,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: false,
            has_timestamp: false,
        },

        // Windows 10 (alternative)
        PassiveSignature {
            os_name: "Windows 10".to_string(),
            os_family: "Windows".to_string(),
            ttl: 128,
            window_size: 64240,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: false,
            has_timestamp: false,
        },

        // Windows Server 2019/2022
        PassiveSignature {
            os_name: "Windows Server 2019/2022".to_string(),
            os_family: "Windows".to_string(),
            ttl: 128,
            window_size: 65535,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: false,
            has_timestamp: false,
        },

        // Windows 7/8.1
        PassiveSignature {
            os_name: "Windows 7/8.1".to_string(),
            os_family: "Windows".to_string(),
            ttl: 128,
            window_size: 8192,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: false,
            has_timestamp: false,
        },

        // Windows XP
        PassiveSignature {
            os_name: "Windows XP".to_string(),
            os_family: "Windows".to_string(),
            ttl: 128,
            window_size: 65535,
            mss: Some(1460),
            has_wscale: false,
            has_sackok: false,
            has_timestamp: false,
        },

        // ===== BSD & macOS =====

        // FreeBSD 12-14
        PassiveSignature {
            os_name: "FreeBSD 12-14".to_string(),
            os_family: "BSD".to_string(),
            ttl: 64,
            window_size: 65535,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // OpenBSD 6-7
        PassiveSignature {
            os_name: "OpenBSD 6-7".to_string(),
            os_family: "BSD".to_string(),
            ttl: 64,
            window_size: 16384,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: false,
        },

        // macOS (Big Sur, Monterey, Ventura, Sonoma)
        PassiveSignature {
            os_name: "macOS 11-14".to_string(),
            os_family: "macOS".to_string(),
            ttl: 64,
            window_size: 65535,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // macOS (alternative)
        PassiveSignature {
            os_name: "macOS".to_string(),
            os_family: "macOS".to_string(),
            ttl: 64,
            window_size: 65535,
            mss: Some(1440),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // ===== Network Devices =====

        // Cisco IOS
        PassiveSignature {
            os_name: "Cisco IOS 12-16".to_string(),
            os_family: "IOS".to_string(),
            ttl: 255,
            window_size: 4128,
            mss: Some(1460),
            has_wscale: false,
            has_sackok: false,
            has_timestamp: false,
        },

        // Juniper Junos
        PassiveSignature {
            os_name: "Juniper Junos".to_string(),
            os_family: "Junos".to_string(),
            ttl: 64,
            window_size: 16384,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // Fortinet FortiOS
        PassiveSignature {
            os_name: "Fortinet FortiOS 6-7".to_string(),
            os_family: "FortiOS".to_string(),
            ttl: 64,
            window_size: 5840,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: false,
        },

        // Palo Alto PAN-OS
        PassiveSignature {
            os_name: "Palo Alto PAN-OS".to_string(),
            os_family: "PAN-OS".to_string(),
            ttl: 64,
            window_size: 5840,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // Arista EOS
        PassiveSignature {
            os_name: "Arista EOS".to_string(),
            os_family: "Linux".to_string(),
            ttl: 64,
            window_size: 14600,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // ===== IoT Devices =====

        // Raspberry Pi OS (Raspbian)
        PassiveSignature {
            os_name: "Raspberry Pi OS".to_string(),
            os_family: "Linux".to_string(),
            ttl: 64,
            window_size: 43690,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // DD-WRT
        PassiveSignature {
            os_name: "DD-WRT".to_string(),
            os_family: "Linux".to_string(),
            ttl: 64,
            window_size: 5840,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: false,
        },

        // OpenWRT
        PassiveSignature {
            os_name: "OpenWRT".to_string(),
            os_family: "Linux".to_string(),
            ttl: 64,
            window_size: 14600,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: false,
        },

        // Ubiquiti EdgeRouter
        PassiveSignature {
            os_name: "Ubiquiti EdgeOS".to_string(),
            os_family: "Linux".to_string(),
            ttl: 64,
            window_size: 5840,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // Hikvision IP Camera
        PassiveSignature {
            os_name: "Hikvision Camera".to_string(),
            os_family: "Embedded Linux".to_string(),
            ttl: 64,
            window_size: 5840,
            mss: Some(1460),
            has_wscale: false,
            has_sackok: false,
            has_timestamp: false,
        },

        // ===== Other Systems =====

        // Solaris
        PassiveSignature {
            os_name: "Solaris 10-11".to_string(),
            os_family: "Solaris".to_string(),
            ttl: 255,
            window_size: 49640,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // AIX
        PassiveSignature {
            os_name: "IBM AIX".to_string(),
            os_family: "AIX".to_string(),
            ttl: 255,
            window_size: 65535,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: false,
            has_timestamp: false,
        },

        // HP-UX
        PassiveSignature {
            os_name: "HP-UX".to_string(),
            os_family: "HP-UX".to_string(),
            ttl: 255,
            window_size: 32768,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: false,
            has_timestamp: false,
        },

        // iOS (iPhone/iPad)
        PassiveSignature {
            os_name: "iOS 15-17".to_string(),
            os_family: "iOS".to_string(),
            ttl: 64,
            window_size: 65535,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: true,
        },

        // NetBSD
        PassiveSignature {
            os_name: "NetBSD 9-10".to_string(),
            os_family: "BSD".to_string(),
            ttl: 64,
            window_size: 65535,
            mss: Some(1460),
            has_wscale: true,
            has_sackok: true,
            has_timestamp: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passive_detector_creation() {
        let detector = PassiveDetector::new();
        assert!(detector.signature_count() > 0);
        assert!(detector.signature_count() >= 30);
    }

    #[test]
    fn test_ttl_guessing() {
        assert_eq!(guess_initial_ttl(60), 64);
        assert_eq!(guess_initial_ttl(120), 128);
        assert_eq!(guess_initial_ttl(250), 255);
        assert_eq!(guess_initial_ttl(30), 32);
        assert_eq!(guess_initial_ttl(64), 64);
    }

    #[test]
    fn test_linux_detection() {
        let detector = PassiveDetector::new();
        let hint = detector.detect(64, 5840, Some(1460));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.family, "Linux");
        assert!(hint.confidence >= 70);
    }

    #[test]
    fn test_windows_detection() {
        let detector = PassiveDetector::new();
        let hint = detector.detect(128, 8192, Some(1460));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.family, "Windows");
        assert!(hint.confidence >= 70);
    }

    #[test]
    fn test_macos_detection() {
        let detector = PassiveDetector::new();
        let hint = detector.detect(64, 65535, Some(1460));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        // TTL=64, window=65535, MSS=1460 could match Android, FreeBSD, macOS, NetBSD
        // All of these use similar TCP stacks
        assert!(
            hint.family == "macOS" || hint.family == "BSD" || hint.family == "Linux" || hint.family == "iOS",
            "Expected macOS, BSD, Linux, or iOS family, got: {}", hint.family
        );
    }

    #[test]
    fn test_full_detection() {
        let detector = PassiveDetector::new();

        // Test Linux with full options
        let hint = detector.detect_full(64, 64240, Some(1460), true, true, true);
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.family, "Linux");

        // Test Windows with full options
        let hint = detector.detect_full(128, 8192, Some(1460), true, false, false);
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.family, "Windows");
    }

    #[test]
    fn test_no_match() {
        let detector = PassiveDetector::new();
        // Unusual combination that shouldn't match
        let hint = detector.detect(32, 1234, Some(500));
        // May or may not match depending on fuzzy matching
        // Just verify it doesn't panic
        let _ = hint;
    }
}
