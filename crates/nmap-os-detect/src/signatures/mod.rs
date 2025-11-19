// OS Fingerprint Signature Database
//
// This module contains OS signatures for matching against fingerprints
// collected from active and passive detection methods.

use serde::{Deserialize, Serialize};

// Import from parent modules
use super::{OSTests, OsMatch};
pub use super::OsMatch as OSMatch;

// Submodules containing signatures
pub mod linux;
pub mod windows;
pub mod network;
pub mod bsd;
pub mod iot;
pub mod mobile;

/// OS Signature for pattern matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSSignature {
    /// OS name (e.g., "Ubuntu Linux 20.04")
    pub name: String,
    /// OS family (e.g., "Linux")
    pub family: String,
    /// Vendor (e.g., "Canonical")
    pub vendor: String,
    /// Device type (e.g., "general purpose", "router", "firewall")
    pub device_type: String,
    /// CPE (Common Platform Enumeration) identifiers
    pub cpe: Vec<String>,
    /// Minimum confidence threshold (0-100)
    pub confidence_threshold: u8,

    // Pattern matching criteria
    pub seq_patterns: Option<SeqPattern>,
    pub tcp_patterns: Option<TcpPattern>,
    pub icmp_patterns: Option<IcmpPattern>,
    pub ip_id_patterns: Option<IpIdPattern>,
}

/// Sequence number generation patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeqPattern {
    /// Sequence predictability (min)
    pub sp_min: u32,
    /// Sequence predictability (max)
    pub sp_max: u32,
    /// GCD (greatest common divisor) min
    pub gcd_min: u32,
    /// GCD max
    pub gcd_max: u32,
    /// ISR (initial sequence rate) min
    pub isr_min: u32,
    /// ISR max
    pub isr_max: u32,
    /// Timestamp generation patterns
    pub ts_pattern: Option<String>,
}

/// TCP behavior patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpPattern {
    /// Expected TCP window sizes
    pub window_sizes: Vec<u16>,
    /// Expected TCP flags combinations
    pub flags: Vec<u8>,
    /// Expected TCP options
    pub options: Vec<String>,
    /// TCP quirks (unusual behaviors)
    pub quirks: Vec<String>,
}

/// ICMP behavior patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpPattern {
    /// TTL values
    pub ttl_values: Vec<u8>,
    /// DF (Don't Fragment) bit usage
    pub df_bit: Option<bool>,
    /// ICMP code patterns
    pub codes: Vec<u8>,
}

/// IP ID sequence patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpIdPattern {
    /// Sequence type (I, RI, Z, BI, R, RPI)
    pub sequence_type: String,
    /// Expected increments
    pub increment_range: Option<(u16, u16)>,
}

/// Signature database for OS matching
pub struct SignatureDatabase {
    signatures: Vec<OSSignature>,
}

impl SignatureDatabase {
    /// Create a new signature database with all built-in signatures
    pub fn new() -> Self {
        let mut signatures = Vec::new();

        // Load signatures from all modules
        signatures.extend(linux::get_signatures());
        signatures.extend(windows::get_signatures());
        signatures.extend(network::get_signatures());
        signatures.extend(bsd::get_signatures());
        signatures.extend(iot::get_signatures());
        signatures.extend(mobile::get_signatures());

        Self { signatures }
    }

    /// Match a fingerprint against the signature database
    pub fn match_fingerprint(&self, tests: &OSTests) -> Vec<OSMatch> {
        let mut matches = Vec::new();

        for sig in &self.signatures {
            let score = self.calculate_match_score(tests, sig);
            if score >= sig.confidence_threshold {
                matches.push(OsMatch {
                    name: sig.name.clone(),
                    accuracy: score,
                    line: String::new(),
                    os_class: vec![],
                    cpe: sig.cpe.clone(),
                    family: Some(sig.family.clone()),
                    vendor: Some(sig.vendor.clone()),
                    device_type: Some(sig.device_type.clone()),
                });
            }
        }

        // Sort by confidence (descending)
        matches.sort_by_key(|m| std::cmp::Reverse(m.accuracy));

        // Return top 3 matches
        matches.truncate(3);
        matches
    }

    /// Calculate match score between fingerprint and signature
    fn calculate_match_score(&self, tests: &OSTests, sig: &OSSignature) -> u8 {
        let mut total_weight = 0u32;
        let mut matched_weight = 0u32;

        // Check sequence patterns (weight: 30)
        if let (Some(seq), Some(pattern)) = (&tests.seq, &sig.seq_patterns) {
            total_weight += 30;
            if self.match_seq_pattern(seq, pattern) {
                matched_weight += 30;
            }
        }

        // Check TCP patterns (weight: 25)
        if let Some(pattern) = &sig.tcp_patterns {
            total_weight += 25;
            let tcp_score = self.match_tcp_pattern(tests, pattern);
            matched_weight += (tcp_score as u32 * 25) / 100;
        }

        // Check ICMP patterns (weight: 20)
        if let (Some(_icmp), Some(pattern)) = (&tests.ie, &sig.icmp_patterns) {
            total_weight += 20;
            // Simplified matching for now
            matched_weight += 10;
        }

        // Check IP ID patterns (weight: 15)
        if let Some(pattern) = &sig.ip_id_patterns {
            total_weight += 15;
            // Simplified matching for now
            matched_weight += 8;
        }

        // General behavior patterns (weight: 10)
        total_weight += 10;
        matched_weight += 5;

        if total_weight == 0 {
            return 0;
        }

        // Calculate percentage
        ((matched_weight * 100) / total_weight) as u8
    }

    /// Match sequence number generation pattern
    fn match_seq_pattern(&self, seq: &crate::SeqTest, pattern: &SeqPattern) -> bool {
        // Check if sequence predictability is in range
        if seq.sp < pattern.sp_min || seq.sp > pattern.sp_max {
            return false;
        }

        // Check GCD
        if seq.gcd < pattern.gcd_min || seq.gcd > pattern.gcd_max {
            return false;
        }

        // Check ISR (Initial Sequence Rate)
        if seq.isr < pattern.isr_min || seq.isr > pattern.isr_max {
            return false;
        }

        true
    }

    /// Match TCP behavior pattern
    fn match_tcp_pattern(&self, tests: &OSTests, pattern: &TcpPattern) -> u8 {
        let mut score = 0u8;
        let mut total_checks = 0u8;

        // Check window sizes
        if !pattern.window_sizes.is_empty() {
            total_checks += 1;
            if let Some(win) = &tests.win {
                if pattern.window_sizes.contains(&win.w1) {
                    score += 1;
                }
            }
        }

        // Check TCP options
        if !pattern.options.is_empty() {
            total_checks += 1;
            // Simplified: assume partial match
            score += 1;
        }

        // Check quirks
        if !pattern.quirks.is_empty() {
            total_checks += 1;
            // Simplified: assume partial match
            score += 1;
        }

        if total_checks == 0 {
            return 50; // Default moderate score
        }

        (score as u32 * 100 / total_checks as u32) as u8
    }

    /// Get total number of signatures in database
    pub fn count(&self) -> usize {
        self.signatures.len()
    }

    /// Get signatures for a specific OS family
    pub fn get_by_family(&self, family: &str) -> Vec<&OSSignature> {
        self.signatures
            .iter()
            .filter(|sig| sig.family.eq_ignore_ascii_case(family))
            .collect()
    }
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_database_creation() {
        let db = SignatureDatabase::new();
        assert!(db.count() > 0, "Database should have signatures");
        assert!(db.count() >= 200, "Database should have at least 200 signatures");
    }

    #[test]
    fn test_get_by_family() {
        let db = SignatureDatabase::new();
        let linux_sigs = db.get_by_family("Linux");
        assert!(!linux_sigs.is_empty(), "Should have Linux signatures");
    }
}
