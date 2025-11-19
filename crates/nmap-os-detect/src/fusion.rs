//! Multi-Source Evidence Fusion for OS Detection
//!
//! This module combines evidence from multiple sources (active fingerprinting,
//! passive detection, application-layer analysis) to produce high-confidence
//! OS detection results.

use crate::OsMatch;
use std::collections::HashMap;

/// Evidence fusion engine
pub struct EvidenceFusion;

/// A piece of evidence from a detection source
#[derive(Debug, Clone)]
pub struct Evidence {
    pub source: EvidenceSource,
    pub hint: OSHint,
}

/// OS hint with confidence level
#[derive(Debug, Clone)]
pub struct OSHint {
    pub name: String,
    pub family: String,
    pub confidence: u8,
}

/// Source of OS detection evidence
#[derive(Debug, Clone)]
pub enum EvidenceSource {
    /// Active fingerprinting (nmap-style TCP/UDP/ICMP probes)
    ActiveFingerprint,
    /// Passive fingerprinting (p0f-style SYN analysis)
    PassiveFingerprint,
    /// SSH banner analysis
    SshBanner,
    /// HTTP headers analysis
    HttpHeaders,
    /// SMB dialect detection
    SmbDialect,
    /// FTP banner analysis
    FtpBanner,
    /// SMTP banner analysis
    SmtpBanner,
}

impl EvidenceSource {
    /// Get the reliability weight of this evidence source
    ///
    /// Higher weight = more reliable
    fn weight(&self) -> f32 {
        match self {
            Self::ActiveFingerprint => 1.0,   // Most reliable (comprehensive tests)
            Self::SshBanner => 0.8,            // Very reliable (often version-specific)
            Self::PassiveFingerprint => 0.7,  // Good reliability
            Self::SmbDialect => 0.7,           // Good reliability for Windows
            Self::HttpHeaders => 0.6,          // Moderate reliability
            Self::FtpBanner => 0.6,            // Moderate reliability
            Self::SmtpBanner => 0.6,           // Moderate reliability
        }
    }

    /// Get a human-readable name for this source
    pub fn name(&self) -> &str {
        match self {
            Self::ActiveFingerprint => "Active Fingerprint",
            Self::PassiveFingerprint => "Passive Fingerprint",
            Self::SshBanner => "SSH Banner",
            Self::HttpHeaders => "HTTP Headers",
            Self::SmbDialect => "SMB Dialect",
            Self::FtpBanner => "FTP Banner",
            Self::SmtpBanner => "SMTP Banner",
        }
    }
}

impl EvidenceFusion {
    /// Create a new evidence fusion engine
    pub fn new() -> Self {
        Self
    }

    /// Combine evidence from multiple sources
    ///
    /// Uses weighted Bayesian fusion to combine evidence.
    /// Returns top matches sorted by confidence.
    pub fn combine(&self, evidence: Vec<Evidence>) -> Vec<OsMatch> {
        if evidence.is_empty() {
            return vec![];
        }

        // Single source - just convert to OsMatch
        if evidence.len() == 1 {
            let ev = &evidence[0];
            return vec![OsMatch {
                name: ev.hint.name.clone(),
                accuracy: ev.hint.confidence,
                line: String::new(),
                os_class: vec![],
                cpe: vec![],
                family: Some(ev.hint.family.clone()),
                vendor: None,
                device_type: None,
            }];
        }

        // Multiple sources - combine with weighting
        let mut os_scores: HashMap<String, f32> = HashMap::new();
        let mut os_family: HashMap<String, String> = HashMap::new();

        // Accumulate weighted scores
        for ev in &evidence {
            let weight = ev.source.weight();
            let score = (ev.hint.confidence as f32) * weight;

            *os_scores.entry(ev.hint.name.clone()).or_insert(0.0) += score;
            os_family.insert(ev.hint.name.clone(), ev.hint.family.clone());
        }

        // Normalize to percentages
        let total: f32 = os_scores.values().sum();

        let mut matches: Vec<_> = os_scores
            .iter()
            .map(|(name, &score)| {
                let confidence = if total > 0.0 {
                    ((score / total) * 100.0).min(100.0) as u8
                } else {
                    0
                };

                OsMatch {
                    name: name.clone(),
                    accuracy: confidence,
                    line: String::new(),
                    os_class: vec![],
                    cpe: vec![],
                    family: os_family.get(name).cloned(),
                    vendor: None,
                    device_type: None,
                }
            })
            .collect();

        // Sort by confidence descending
        matches.sort_by_key(|m| std::cmp::Reverse(m.accuracy));

        // Return top 3
        matches.truncate(3);
        matches
    }

    /// Combine evidence with detailed analysis
    ///
    /// Returns matches with additional metadata about sources
    pub fn combine_detailed(&self, evidence: Vec<Evidence>) -> DetailedResult {
        let matches = self.combine(evidence.clone());

        let sources: Vec<_> = evidence.iter()
            .map(|e| SourceInfo {
                source: e.source.name().to_string(),
                os_name: e.hint.name.clone(),
                confidence: e.hint.confidence,
                weight: e.source.weight(),
            })
            .collect();

        DetailedResult {
            matches,
            sources,
            total_sources: evidence.len(),
        }
    }

    /// Check if evidence sources agree
    ///
    /// Returns true if >50% of sources agree on the same OS family
    pub fn has_consensus(&self, evidence: &[Evidence]) -> bool {
        if evidence.is_empty() {
            return false;
        }

        let mut family_counts: HashMap<String, usize> = HashMap::new();
        for ev in evidence {
            *family_counts.entry(ev.hint.family.clone()).or_insert(0) += 1;
        }

        let max_count = family_counts.values().max().unwrap_or(&0);
        // For consensus, we need MORE than 50% (not exactly 50%)
        let threshold = evidence.len() / 2;

        *max_count > threshold
    }

    /// Get the most likely OS family from evidence
    pub fn most_likely_family(&self, evidence: &[Evidence]) -> Option<String> {
        if evidence.is_empty() {
            return None;
        }

        let mut family_scores: HashMap<String, f32> = HashMap::new();

        for ev in evidence {
            let weight = ev.source.weight();
            let score = (ev.hint.confidence as f32) * weight;
            *family_scores.entry(ev.hint.family.clone()).or_insert(0.0) += score;
        }

        family_scores
            .into_iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .map(|(family, _)| family)
    }
}

impl Default for EvidenceFusion {
    fn default() -> Self {
        Self::new()
    }
}

/// Detailed result with source information
#[derive(Debug, Clone)]
pub struct DetailedResult {
    pub matches: Vec<OsMatch>,
    pub sources: Vec<SourceInfo>,
    pub total_sources: usize,
}

/// Information about a detection source
#[derive(Debug, Clone)]
pub struct SourceInfo {
    pub source: String,
    pub os_name: String,
    pub confidence: u8,
    pub weight: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_fusion_single_source() {
        let fusion = EvidenceFusion::new();
        let evidence = vec![Evidence {
            source: EvidenceSource::ActiveFingerprint,
            hint: OSHint {
                name: "Ubuntu Linux 20.04".to_string(),
                family: "Linux".to_string(),
                confidence: 90,
            },
        }];

        let matches = fusion.combine(evidence);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "Ubuntu Linux 20.04");
        assert_eq!(matches[0].accuracy, 90);
    }

    #[test]
    fn test_evidence_fusion_multiple_agreeing() {
        let fusion = EvidenceFusion::new();
        let evidence = vec![
            Evidence {
                source: EvidenceSource::ActiveFingerprint,
                hint: OSHint {
                    name: "Ubuntu Linux 20.04".to_string(),
                    family: "Linux".to_string(),
                    confidence: 90,
                },
            },
            Evidence {
                source: EvidenceSource::SshBanner,
                hint: OSHint {
                    name: "Ubuntu Linux 20.04".to_string(),
                    family: "Linux".to_string(),
                    confidence: 85,
                },
            },
            Evidence {
                source: EvidenceSource::HttpHeaders,
                hint: OSHint {
                    name: "Ubuntu Linux 20.04".to_string(),
                    family: "Linux".to_string(),
                    confidence: 75,
                },
            },
        ];

        let matches = fusion.combine(evidence);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].name, "Ubuntu Linux 20.04");
        // When all sources agree, confidence should be very high
        assert!(matches[0].accuracy >= 90);
    }

    #[test]
    fn test_evidence_fusion_conflicting() {
        let fusion = EvidenceFusion::new();
        let evidence = vec![
            Evidence {
                source: EvidenceSource::ActiveFingerprint,
                hint: OSHint {
                    name: "Ubuntu Linux 20.04".to_string(),
                    family: "Linux".to_string(),
                    confidence: 90,
                },
            },
            Evidence {
                source: EvidenceSource::SshBanner,
                hint: OSHint {
                    name: "Debian Linux 11".to_string(),
                    family: "Linux".to_string(),
                    confidence: 80,
                },
            },
            Evidence {
                source: EvidenceSource::HttpHeaders,
                hint: OSHint {
                    name: "Windows 10".to_string(),
                    family: "Windows".to_string(),
                    confidence: 70,
                },
            },
        ];

        let matches = fusion.combine(evidence);
        // Should have multiple matches
        assert!(matches.len() > 1);
        // Active fingerprint has highest weight, so Ubuntu should win
        assert_eq!(matches[0].name, "Ubuntu Linux 20.04");
    }

    #[test]
    fn test_consensus_detection() {
        let fusion = EvidenceFusion::new();

        // Strong consensus
        let evidence_agree = vec![
            Evidence {
                source: EvidenceSource::ActiveFingerprint,
                hint: OSHint {
                    name: "Linux".to_string(),
                    family: "Linux".to_string(),
                    confidence: 90,
                },
            },
            Evidence {
                source: EvidenceSource::SshBanner,
                hint: OSHint {
                    name: "Ubuntu".to_string(),
                    family: "Linux".to_string(),
                    confidence: 85,
                },
            },
            Evidence {
                source: EvidenceSource::HttpHeaders,
                hint: OSHint {
                    name: "Debian".to_string(),
                    family: "Linux".to_string(),
                    confidence: 75,
                },
            },
        ];
        assert!(fusion.has_consensus(&evidence_agree));

        // No consensus
        let evidence_conflict = vec![
            Evidence {
                source: EvidenceSource::ActiveFingerprint,
                hint: OSHint {
                    name: "Linux".to_string(),
                    family: "Linux".to_string(),
                    confidence: 90,
                },
            },
            Evidence {
                source: EvidenceSource::SshBanner,
                hint: OSHint {
                    name: "Windows".to_string(),
                    family: "Windows".to_string(),
                    confidence: 85,
                },
            },
        ];
        assert!(!fusion.has_consensus(&evidence_conflict));
    }

    #[test]
    fn test_most_likely_family() {
        let fusion = EvidenceFusion::new();
        let evidence = vec![
            Evidence {
                source: EvidenceSource::ActiveFingerprint,
                hint: OSHint {
                    name: "Ubuntu Linux".to_string(),
                    family: "Linux".to_string(),
                    confidence: 90,
                },
            },
            Evidence {
                source: EvidenceSource::SshBanner,
                hint: OSHint {
                    name: "Debian Linux".to_string(),
                    family: "Linux".to_string(),
                    confidence: 80,
                },
            },
            Evidence {
                source: EvidenceSource::HttpHeaders,
                hint: OSHint {
                    name: "Windows 10".to_string(),
                    family: "Windows".to_string(),
                    confidence: 60,
                },
            },
        ];

        let family = fusion.most_likely_family(&evidence);
        assert_eq!(family, Some("Linux".to_string()));
    }

    #[test]
    fn test_detailed_result() {
        let fusion = EvidenceFusion::new();
        let evidence = vec![
            Evidence {
                source: EvidenceSource::ActiveFingerprint,
                hint: OSHint {
                    name: "Ubuntu Linux 20.04".to_string(),
                    family: "Linux".to_string(),
                    confidence: 90,
                },
            },
            Evidence {
                source: EvidenceSource::SshBanner,
                hint: OSHint {
                    name: "Ubuntu Linux 20.04".to_string(),
                    family: "Linux".to_string(),
                    confidence: 85,
                },
            },
        ];

        let result = fusion.combine_detailed(evidence);
        assert!(!result.matches.is_empty());
        assert_eq!(result.sources.len(), 2);
        assert_eq!(result.total_sources, 2);
        assert_eq!(result.sources[0].source, "Active Fingerprint");
        assert_eq!(result.sources[1].source, "SSH Banner");
    }

    #[test]
    fn test_empty_evidence() {
        let fusion = EvidenceFusion::new();
        let evidence = vec![];

        let matches = fusion.combine(evidence.clone());
        assert!(matches.is_empty());

        assert!(!fusion.has_consensus(&evidence));
        assert!(fusion.most_likely_family(&evidence).is_none());
    }

    #[test]
    fn test_source_weights() {
        // Verify weight hierarchy
        assert_eq!(EvidenceSource::ActiveFingerprint.weight(), 1.0);
        assert!(EvidenceSource::SshBanner.weight() > EvidenceSource::HttpHeaders.weight());
        assert!(EvidenceSource::PassiveFingerprint.weight() > EvidenceSource::HttpHeaders.weight());
    }
}
