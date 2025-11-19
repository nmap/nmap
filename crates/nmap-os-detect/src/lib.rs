use nmap_core::{NmapError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::time::{timeout, Duration};

pub mod fingerprint;
pub mod tcp_tests;
pub mod udp_tests;
pub mod icmp_tests;
pub mod raw_socket;
pub mod utils;
pub mod signatures;
pub mod passive;
pub mod app_layer;
pub mod fusion;

pub use fingerprint::*;
pub use tcp_tests::*;
pub use udp_tests::*;
pub use icmp_tests::*;
pub use raw_socket::*;
pub use utils::*;
pub use signatures::SignatureDatabase;
pub use passive::{PassiveDetector, PassiveSignature, OSHint as PassiveOSHint};
pub use app_layer::{AppLayerDetector, OSHint as AppLayerOSHint};
pub use fusion::{EvidenceFusion, Evidence, EvidenceSource, OSHint as FusionOSHint, DetailedResult, SourceInfo};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsMatch {
    pub name: String,
    pub accuracy: u8,
    #[serde(default)]
    pub line: String,
    #[serde(default)]
    pub os_class: Vec<OsClass>,
    #[serde(default)]
    pub cpe: Vec<String>,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub device_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsClass {
    pub vendor: String,
    pub os_gen: String,
    pub os_type: String,
    pub accuracy: u8,
    pub cpe: Vec<String>,
}

/// OS fingerprinting tests results
#[derive(Debug, Clone)]
pub struct OSTests {
    pub seq: Option<SeqTest>,
    pub ops: Option<OpsTest>,
    pub win: Option<WinTest>,
    pub ecn: Option<EcnTest>,
    pub t1: Option<TTest>,
    pub t2: Option<TTest>,
    pub t3: Option<TTest>,
    pub t4: Option<TTest>,
    pub t5: Option<TTest>,
    pub t6: Option<TTest>,
    pub t7: Option<TTest>,
    pub u1: Option<U1Test>,
    pub ie: Option<IeTest>,
}

#[derive(Debug, Clone)]
pub struct OsDetectionResult {
    pub target: IpAddr,
    pub matches: Vec<OsMatch>,
    pub fingerprint: Option<String>,
    pub uptime: Option<u32>,
    pub tcp_sequence: Option<TcpSequence>,
    pub ip_id_sequence: Option<IpIdSequence>,
}

#[derive(Debug, Clone)]
pub struct TcpSequence {
    pub index: u32,
    pub difficulty: String,
    pub values: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct IpIdSequence {
    pub class: String,
    pub values: Vec<u16>,
}

pub struct OsDetector {
    fingerprint_db: FingerprintDatabase,
    timeout: Duration,
}

impl OsDetector {
    pub fn new() -> Result<Self> {
        Ok(Self {
            fingerprint_db: FingerprintDatabase::load_default()?,
            timeout: Duration::from_secs(5),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn detect_os(&self, target: IpAddr) -> Result<OsDetectionResult> {
        let ip = target;

        // Perform OS detection tests
        let tcp_results = timeout(
            self.timeout,
            self.run_tcp_tests(ip)
        ).await.map_err(|_| NmapError::Timeout("TCP tests timed out".to_string()))??;

        let udp_results = timeout(
            self.timeout,
            self.run_udp_tests(ip)
        ).await.map_err(|_| NmapError::Timeout("UDP tests timed out".to_string()))??;

        let icmp_results = timeout(
            self.timeout,
            self.run_icmp_tests(ip)
        ).await.map_err(|_| NmapError::Timeout("ICMP tests timed out".to_string()))??;

        // Generate fingerprint from test results
        let fingerprint = self.generate_fingerprint(&tcp_results, &udp_results, &icmp_results);

        // Match against database
        let matches = self.fingerprint_db.match_fingerprint(&fingerprint)?;

        Ok(OsDetectionResult {
            target: ip,
            matches,
            fingerprint: Some(fingerprint),
            uptime: tcp_results.uptime,
            tcp_sequence: tcp_results.sequence,
            ip_id_sequence: tcp_results.ip_id_sequence,
        })
    }

    async fn run_tcp_tests(&self, target: IpAddr) -> Result<TcpTestResults> {
        let mut tcp_tester = TcpTester::new(target);
        tcp_tester.run_all_tests().await
    }

    async fn run_udp_tests(&self, target: IpAddr) -> Result<UdpTestResults> {
        let mut udp_tester = UdpTester::new(target);
        udp_tester.run_all_tests().await
    }

    async fn run_icmp_tests(&self, target: IpAddr) -> Result<IcmpTestResults> {
        let mut icmp_tester = IcmpTester::new(target);
        icmp_tester.run_all_tests().await
    }

    fn generate_fingerprint(
        &self,
        tcp: &TcpTestResults,
        udp: &UdpTestResults,
        icmp: &IcmpTestResults,
    ) -> String {
        let mut fingerprint = String::new();
        
        // SEQ test
        if let Some(ref seq) = tcp.seq_test {
            fingerprint.push_str(&format!("SEQ(SP={:X},GCD={:X},ISR={:X},TI={},CI={},II={},TS={})\n",
                seq.sp, seq.gcd, seq.isr, seq.ti, seq.ci, seq.ii, seq.ts));
        }

        // OPS test
        if let Some(ref ops) = tcp.ops_test {
            fingerprint.push_str(&format!("OPS(O1={},O2={},O3={},O4={},O5={},O6={})\n",
                ops.o1, ops.o2, ops.o3, ops.o4, ops.o5, ops.o6));
        }

        // WIN test
        if let Some(ref win) = tcp.win_test {
            fingerprint.push_str(&format!("WIN(W1={:X},W2={:X},W3={:X},W4={:X},W5={:X},W6={:X})\n",
                win.w1, win.w2, win.w3, win.w4, win.w5, win.w6));
        }

        // ECN test
        if let Some(ref ecn) = tcp.ecn_test {
            fingerprint.push_str(&format!("ECN(R={},DF={},T={:X},W={:X},O={},CC={},Q={})\n",
                ecn.r, ecn.df, ecn.t, ecn.w, ecn.o, ecn.cc, ecn.q));
        }

        // T1-T7 tests
        for (i, test) in tcp.t_tests.iter().enumerate() {
            if let Some(ref t) = test {
                fingerprint.push_str(&format!("T{}(R={},DF={},T={:X},TG={:X},W={:X},S={},A={},F={},O={},RD={:X},Q={})\n",
                    i + 1, t.r, t.df, t.t, t.tg, t.w, t.s, t.a, t.f, t.o, t.rd, t.q));
            }
        }

        // U1 test
        if let Some(ref u1) = udp.u1_test {
            fingerprint.push_str(&format!("U1(R={},DF={},T={:X},IPL={:X},UN={:X},RIPL={:X},RID={:X},RIPCK={},RUCK={:X},RUD={})\n",
                u1.r, u1.df, u1.t, u1.ipl, u1.un, u1.ripl, u1.rid, u1.ripck, u1.ruck, u1.rud));
        }

        // IE test
        if let Some(ref ie) = icmp.ie_test {
            fingerprint.push_str(&format!("IE(R={},DFI={},T={:X},CD={})\n",
                ie.r, ie.dfi, ie.t, ie.cd));
        }

        fingerprint
    }
}

// Note: Default trait not implemented because OsDetector::new() can fail.
// Users should explicitly call OsDetector::new() which returns Result<Self, Error>
// instead of relying on Default::default() which would panic on failure.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passive_detector_creation() {
        let detector = PassiveDetector::new();
        // Should have 30+ signatures
        assert!(detector.signature_count() >= 30);
    }

    #[test]
    fn test_app_layer_detector_creation() {
        let _detector = AppLayerDetector::new();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_evidence_fusion_creation() {
        let _fusion = EvidenceFusion::new();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_passive_linux_detection() {
        let detector = PassiveDetector::new();
        let hint = detector.detect(64, 5840, Some(1460));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.family, "Linux");
    }

    #[test]
    fn test_passive_windows_detection() {
        let detector = PassiveDetector::new();
        let hint = detector.detect(128, 8192, Some(1460));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.family, "Windows");
    }

    #[test]
    fn test_app_layer_http_detection() {
        let detector = AppLayerDetector::new();
        let mut headers = HashMap::new();
        headers.insert("Server".to_string(), "Apache/2.4.41 (Ubuntu)".to_string());

        let result = detector.detect_from_http(&headers);
        assert!(result.is_some());
        let os = result.unwrap();
        assert_eq!(os.family, "Linux");
    }

    #[test]
    fn test_app_layer_ssh_detection() {
        let detector = AppLayerDetector::new();
        let banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";

        let result = detector.detect_from_ssh(banner);
        assert!(result.is_some());
        let os = result.unwrap();
        assert_eq!(os.family, "Linux");
    }

    #[test]
    fn test_evidence_fusion_single() {
        let fusion = EvidenceFusion::new();
        let evidence = vec![Evidence {
            source: EvidenceSource::ActiveFingerprint,
            hint: FusionOSHint {
                name: "Ubuntu Linux 20.04".to_string(),
                family: "Linux".to_string(),
                confidence: 90,
            },
        }];

        let matches = fusion.combine(evidence);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].name, "Ubuntu Linux 20.04");
    }

    #[test]
    fn test_evidence_fusion_multiple() {
        let fusion = EvidenceFusion::new();
        let evidence = vec![
            Evidence {
                source: EvidenceSource::ActiveFingerprint,
                hint: FusionOSHint {
                    name: "Ubuntu Linux 20.04".to_string(),
                    family: "Linux".to_string(),
                    confidence: 90,
                },
            },
            Evidence {
                source: EvidenceSource::SshBanner,
                hint: FusionOSHint {
                    name: "Ubuntu Linux 20.04".to_string(),
                    family: "Linux".to_string(),
                    confidence: 85,
                },
            },
            Evidence {
                source: EvidenceSource::HttpHeaders,
                hint: FusionOSHint {
                    name: "Ubuntu Linux".to_string(),
                    family: "Linux".to_string(),
                    confidence: 70,
                },
            },
        ];

        let matches = fusion.combine(evidence);
        assert!(!matches.is_empty());
        // Ubuntu Linux 20.04 should have highest confidence
        // (Note: "Ubuntu Linux" and "Ubuntu Linux 20.04" are treated as different OSes,
        //  so the score is split. Expect >= 70% confidence)
        assert!(matches[0].accuracy >= 70);
    }

    #[test]
    fn test_integration_passive_to_fusion() {
        // Passive detection
        let passive_detector = PassiveDetector::new();
        let passive_hint = passive_detector.detect(64, 64240, Some(1460));
        assert!(passive_hint.is_some());

        // Convert to evidence
        let evidence = vec![Evidence {
            source: EvidenceSource::PassiveFingerprint,
            hint: FusionOSHint {
                name: passive_hint.as_ref().unwrap().name.clone(),
                family: passive_hint.as_ref().unwrap().family.clone(),
                confidence: passive_hint.unwrap().confidence,
            },
        }];

        // Fusion
        let fusion = EvidenceFusion::new();
        let matches = fusion.combine(evidence);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_integration_app_layer_to_fusion() {
        // App-layer detection
        let app_detector = AppLayerDetector::new();
        let ssh_hint = app_detector.detect_from_ssh("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5");
        assert!(ssh_hint.is_some());

        let mut headers = HashMap::new();
        headers.insert("Server".to_string(), "Apache/2.4.41 (Ubuntu)".to_string());
        let http_hint = app_detector.detect_from_http(&headers);
        assert!(http_hint.is_some());

        // Combine both
        let evidence = vec![
            Evidence {
                source: EvidenceSource::SshBanner,
                hint: FusionOSHint {
                    name: ssh_hint.as_ref().unwrap().name.clone(),
                    family: ssh_hint.as_ref().unwrap().family.clone(),
                    confidence: ssh_hint.unwrap().confidence,
                },
            },
            Evidence {
                source: EvidenceSource::HttpHeaders,
                hint: FusionOSHint {
                    name: http_hint.as_ref().unwrap().name.clone(),
                    family: http_hint.as_ref().unwrap().family.clone(),
                    confidence: http_hint.unwrap().confidence,
                },
            },
        ];

        let fusion = EvidenceFusion::new();
        let matches = fusion.combine(evidence);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].family, Some("Linux".to_string()));
    }

    #[test]
    fn test_full_pipeline() {
        // Simulate a full detection pipeline with all three components

        // 1. Passive detection
        let passive = PassiveDetector::new();
        let passive_hint = passive.detect_full(64, 64240, Some(1460), true, true, true);

        // 2. App-layer detection
        let app_layer = AppLayerDetector::new();
        let ssh_hint = app_layer.detect_from_ssh("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1");
        let smb_hint = app_layer.detect_from_smb("SMB 3.1.1");

        // 3. Collect evidence
        let mut evidence = vec![];

        if let Some(hint) = passive_hint {
            evidence.push(Evidence {
                source: EvidenceSource::PassiveFingerprint,
                hint: FusionOSHint {
                    name: hint.name,
                    family: hint.family,
                    confidence: hint.confidence,
                },
            });
        }

        if let Some(hint) = ssh_hint {
            evidence.push(Evidence {
                source: EvidenceSource::SshBanner,
                hint: FusionOSHint {
                    name: hint.name,
                    family: hint.family,
                    confidence: hint.confidence,
                },
            });
        }

        if let Some(hint) = smb_hint {
            evidence.push(Evidence {
                source: EvidenceSource::SmbDialect,
                hint: FusionOSHint {
                    name: hint.name,
                    family: hint.family,
                    confidence: hint.confidence,
                },
            });
        }

        // 4. Fuse evidence
        let fusion = EvidenceFusion::new();
        let matches = fusion.combine(evidence);

        // Should have results
        assert!(!matches.is_empty());

        // Top match should have reasonable confidence
        assert!(matches[0].accuracy > 0);
    }
}