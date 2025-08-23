use nmap_core::{NmapError, Result};
use nmap_net::TargetHost;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::time::{timeout, Duration};

pub mod fingerprint;
pub mod tcp_tests;
pub mod udp_tests;
pub mod icmp_tests;

pub use fingerprint::*;
pub use tcp_tests::*;
pub use udp_tests::*;
pub use icmp_tests::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsMatch {
    pub name: String,
    pub accuracy: u8,
    pub line: String,
    pub os_class: Vec<OsClass>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsClass {
    pub vendor: String,
    pub os_gen: String,
    pub os_type: String,
    pub accuracy: u8,
    pub cpe: Vec<String>,
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

    pub async fn detect_os(&self, target: &TargetHost) -> Result<OsDetectionResult> {
        let ip = target.ip();
        
        // Perform OS detection tests
        let tcp_results = timeout(
            self.timeout,
            self.run_tcp_tests(ip)
        ).await.map_err(|_| NmapError::Timeout)?;

        let udp_results = timeout(
            self.timeout,
            self.run_udp_tests(ip)
        ).await.map_err(|_| NmapError::Timeout)?;

        let icmp_results = timeout(
            self.timeout,
            self.run_icmp_tests(ip)
        ).await.map_err(|_| NmapError::Timeout)?;

        // Generate fingerprint from test results
        let fingerprint = self.generate_fingerprint(&tcp_results?, &udp_results?, &icmp_results?);
        
        // Match against database
        let matches = self.fingerprint_db.match_fingerprint(&fingerprint)?;

        Ok(OsDetectionResult {
            target: ip,
            matches,
            fingerprint: Some(fingerprint),
            uptime: tcp_results?.uptime,
            tcp_sequence: tcp_results?.sequence,
            ip_id_sequence: tcp_results?.ip_id_sequence,
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

impl Default for OsDetector {
    fn default() -> Self {
        Self::new().expect("Failed to create default OS detector")
    }
}