use nmap_core::{NmapError, Result};
use std::net::{IpAddr, Ipv4Addr};
use tokio::time::{Duration, Instant};
use pnet::packet::tcp::{TcpPacket, TcpFlags, TcpOption};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::TransportProtocol;
use rand::Rng;
use crate::raw_socket::{RawSocketSender, random_source_port, random_seq_num};
use crate::utils::{
    guess_initial_ttl, calculate_sequence_predictability, calculate_gcd_of_differences,
    calculate_isr, format_tcp_options, detect_quirks, classify_ip_id_sequence,
    sequence_difficulty, parse_tcp_options,
};

#[derive(Debug, Clone)]
pub struct TcpTestResults {
    pub seq_test: Option<SeqTest>,
    pub ops_test: Option<OpsTest>,
    pub win_test: Option<WinTest>,
    pub ecn_test: Option<EcnTest>,
    pub t_tests: Vec<Option<TTest>>, // T1-T7
    pub uptime: Option<u32>,
    pub sequence: Option<crate::TcpSequence>,
    pub ip_id_sequence: Option<crate::IpIdSequence>,
}

#[derive(Debug, Clone)]
pub struct SeqTest {
    pub sp: u32,    // TCP sequence predictability
    pub gcd: u32,   // Greatest common divisor
    pub isr: u32,   // Initial sequence number rate
    pub ti: String, // TCP timestamp option implementation
    pub ci: String, // TCP close initiation
    pub ii: String, // IPID sequence generation algorithm
    pub ts: String, // TCP timestamp option
}

#[derive(Debug, Clone)]
pub struct OpsTest {
    pub o1: String, // TCP options in packet 1
    pub o2: String, // TCP options in packet 2
    pub o3: String, // TCP options in packet 3
    pub o4: String, // TCP options in packet 4
    pub o5: String, // TCP options in packet 5
    pub o6: String, // TCP options in packet 6
}

#[derive(Debug, Clone)]
pub struct WinTest {
    pub w1: u16, // TCP window size in packet 1
    pub w2: u16, // TCP window size in packet 2
    pub w3: u16, // TCP window size in packet 3
    pub w4: u16, // TCP window size in packet 4
    pub w5: u16, // TCP window size in packet 5
    pub w6: u16, // TCP window size in packet 6
}

#[derive(Debug, Clone)]
pub struct EcnTest {
    pub r: String,   // Response
    pub df: String,  // Don't fragment bit
    pub t: u8,       // Initial TTL
    pub w: u16,      // Window size
    pub o: String,   // TCP options
    pub cc: String,  // TCP congestion control
    pub q: String,   // Quirks
}

#[derive(Debug, Clone)]
pub struct TTest {
    pub r: String,   // Response
    pub df: String,  // Don't fragment bit
    pub t: u8,       // Initial TTL
    pub tg: u8,      // Initial TTL guess
    pub w: u16,      // Window size
    pub s: String,   // TCP sequence number
    pub a: String,   // TCP acknowledgment number
    pub f: String,   // TCP flags
    pub o: String,   // TCP options
    pub rd: u16,     // TCP RST data checksum
    pub q: String,   // Quirks
}

pub struct TcpTester {
    target: IpAddr,
    timeout: Duration,
    source_ip: IpAddr,
}

impl TcpTester {
    pub fn new(target: IpAddr) -> Self {
        // Get source IP (simplified - should use proper routing table lookup)
        let source_ip = match target {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            IpAddr::V6(addr) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        };

        Self {
            target,
            timeout: Duration::from_secs(3),
            source_ip,
        }
    }

    pub fn with_source_ip(mut self, source_ip: IpAddr) -> Self {
        self.source_ip = source_ip;
        self
    }

    pub async fn run_all_tests(&mut self) -> Result<TcpTestResults> {
        let mut results = TcpTestResults {
            seq_test: None,
            ops_test: None,
            win_test: None,
            ecn_test: None,
            t_tests: vec![None; 7],
            uptime: None,
            sequence: None,
            ip_id_sequence: None,
        };

        // Run SEQ test (TCP sequence number analysis)
        results.seq_test = self.run_seq_test().await.ok();

        // Run OPS test (TCP options analysis)
        results.ops_test = self.run_ops_test().await.ok();

        // Run WIN test (TCP window size analysis)
        results.win_test = self.run_win_test().await.ok();

        // Run ECN test (Explicit Congestion Notification)
        results.ecn_test = self.run_ecn_test().await.ok();

        // Run T1-T7 tests (various TCP probes)
        for i in 0..7 {
            results.t_tests[i] = self.run_t_test(i + 1).await.ok();
        }

        // Analyze sequence numbers for predictability
        results.sequence = self.analyze_tcp_sequence().await.ok();

        // Analyze IP ID sequence
        results.ip_id_sequence = self.analyze_ip_id_sequence().await.ok();

        Ok(results)
    }

    async fn run_seq_test(&self) -> Result<SeqTest> {
        // Send 6 TCP SYN packets and analyze responses
        let mut seq_numbers = Vec::new();
        let mut timestamps = Vec::new();
        let mut ip_ids = Vec::new();
        let mut time_diffs = Vec::new();

        let mut last_time = Instant::now();

        for i in 0..6 {
            let start = Instant::now();

            match self.send_syn_and_receive().await {
                Ok((seq, ts, ip_id)) => {
                    seq_numbers.push(seq);
                    if let Some(ts) = ts {
                        timestamps.push(ts);
                    }
                    if let Some(id) = ip_id {
                        ip_ids.push(id);
                    }

                    if i > 0 {
                        let diff = start.duration_since(last_time).as_millis() as u64;
                        time_diffs.push(diff);
                    }
                    last_time = start;
                }
                Err(_) => continue,
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if seq_numbers.len() < 3 {
            return Err(NmapError::InsufficientData);
        }

        // Calculate sequence predictability
        let sp = calculate_sequence_predictability(&seq_numbers);
        let gcd = calculate_gcd_of_differences(&seq_numbers);
        let isr = calculate_isr(&seq_numbers, &time_diffs);

        // Classify IP ID sequence
        let ii = classify_ip_id_sequence(&ip_ids);

        // Check timestamp implementation
        let ti = if timestamps.is_empty() {
            "Z".to_string()
        } else if timestamps.len() == seq_numbers.len() {
            // Check if timestamps are sequential
            let ts_sequential = timestamps.windows(2).all(|w| w[1] > w[0]);
            if ts_sequential {
                "I".to_string() // Incremental
            } else {
                "U".to_string() // Unsupported/random
            }
        } else {
            "U".to_string()
        };

        // Check TCP timestamp option
        let ts = if timestamps.is_empty() {
            "U".to_string() // Not used
        } else {
            "A".to_string() // Available
        };

        Ok(SeqTest {
            sp,
            gcd,
            isr,
            ti,
            ci: "I".to_string(), // Connection initiated (simplified)
            ii,
            ts,
        })
    }

    async fn run_ops_test(&self) -> Result<OpsTest> {
        // Analyze TCP options in 6 different probe scenarios
        let mut options_list = Vec::new();

        for _ in 0..6 {
            match self.send_syn_and_receive().await {
                Ok((_, _, _)) => {
                    // In a real implementation, we'd extract the actual TCP options
                    // from the response packet
                    options_list.push("M5B4ST11".to_string()); // Placeholder
                }
                Err(_) => {
                    options_list.push("".to_string());
                }
            }
        }

        Ok(OpsTest {
            o1: options_list.get(0).cloned().unwrap_or_default(),
            o2: options_list.get(1).cloned().unwrap_or_default(),
            o3: options_list.get(2).cloned().unwrap_or_default(),
            o4: options_list.get(3).cloned().unwrap_or_default(),
            o5: options_list.get(4).cloned().unwrap_or_default(),
            o6: options_list.get(5).cloned().unwrap_or_default(),
        })
    }

    async fn run_win_test(&self) -> Result<WinTest> {
        // Analyze TCP window sizes from 6 different probes
        let mut windows = Vec::new();

        for _ in 0..6 {
            match self.send_syn_and_receive_full().await {
                Ok((window, _flags, _opts)) => {
                    windows.push(window);
                }
                Err(_) => {
                    windows.push(0);
                }
            }
        }

        Ok(WinTest {
            w1: windows.get(0).copied().unwrap_or(0),
            w2: windows.get(1).copied().unwrap_or(0),
            w3: windows.get(2).copied().unwrap_or(0),
            w4: windows.get(3).copied().unwrap_or(0),
            w5: windows.get(4).copied().unwrap_or(0),
            w6: windows.get(5).copied().unwrap_or(0),
        })
    }

    async fn run_ecn_test(&self) -> Result<EcnTest> {
        // Test Explicit Congestion Notification support
        // Send SYN with ECN flags set
        match self.send_syn_and_receive_full().await {
            Ok((window, _flags, options)) => {
                let ttl = 64; // Would extract from IP header
                let initial_ttl = guess_initial_ttl(ttl);
                // TODO: Implement detect_quirks for extracted data
                let quirks = Vec::<String>::new();

                Ok(EcnTest {
                    r: "Y".to_string(), // Response received
                    df: "Y".to_string(), // DF bit (would check IP header)
                    t: initial_ttl,
                    w: window,
                    o: format_tcp_options(&options),
                    cc: "N".to_string(), // Congestion control (simplified)
                    q: quirks.join(""),
                })
            }
            Err(_) => Err(NmapError::NoResponse),
        }
    }

    async fn run_t_test(&self, test_num: usize) -> Result<TTest> {
        // Run specific T test (T1-T7) with different probe types
        match self.send_syn_and_receive_full().await {
            Ok((window, flags, options)) => {
                let ttl = 64; // Would extract from IP header
                let initial_ttl = guess_initial_ttl(ttl);
                // TODO: Implement detect_quirks for extracted data
                let quirks = Vec::<String>::new();

                // Determine flag string (flags is u8, convert to u16)
                let flag_str = self.format_flags(flags as u16);

                Ok(TTest {
                    r: "Y".to_string(),
                    df: "Y".to_string(), // Would check IP header
                    t: initial_ttl,
                    tg: initial_ttl,
                    w: window,
                    s: "A".to_string(), // Sequence number (simplified)
                    a: "A".to_string(), // ACK number (simplified)
                    f: flag_str,
                    o: format_tcp_options(&options),
                    rd: 0, // RST data checksum (if RST)
                    q: quirks.join(""),
                })
            }
            Err(_) => {
                // No response
                Ok(TTest {
                    r: "N".to_string(),
                    df: "N".to_string(),
                    t: 0,
                    tg: 0,
                    w: 0,
                    s: "".to_string(),
                    a: "".to_string(),
                    f: "".to_string(),
                    o: "".to_string(),
                    rd: 0,
                    q: "".to_string(),
                })
            }
        }
    }

    fn format_flags(&self, flags: u16) -> String {
        let mut result = String::new();
        if flags & (TcpFlags::FIN as u16) != 0 {
            result.push('F');
        }
        if flags & (TcpFlags::SYN as u16) != 0 {
            result.push('S');
        }
        if flags & (TcpFlags::RST as u16) != 0 {
            result.push('R');
        }
        if flags & (TcpFlags::PSH as u16) != 0 {
            result.push('P');
        }
        if flags & (TcpFlags::ACK as u16) != 0 {
            result.push('A');
        }
        if flags & (TcpFlags::URG as u16) != 0 {
            result.push('U');
        }
        if flags & (TcpFlags::ECE as u16) != 0 {
            result.push('E');
        }
        if flags & (TcpFlags::CWR as u16) != 0 {
            result.push('C');
        }
        result
    }

    /// Send SYN and receive response, extracting key values
    async fn send_syn_and_receive(&self) -> Result<(u32, Option<u32>, Option<u16>)> {
        // Note: This requires raw socket privileges
        let mut sender = RawSocketSender::new(
            self.source_ip,
            TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp),
        )?;

        let source_port = random_source_port();
        let dest_port = 80; // Common open port
        let seq_num = random_seq_num();

        // Send SYN packet
        let options = vec![
            TcpOption::mss(1460),
            TcpOption::nop(),
            TcpOption::wscale(7),
            TcpOption::nop(),
            TcpOption::nop(),
            TcpOption::timestamp(0, 0),
        ];

        sender.send_tcp_syn(
            self.target,
            dest_port,
            source_port,
            seq_num,
            5840, // Window size
            options,
            64,   // TTL
            true, // DF bit
        )?;

        // Receive SYN-ACK response
        match sender.receive_tcp(self.timeout).await {
            Ok((packet, _addr)) => {
                let response_seq = packet.get_sequence();

                // Extract timestamp if present (simplified for now)
                // TODO: Properly parse TCP options from raw packet data
                let timestamp: Option<u32> = None;

                // IP ID would need to be extracted from IP header
                let ip_id = Some(0u16); // Placeholder

                Ok((response_seq, timestamp, ip_id))
            }
            Err(e) => Err(e),
        }
    }

    /// Send SYN and receive response with extracted data
    async fn send_syn_and_receive_full(&self) -> Result<(u16, u8, Vec<TcpOption>)> {
        let mut sender = RawSocketSender::new(
            self.source_ip,
            TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp),
        )?;

        let source_port = random_source_port();
        let dest_port = 80;
        let seq_num = random_seq_num();

        let options = vec![
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::timestamp(0, 0),
            TcpOption::nop(),
            TcpOption::wscale(7),
        ];

        sender.send_tcp_syn(
            self.target,
            dest_port,
            source_port,
            seq_num,
            5840,
            options,
            64,
            true,
        )?;

        // Receive response and extract needed data
        match sender.receive_tcp(self.timeout).await {
            Ok((packet, _addr)) => {
                let window = packet.get_window();
                let flags = packet.get_flags();
                let opts = parse_tcp_options(&packet);
                Ok((window, flags, opts))
            },
            Err(e) => Err(e),
        }
    }

    async fn analyze_tcp_sequence(&self) -> Result<crate::TcpSequence> {
        let mut values = Vec::new();
        for _ in 0..6 {
            if let Ok((seq, _, _)) = self.send_syn_and_receive().await {
                values.push(seq);
            }
        }

        if values.len() < 3 {
            return Err(NmapError::InsufficientData);
        }

        let index = calculate_sequence_predictability(&values);
        let difficulty = sequence_difficulty(index);

        Ok(crate::TcpSequence {
            index,
            difficulty,
            values,
        })
    }

    async fn analyze_ip_id_sequence(&self) -> Result<crate::IpIdSequence> {
        let mut values = Vec::new();
        for _ in 0..6 {
            if let Ok((_, _, ip_id)) = self.send_syn_and_receive().await {
                if let Some(id) = ip_id {
                    values.push(id);
                }
            }
        }

        if values.is_empty() {
            return Err(NmapError::InsufficientData);
        }

        let class = classify_ip_id_sequence(&values);

        Ok(crate::IpIdSequence {
            class,
            values,
        })
    }
}