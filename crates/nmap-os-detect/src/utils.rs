use pnet::packet::tcp::{TcpOption, TcpPacket, TcpFlags, TcpOptionPacket, TcpOptionNumbers};
use pnet::packet::Packet;
use std::collections::HashMap;

/// Guess the initial TTL value based on the observed TTL
///
/// Common initial TTL values:
/// - 32, 64, 128, 255 (most common)
/// - 30, 60, 120, 200 (less common)
///
/// # Arguments
/// * `observed_ttl` - The TTL value observed in the received packet
///
/// # Returns
/// The most likely initial TTL value
pub fn guess_initial_ttl(observed_ttl: u8) -> u8 {
    // Common initial TTL values in descending order of likelihood
    const COMMON_TTLS: [u8; 8] = [255, 128, 64, 32, 200, 120, 60, 30];

    // Find the smallest common TTL that is greater than or equal to observed
    for &ttl in &COMMON_TTLS {
        if ttl >= observed_ttl {
            return ttl;
        }
    }

    // If observed TTL is greater than all common values, return 255
    255
}

/// Calculate the distance (hop count) between source and destination
///
/// # Arguments
/// * `initial_ttl` - The guessed initial TTL
/// * `observed_ttl` - The observed TTL in the packet
///
/// # Returns
/// Estimated number of hops
pub fn calculate_hop_distance(initial_ttl: u8, observed_ttl: u8) -> u8 {
    initial_ttl.saturating_sub(observed_ttl)
}

/// Calculate TCP sequence number predictability index
///
/// The predictability index measures how predictable TCP sequence numbers are.
/// Lower values indicate more predictable (less secure) sequence numbers.
///
/// # Arguments
/// * `sequences` - Array of TCP sequence numbers from consecutive probes
///
/// # Returns
/// Predictability index (0 = perfectly predictable, higher = more random)
pub fn calculate_sequence_predictability(sequences: &[u32]) -> u32 {
    if sequences.len() < 2 {
        return 0;
    }

    // Calculate differences between consecutive sequence numbers
    let mut diffs: Vec<i64> = Vec::new();
    for i in 1..sequences.len() {
        let diff = sequences[i].wrapping_sub(sequences[i - 1]) as i64;
        diffs.push(diff);
    }

    if diffs.is_empty() {
        return 0;
    }

    // Calculate mean of differences
    let mean: f64 = diffs.iter().sum::<i64>() as f64 / diffs.len() as f64;

    // Calculate standard deviation
    let variance: f64 = diffs
        .iter()
        .map(|&x| {
            let diff = x as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / diffs.len() as f64;

    let std_dev = variance.sqrt();

    // Predictability index is based on standard deviation
    // Scale it to match Nmap's index range (0-2^32)
    let index = std_dev as u32;

    index
}

/// Calculate the Greatest Common Divisor (GCD) of sequence number differences
///
/// This helps identify if sequence numbers follow a pattern (incrementing by
/// a constant value or multiples of it).
///
/// # Arguments
/// * `sequences` - Array of TCP sequence numbers
///
/// # Returns
/// GCD of all sequence number differences
pub fn calculate_gcd_of_differences(sequences: &[u32]) -> u32 {
    if sequences.len() < 2 {
        return 1;
    }

    // Calculate differences
    let mut diffs: Vec<u32> = Vec::new();
    for i in 1..sequences.len() {
        let diff = sequences[i].wrapping_sub(sequences[i - 1]);
        if diff > 0 {
            diffs.push(diff);
        }
    }

    if diffs.is_empty() {
        return 1;
    }

    // Calculate GCD of all differences
    let mut result = diffs[0];
    for &diff in &diffs[1..] {
        result = gcd(result, diff);
        if result == 1 {
            break; // No point continuing if GCD is already 1
        }
    }

    result
}

/// Calculate GCD of two numbers using Euclidean algorithm
fn gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let temp = b;
        b = a % b;
        a = temp;
    }
    a
}

/// Calculate Initial Sequence Rate (ISR)
///
/// Measures the rate at which sequence numbers increase per time unit
///
/// # Arguments
/// * `sequences` - Array of TCP sequence numbers
/// * `time_diffs_ms` - Time differences in milliseconds between probes
///
/// # Returns
/// ISR value (sequence increment per second)
pub fn calculate_isr(sequences: &[u32], time_diffs_ms: &[u64]) -> u32 {
    if sequences.len() < 2 || time_diffs_ms.is_empty() {
        return 0;
    }

    let mut total_seq_diff: u64 = 0;
    let mut total_time_ms: u64 = 0;

    for i in 1..sequences.len() {
        let seq_diff = sequences[i].wrapping_sub(sequences[i - 1]) as u64;
        total_seq_diff = total_seq_diff.wrapping_add(seq_diff);

        if i - 1 < time_diffs_ms.len() {
            total_time_ms += time_diffs_ms[i - 1];
        }
    }

    if total_time_ms == 0 {
        return 0;
    }

    // Convert to rate per second
    let rate = (total_seq_diff * 1000) / total_time_ms;
    rate as u32
}

/// Format TCP options into Nmap fingerprint format
///
/// Formats TCP options as they appear in Nmap fingerprints (e.g., "M5B4ST11")
///
/// # Arguments
/// * `options` - Slice of TCP options
///
/// # Returns
/// Formatted string representation
pub fn format_tcp_options(options: &[TcpOption]) -> String {
    // TODO: Properly parse TCP options from TcpOption structs
    // For now, return a placeholder based on the number of options
    if options.is_empty() {
        return "O".to_string(); // No options
    }

    // Simplified implementation - just indicate options are present
    let mut result = String::new();
    for _opt in options {
        // Each option contributes to the fingerprint
        // This is a simplified version - full implementation would parse each option type
        result.push('X'); // Placeholder
    }

    if result.is_empty() {
        result.push('O');
    }

    result
}

/// Parse TCP options from a packet
///
/// # Arguments
/// * `packet` - TCP packet to parse options from
///
/// # Returns
/// Vector of parsed TCP options
pub fn parse_tcp_options(packet: &TcpPacket) -> Vec<TcpOption> {
    packet.get_options().to_vec()
}

/// Detect TCP quirks and anomalies
///
/// Identifies unusual or non-standard TCP behavior that can help
/// identify specific OS implementations.
///
/// # Arguments
/// * `tcp` - TCP packet to analyze
///
/// # Returns
/// Vector of quirk identifiers
pub fn detect_quirks(tcp: &TcpPacket) -> Vec<String> {
    let mut quirks = Vec::new();

    // Check for reserved bits being set
    let flags = tcp.get_flags();
    if flags & 0x80 != 0 {
        quirks.push("R".to_string()); // Reserved bit set
    }

    // Check for unusual urgent pointer with no URG flag
    if tcp.get_urgent_ptr() != 0 && (flags & TcpFlags::URG) == 0 {
        quirks.push("U".to_string()); // Urgent pointer set without URG flag
    }

    // Check for data in packets that shouldn't have it
    let has_data = tcp.payload().len() > 0;
    if has_data && (flags & (TcpFlags::SYN | TcpFlags::RST)) != 0 {
        quirks.push("D".to_string()); // Data in SYN or RST
    }

    // Check for unusual flag combinations
    if (flags & TcpFlags::SYN) != 0 && (flags & TcpFlags::FIN) != 0 {
        quirks.push("SF".to_string()); // SYN+FIN (unusual)
    }

    if (flags & TcpFlags::SYN) != 0 && (flags & TcpFlags::RST) != 0 {
        quirks.push("SR".to_string()); // SYN+RST (unusual)
    }

    // Check for ACK number in non-ACK packets
    if tcp.get_acknowledgement() != 0 && (flags & TcpFlags::ACK) == 0 {
        quirks.push("A".to_string()); // ACK number without ACK flag
    }

    // Check for zero window
    if tcp.get_window() == 0 && (flags & TcpFlags::RST) == 0 {
        quirks.push("Z".to_string()); // Zero window (not in RST)
    }

    // Check sequence number in RST
    if (flags & TcpFlags::RST) != 0 && tcp.get_sequence() == 0 {
        quirks.push("0".to_string()); // Zero sequence in RST
    }

    quirks
}

/// Classify IP ID sequence generation algorithm
///
/// Determines how a host generates IP ID values, which can be used
/// for OS fingerprinting.
///
/// # Arguments
/// * `ip_ids` - Array of IP ID values from consecutive probes
///
/// # Returns
/// Classification string (I=incremental, RI=random incremental, Z=zero, etc.)
pub fn classify_ip_id_sequence(ip_ids: &[u16]) -> String {
    if ip_ids.is_empty() {
        return "U".to_string(); // Unknown
    }

    // Check if all zeros
    if ip_ids.iter().all(|&id| id == 0) {
        return "Z".to_string(); // All zeros
    }

    // Check if all the same (but not zero)
    if ip_ids.windows(2).all(|w| w[0] == w[1]) {
        return "BI".to_string(); // Broken - identical
    }

    if ip_ids.len() < 2 {
        return "U".to_string();
    }

    // Check if incremental
    let mut diffs: Vec<i32> = Vec::new();
    for i in 1..ip_ids.len() {
        let diff = (ip_ids[i] as i32).wrapping_sub(ip_ids[i - 1] as i32);
        diffs.push(diff);
    }

    // Check if differences are small and positive (incremental)
    let avg_diff: f64 = diffs.iter().sum::<i32>() as f64 / diffs.len() as f64;
    let abs_diffs: Vec<i32> = diffs.iter().map(|&d| d.abs()).collect();
    let avg_abs_diff = abs_diffs.iter().sum::<i32>() as f64 / abs_diffs.len() as f64;

    if avg_diff > 0.0 && avg_abs_diff < 10000.0 {
        // Check variance to determine if random or predictable
        let variance: f64 = diffs
            .iter()
            .map(|&d| {
                let diff = d as f64 - avg_diff;
                diff * diff
            })
            .sum::<f64>()
            / diffs.len() as f64;

        if variance < 100.0 {
            return "I".to_string(); // Incremental (predictable)
        } else if variance < 10000.0 {
            return "RI".to_string(); // Random incremental
        } else {
            return "RPI".to_string(); // Random positive incremental
        }
    }

    // Check if truly random (large variance in both directions)
    if avg_abs_diff > 10000.0 {
        return "R".to_string(); // Random
    }

    "U".to_string() // Unknown/unclassified
}

/// Calculate difficulty of TCP sequence prediction
///
/// # Arguments
/// * `predictability_index` - The sequence predictability index
///
/// # Returns
/// Human-readable difficulty string
pub fn sequence_difficulty(predictability_index: u32) -> String {
    match predictability_index {
        0..=999_999 => "Trivial joke".to_string(),
        1_000_000..=9_999_999 => "Easy".to_string(),
        10_000_000..=49_999_999 => "Worthy challenge".to_string(),
        50_000_000..=99_999_999 => "Good luck!".to_string(),
        _ => "Impossible".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guess_initial_ttl() {
        assert_eq!(guess_initial_ttl(62), 64);
        assert_eq!(guess_initial_ttl(120), 128);
        assert_eq!(guess_initial_ttl(250), 255);
        assert_eq!(guess_initial_ttl(30), 32);
        assert_eq!(guess_initial_ttl(64), 64);
    }

    #[test]
    fn test_calculate_hop_distance() {
        assert_eq!(calculate_hop_distance(64, 60), 4);
        assert_eq!(calculate_hop_distance(128, 100), 28);
        assert_eq!(calculate_hop_distance(255, 240), 15);
    }

    #[test]
    fn test_gcd() {
        assert_eq!(gcd(12, 8), 4);
        assert_eq!(gcd(100, 50), 50);
        assert_eq!(gcd(17, 19), 1);
        assert_eq!(gcd(0, 5), 5);
    }

    #[test]
    fn test_calculate_gcd_of_differences() {
        // Sequences incrementing by 2
        let sequences = vec![100, 102, 104, 106, 108];
        assert_eq!(calculate_gcd_of_differences(&sequences), 2);

        // Sequences incrementing by different values with GCD 5
        let sequences = vec![100, 105, 115, 125];
        assert_eq!(calculate_gcd_of_differences(&sequences), 5);

        // Random increments
        let sequences = vec![100, 103, 108, 115];
        assert_eq!(calculate_gcd_of_differences(&sequences), 1);
    }

    #[test]
    fn test_calculate_sequence_predictability() {
        // Perfectly predictable (constant increment)
        let sequences = vec![100, 200, 300, 400, 500];
        let index = calculate_sequence_predictability(&sequences);
        assert_eq!(index, 0); // Standard deviation is 0

        // Somewhat predictable
        let sequences = vec![100, 200, 305, 410, 520];
        let index = calculate_sequence_predictability(&sequences);
        assert!(index > 0);
    }

    #[test]
    fn test_classify_ip_id_sequence() {
        // All zeros
        assert_eq!(classify_ip_id_sequence(&[0, 0, 0, 0]), "Z");

        // All same (not zero)
        assert_eq!(classify_ip_id_sequence(&[100, 100, 100]), "BI");

        // Incremental
        let ids = vec![100, 101, 102, 103, 104];
        let class = classify_ip_id_sequence(&ids);
        assert_eq!(class, "I");

        // Empty
        assert_eq!(classify_ip_id_sequence(&[]), "U");
    }

    #[test]
    fn test_sequence_difficulty() {
        assert_eq!(sequence_difficulty(500_000), "Trivial joke");
        assert_eq!(sequence_difficulty(5_000_000), "Easy");
        assert_eq!(sequence_difficulty(25_000_000), "Worthy challenge");
        assert_eq!(sequence_difficulty(75_000_000), "Good luck!");
        assert_eq!(sequence_difficulty(150_000_000), "Impossible");
    }

    #[test]
    fn test_format_tcp_options() {
        let options = vec![
            TcpOption::mss(1460),
            TcpOption::nop(),
            TcpOption::wscale(7),
            TcpOption::sack_perm(),
        ];
        let formatted = format_tcp_options(&options);
        assert!(formatted.contains("M"));
        assert!(formatted.contains("N"));
        assert!(formatted.contains("W"));
        assert!(formatted.contains("S"));
    }

    #[test]
    fn test_calculate_isr() {
        let sequences = vec![1000, 2000, 3000, 4000];
        let time_diffs = vec![100, 100, 100]; // 100ms between each
        let isr = calculate_isr(&sequences, &time_diffs);
        // 1000 increase per 100ms = 10000 per second
        assert_eq!(isr, 10000);
    }
}
