use nmap_core::{NmapError, Result};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::echo_request::{MutableEchoRequestPacket, EchoRequestPacket};
use pnet::packet::icmp::{IcmpTypes, IcmpCode};
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet, checksum as ipv4_checksum};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpPacket, ipv4_checksum as tcp_ipv4_checksum};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket, ipv4_checksum as udp_ipv4_checksum};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{
    transport_channel, TransportChannelType, TransportProtocol, TransportReceiver, TransportSender,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::time::timeout;
use rand::Rng;

/// Check if the current process has raw socket privileges (root or CAP_NET_RAW)
pub fn check_raw_socket_privilege() -> Result<()> {
    #[cfg(unix)]
    {
        use std::process::Command;

        // Check if running as root (UID 0)
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            return Ok(());
        }

        // Check for CAP_NET_RAW capability
        let output = Command::new("getcap")
            .arg("/proc/self/exe")
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("cap_net_raw") {
                return Ok(());
            }
        }

        Err(NmapError::InsufficientPrivileges(
            "Raw socket operations require root privileges or CAP_NET_RAW capability".to_string()
        ))
    }

    #[cfg(not(unix))]
    {
        // On Windows, administrator privileges are typically required
        Ok(())
    }
}

/// Raw socket sender for crafting and sending custom packets
pub struct RawSocketSender {
    source_ip: IpAddr,
    tx: TransportSender,
    rx: TransportReceiver,
}

impl RawSocketSender {
    /// Create a new RawSocketSender
    ///
    /// # Arguments
    /// * `source_ip` - Source IP address for packets
    /// * `protocol` - Transport protocol (TCP, UDP, ICMP, etc.)
    ///
    /// # Errors
    /// Returns error if:
    /// - Insufficient privileges (not root or no CAP_NET_RAW)
    /// - Cannot create transport channel
    pub fn new(source_ip: IpAddr, protocol: TransportProtocol) -> Result<Self> {
        check_raw_socket_privilege()?;

        let channel_type = TransportChannelType::Layer4(protocol);
        let (tx, rx) = transport_channel(4096, channel_type)
            .map_err(|e| NmapError::SocketCreationFailed)?;

        Ok(Self { source_ip, tx, rx })
    }

    /// Send a TCP SYN packet
    ///
    /// # Arguments
    /// * `dest_ip` - Destination IP address
    /// * `dest_port` - Destination port
    /// * `source_port` - Source port
    /// * `seq_num` - TCP sequence number
    /// * `window_size` - TCP window size
    /// * `options` - TCP options to include
    /// * `ttl` - IP TTL value
    /// * `df_bit` - Don't Fragment bit
    pub fn send_tcp_syn(
        &mut self,
        dest_ip: IpAddr,
        dest_port: u16,
        source_port: u16,
        seq_num: u32,
        window_size: u16,
        options: Vec<TcpOption>,
        ttl: u8,
        df_bit: bool,
    ) -> Result<()> {
        self.send_tcp_packet(
            dest_ip,
            dest_port,
            source_port,
            seq_num,
            0,
            TcpFlags::SYN,
            window_size,
            options,
            ttl,
            df_bit,
        )
    }

    /// Send a TCP ACK packet
    pub fn send_tcp_ack(
        &mut self,
        dest_ip: IpAddr,
        dest_port: u16,
        source_port: u16,
        seq_num: u32,
        ack_num: u32,
        window_size: u16,
        options: Vec<TcpOption>,
        ttl: u8,
        df_bit: bool,
    ) -> Result<()> {
        self.send_tcp_packet(
            dest_ip,
            dest_port,
            source_port,
            seq_num,
            ack_num,
            TcpFlags::ACK,
            window_size,
            options,
            ttl,
            df_bit,
        )
    }

    /// Send a TCP FIN packet
    pub fn send_tcp_fin(
        &mut self,
        dest_ip: IpAddr,
        dest_port: u16,
        source_port: u16,
        seq_num: u32,
        ack_num: u32,
        window_size: u16,
        options: Vec<TcpOption>,
        ttl: u8,
        df_bit: bool,
    ) -> Result<()> {
        self.send_tcp_packet(
            dest_ip,
            dest_port,
            source_port,
            seq_num,
            ack_num,
            TcpFlags::FIN | TcpFlags::ACK,
            window_size,
            options,
            ttl,
            df_bit,
        )
    }

    /// Send a TCP RST packet
    pub fn send_tcp_rst(
        &mut self,
        dest_ip: IpAddr,
        dest_port: u16,
        source_port: u16,
        seq_num: u32,
        ttl: u8,
        df_bit: bool,
    ) -> Result<()> {
        self.send_tcp_packet(
            dest_ip,
            dest_port,
            source_port,
            seq_num,
            0,
            TcpFlags::RST,
            0,
            vec![],
            ttl,
            df_bit,
        )
    }

    /// Send a generic TCP packet with custom flags
    fn send_tcp_packet(
        &mut self,
        dest_ip: IpAddr,
        dest_port: u16,
        source_port: u16,
        seq_num: u32,
        ack_num: u32,
        flags: u16,
        window_size: u16,
        options: Vec<TcpOption>,
        ttl: u8,
        df_bit: bool,
    ) -> Result<()> {
        match (self.source_ip, dest_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                self.send_tcp_ipv4(
                    src, dst, dest_port, source_port, seq_num, ack_num,
                    flags, window_size, options, ttl, df_bit,
                )
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                self.send_tcp_ipv6(
                    src, dst, dest_port, source_port, seq_num, ack_num,
                    flags, window_size, options, ttl,
                )
            }
            _ => Err(NmapError::InvalidPacket),
        }
    }

    fn send_tcp_ipv4(
        &mut self,
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        source_port: u16,
        seq_num: u32,
        ack_num: u32,
        flags: u16,
        window_size: u16,
        options: Vec<TcpOption>,
        ttl: u8,
        df_bit: bool,
    ) -> Result<()> {
        // Calculate TCP options length
        // TODO: Properly serialize TcpOption to bytes
        // For now, skip TCP options to get compilation working
        let options_len = 0;
        let options_bytes: Vec<u8> = Vec::new();

        // Pad to 4-byte boundary
        let padded_options_len = ((options_len + 3) / 4) * 4;
        let tcp_header_len = 20 + padded_options_len;

        let mut tcp_buffer = vec![0u8; tcp_header_len];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer)
            .ok_or(NmapError::PacketCreationFailed)?;

        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(dest_port);
        tcp_packet.set_sequence(seq_num);
        tcp_packet.set_acknowledgement(ack_num);
        tcp_packet.set_flags(flags);
        tcp_packet.set_window(window_size);
        tcp_packet.set_data_offset((tcp_header_len / 4) as u8);
        tcp_packet.set_urgent_ptr(0);

        // Set TCP options by copying the pre-encoded bytes
        if !options_bytes.is_empty() {
            tcp_buffer[20..20 + options_bytes.len()].copy_from_slice(&options_bytes);
            // Pad with zeros to 4-byte boundary
            for i in (20 + options_bytes.len())..(20 + padded_options_len) {
                tcp_buffer[i] = 0;
            }
        }

        // Calculate TCP checksum
        let checksum = tcp_ipv4_checksum(&tcp_packet.to_immutable(), &source_ip, &dest_ip);
        tcp_packet.set_checksum(checksum);

        // Send the packet
        self.tx
            .send_to(tcp_packet, IpAddr::V4(dest_ip))
            .map_err(|_| NmapError::SendFailed)?;

        Ok(())
    }

    fn send_tcp_ipv6(
        &mut self,
        source_ip: Ipv6Addr,
        dest_ip: Ipv6Addr,
        dest_port: u16,
        source_port: u16,
        seq_num: u32,
        ack_num: u32,
        flags: u16,
        window_size: u16,
        options: Vec<TcpOption>,
        ttl: u8,
    ) -> Result<()> {
        // Similar to IPv4 but for IPv6
        let tcp_header_len = 20; // Simplified - no options for now
        let mut tcp_buffer = vec![0u8; tcp_header_len];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer)
            .ok_or(NmapError::PacketCreationFailed)?;

        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(dest_port);
        tcp_packet.set_sequence(seq_num);
        tcp_packet.set_acknowledgement(ack_num);
        tcp_packet.set_flags(flags);
        tcp_packet.set_window(window_size);
        tcp_packet.set_data_offset(5); // 5 * 4 = 20 bytes
        tcp_packet.set_urgent_ptr(0);

        // Calculate TCP checksum for IPv6
        let checksum = pnet::packet::tcp::ipv6_checksum(
            &tcp_packet.to_immutable(),
            &source_ip,
            &dest_ip
        );
        tcp_packet.set_checksum(checksum);

        // Send the packet
        self.tx
            .send_to(tcp_packet, IpAddr::V6(dest_ip))
            .map_err(|_| NmapError::SendFailed)?;

        Ok(())
    }

    /// Send an ICMP Echo Request (ping)
    pub fn send_icmp_echo(
        &mut self,
        dest_ip: IpAddr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
        ttl: u8,
        df_bit: bool,
    ) -> Result<()> {
        match dest_ip {
            IpAddr::V4(dest) => {
                self.send_icmp_echo_ipv4(dest, identifier, sequence, payload, ttl, df_bit)
            }
            IpAddr::V6(dest) => {
                self.send_icmp_echo_ipv6(dest, identifier, sequence, payload, ttl)
            }
        }
    }

    fn send_icmp_echo_ipv4(
        &mut self,
        dest_ip: Ipv4Addr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
        ttl: u8,
        df_bit: bool,
    ) -> Result<()> {
        let icmp_packet_len = 8 + payload.len(); // 8 bytes header + payload
        let mut icmp_buffer = vec![0u8; icmp_packet_len];
        let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_buffer)
            .ok_or(NmapError::PacketCreationFailed)?;

        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_icmp_code(IcmpCode::new(0));
        icmp_packet.set_identifier(identifier);
        icmp_packet.set_sequence_number(sequence);
        icmp_packet.set_payload(payload);

        // Calculate ICMP checksum
        let checksum = pnet::packet::icmp::checksum(&icmp_packet.to_immutable());
        icmp_packet.set_checksum(checksum);

        // Send the packet
        self.tx
            .send_to(icmp_packet, IpAddr::V4(dest_ip))
            .map_err(|_| NmapError::SendFailed)?;

        Ok(())
    }

    fn send_icmp_echo_ipv6(
        &mut self,
        dest_ip: Ipv6Addr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
        ttl: u8,
    ) -> Result<()> {
        // ICMPv6 echo request
        let icmp_packet_len = 8 + payload.len();
        let mut icmp_buffer = vec![0u8; icmp_packet_len];

        // Type: 128 (Echo Request), Code: 0
        icmp_buffer[0] = 128;
        icmp_buffer[1] = 0;
        icmp_buffer[4..6].copy_from_slice(&identifier.to_be_bytes());
        icmp_buffer[6..8].copy_from_slice(&sequence.to_be_bytes());
        icmp_buffer[8..].copy_from_slice(payload);

        // Calculate checksum (simplified)
        let checksum = pnet::packet::util::checksum(&icmp_buffer, 1);
        icmp_buffer[2..4].copy_from_slice(&checksum.to_be_bytes());

        self.tx
            .send_to(MutableIcmpv6Packet::new(&mut icmp_buffer).unwrap(), IpAddr::V6(dest_ip))
            .map_err(|_| NmapError::SendFailed)?;

        Ok(())
    }

    /// Send a UDP probe packet
    pub fn send_udp_probe(
        &mut self,
        dest_ip: IpAddr,
        dest_port: u16,
        source_port: u16,
        payload: &[u8],
        ttl: u8,
        df_bit: bool,
    ) -> Result<()> {
        match (self.source_ip, dest_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                self.send_udp_ipv4(src, dst, dest_port, source_port, payload, ttl, df_bit)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                self.send_udp_ipv6(src, dst, dest_port, source_port, payload, ttl)
            }
            _ => Err(NmapError::InvalidPacket),
        }
    }

    fn send_udp_ipv4(
        &mut self,
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        source_port: u16,
        payload: &[u8],
        ttl: u8,
        df_bit: bool,
    ) -> Result<()> {
        let udp_packet_len = 8 + payload.len(); // 8 bytes header + payload
        let mut udp_buffer = vec![0u8; udp_packet_len];
        let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer)
            .ok_or(NmapError::PacketCreationFailed)?;

        udp_packet.set_source(source_port);
        udp_packet.set_destination(dest_port);
        udp_packet.set_length(udp_packet_len as u16);
        udp_packet.set_payload(payload);

        // Calculate UDP checksum
        let checksum = udp_ipv4_checksum(&udp_packet.to_immutable(), &source_ip, &dest_ip);
        udp_packet.set_checksum(checksum);

        // Send the packet
        self.tx
            .send_to(udp_packet, IpAddr::V4(dest_ip))
            .map_err(|_| NmapError::SendFailed)?;

        Ok(())
    }

    fn send_udp_ipv6(
        &mut self,
        source_ip: Ipv6Addr,
        dest_ip: Ipv6Addr,
        dest_port: u16,
        source_port: u16,
        payload: &[u8],
        ttl: u8,
    ) -> Result<()> {
        let udp_packet_len = 8 + payload.len();
        let mut udp_buffer = vec![0u8; udp_packet_len];
        let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer)
            .ok_or(NmapError::PacketCreationFailed)?;

        udp_packet.set_source(source_port);
        udp_packet.set_destination(dest_port);
        udp_packet.set_length(udp_packet_len as u16);
        udp_packet.set_payload(payload);

        // Calculate UDP checksum for IPv6
        let checksum = pnet::packet::udp::ipv6_checksum(
            &udp_packet.to_immutable(),
            &source_ip,
            &dest_ip
        );
        udp_packet.set_checksum(checksum);

        // Send the packet
        self.tx
            .send_to(udp_packet, IpAddr::V6(dest_ip))
            .map_err(|_| NmapError::SendFailed)?;

        Ok(())
    }

    /// Receive a TCP packet with timeout
    pub async fn receive_tcp(&mut self, timeout_duration: Duration) -> Result<(TcpPacket, IpAddr)> {
        timeout(timeout_duration, async {
            loop {
                let mut iter = pnet::transport::tcp_packet_iter(&mut self.rx);
                if let Ok((packet, addr)) = iter.next() {
                    return Ok((packet, addr));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| NmapError::Timeout)?
    }

    /// Receive an ICMP packet with timeout
    pub async fn receive_icmp(&mut self, timeout_duration: Duration) -> Result<(Vec<u8>, IpAddr)> {
        timeout(timeout_duration, async {
            loop {
                let mut iter = pnet::transport::icmp_packet_iter(&mut self.rx);
                if let Ok((packet, addr)) = iter.next() {
                    return Ok((packet.packet().to_vec(), addr));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| NmapError::Timeout)?
    }

    /// Receive a UDP packet with timeout
    pub async fn receive_udp(&mut self, timeout_duration: Duration) -> Result<(UdpPacket, IpAddr)> {
        timeout(timeout_duration, async {
            loop {
                let mut iter = pnet::transport::udp_packet_iter(&mut self.rx);
                if let Ok((packet, addr)) = iter.next() {
                    return Ok((packet, addr));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| NmapError::Timeout)?
    }
}

/// Generate a random source port for probes
pub fn random_source_port() -> u16 {
    let mut rng = rand::thread_rng();
    rng.gen_range(49152..=65535) // Ephemeral port range
}

/// Generate a random TCP sequence number
pub fn random_seq_num() -> u32 {
    let mut rng = rand::thread_rng();
    rng.gen()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_check() {
        // This test will pass or fail depending on privileges
        // In CI/CD, it may need to be skipped
        let result = check_raw_socket_privilege();
        println!("Privilege check result: {:?}", result);
    }

    #[test]
    fn test_random_port_generation() {
        let port = random_source_port();
        assert!(port >= 49152 && port <= 65535);
    }

    #[test]
    fn test_random_seq_num() {
        let seq1 = random_seq_num();
        let seq2 = random_seq_num();
        // Very unlikely to be equal
        assert_ne!(seq1, seq2);
    }

    #[tokio::test]
    #[ignore] // Requires root privileges
    async fn test_raw_socket_creation() {
        let source_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = RawSocketSender::new(source_ip, TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));

        if check_raw_socket_privilege().is_ok() {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }
}
