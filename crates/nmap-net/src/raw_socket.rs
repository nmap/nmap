use anyhow::{anyhow, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet};
use rand::Rng;

/// Raw socket wrapper for packet crafting
pub struct RawSocket {
    socket: Socket,
    local_addr: IpAddr,
}

impl RawSocket {
    /// Create a new raw socket for TCP packets
    pub fn new_tcp() -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        
        // Set socket options
        socket.set_nonblocking(true)?;
        // socket.set_header_included(true)?; // Not available in socket2 0.5
        
        // Get local IP address
        let local_addr = get_local_ip()?;
        
        Ok(Self {
            socket,
            local_addr,
        })
    }
    
    /// Send a TCP SYN packet to the target
    pub fn send_syn_packet(
        &self,
        target: IpAddr,
        target_port: u16,
        source_port: u16,
    ) -> Result<()> {
        let packet = craft_syn_packet(
            self.local_addr,
            target,
            source_port,
            target_port,
        )?;

        let target_addr = SocketAddr::new(target, target_port);
        self.socket.send_to(&packet, &target_addr.into())?;

        Ok(())
    }

    /// Send a TCP ACK packet to the target
    pub fn send_ack_packet(
        &self,
        target: IpAddr,
        target_port: u16,
        source_port: u16,
    ) -> Result<()> {
        let packet = craft_tcp_packet(
            self.local_addr,
            target,
            source_port,
            target_port,
            TcpFlags::ACK,
        )?;

        let target_addr = SocketAddr::new(target, target_port);
        self.socket.send_to(&packet, &target_addr.into())?;

        Ok(())
    }

    /// Send a TCP FIN packet to the target
    pub fn send_fin_packet(
        &self,
        target: IpAddr,
        target_port: u16,
        source_port: u16,
    ) -> Result<()> {
        let packet = craft_tcp_packet(
            self.local_addr,
            target,
            source_port,
            target_port,
            TcpFlags::FIN,
        )?;

        let target_addr = SocketAddr::new(target, target_port);
        self.socket.send_to(&packet, &target_addr.into())?;

        Ok(())
    }

    /// Send a TCP NULL packet to the target (no flags set)
    pub fn send_null_packet(
        &self,
        target: IpAddr,
        target_port: u16,
        source_port: u16,
    ) -> Result<()> {
        let packet = craft_tcp_packet(
            self.local_addr,
            target,
            source_port,
            target_port,
            0, // No flags
        )?;

        let target_addr = SocketAddr::new(target, target_port);
        self.socket.send_to(&packet, &target_addr.into())?;

        Ok(())
    }

    /// Send a TCP Xmas packet to the target (FIN, PSH, URG flags set)
    pub fn send_xmas_packet(
        &self,
        target: IpAddr,
        target_port: u16,
        source_port: u16,
    ) -> Result<()> {
        let packet = craft_tcp_packet(
            self.local_addr,
            target,
            source_port,
            target_port,
            TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
        )?;

        let target_addr = SocketAddr::new(target, target_port);
        self.socket.send_to(&packet, &target_addr.into())?;

        Ok(())
    }
    
    /// Receive a packet from the socket
    pub fn receive_packet(&self, buffer: &mut [u8]) -> Result<usize> {
        use std::mem::MaybeUninit;

        // Ensure buffer is large enough and size is valid
        if buffer.is_empty() {
            return Ok(0);
        }

        let mut uninit_buffer: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); buffer.len()];
        match self.socket.recv(&mut uninit_buffer) {
            Ok(size) => {
                // Safety check: size should not exceed buffer length
                if size > buffer.len() {
                    return Err(anyhow!("Received size {} exceeds buffer length {}", size, buffer.len()));
                }

                // Copy from MaybeUninit to regular buffer
                // Safety: socket.recv() guarantees that bytes 0..size are initialized
                // We explicitly check that size <= buffer.len() above
                for i in 0..size {
                    buffer[i] = unsafe { uninit_buffer[i].assume_init() };
                }
                Ok(size)
            },
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Ok(0) // No data available
            }
            Err(e) => Err(anyhow!("Failed to receive packet: {}", e)),
        }
    }
    
    /// Set receive timeout
    pub fn set_timeout(&self, timeout: Duration) -> Result<()> {
        self.socket.set_read_timeout(Some(timeout))?;
        Ok(())
    }
}

/// Craft a TCP SYN packet
fn craft_syn_packet(
    source_ip: IpAddr,
    dest_ip: IpAddr,
    source_port: u16,
    dest_port: u16,
) -> Result<Vec<u8>> {
    craft_tcp_packet(source_ip, dest_ip, source_port, dest_port, TcpFlags::SYN)
}

/// Craft a generic TCP packet with specified flags
fn craft_tcp_packet(
    source_ip: IpAddr,
    dest_ip: IpAddr,
    source_port: u16,
    dest_port: u16,
    flags: u8,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // Create IP header (20 bytes) + TCP header (20 bytes)
    let mut packet = vec![0u8; 40];

    // Create IPv4 header
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet[..20])
            .ok_or_else(|| anyhow!("Failed to create IP header"))?;

        ip_header.set_version(4);
        ip_header.set_header_length(5); // 5 * 4 = 20 bytes
        ip_header.set_dscp(0);
        ip_header.set_ecn(0);
        ip_header.set_total_length(40); // IP header + TCP header
        ip_header.set_identification(rng.gen());
        ip_header.set_flags(2); // Don't fragment
        ip_header.set_fragment_offset(0);
        ip_header.set_ttl(64);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);

        if let (IpAddr::V4(src), IpAddr::V4(dst)) = (source_ip, dest_ip) {
            ip_header.set_source(src);
            ip_header.set_destination(dst);
        } else {
            return Err(anyhow!("IPv6 not supported yet"));
        }

        // Calculate IP checksum
        let checksum = pnet::packet::ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }

    // Create TCP header
    {
        let mut tcp_header = MutableTcpPacket::new(&mut packet[20..])
            .ok_or_else(|| anyhow!("Failed to create TCP header"))?;

        tcp_header.set_source(source_port);
        tcp_header.set_destination(dest_port);
        tcp_header.set_sequence(rng.gen()); // Random sequence number
        tcp_header.set_acknowledgement(0);
        tcp_header.set_data_offset(5); // 5 * 4 = 20 bytes
        tcp_header.set_reserved(0);
        tcp_header.set_flags(flags);
        tcp_header.set_window(65535);
        tcp_header.set_urgent_ptr(0);

        // Calculate TCP checksum
        if let (IpAddr::V4(src), IpAddr::V4(dst)) = (source_ip, dest_ip) {
            let checksum = pnet::packet::tcp::ipv4_checksum(
                &tcp_header.to_immutable(),
                &src,
                &dst,
            );
            tcp_header.set_checksum(checksum);
        }
    }

    Ok(packet)
}

/// Parse a received TCP packet to check for SYN-ACK response
pub fn parse_tcp_response(packet: &[u8]) -> Result<TcpResponse> {
    // Skip IP header (assume 20 bytes for now)
    if packet.len() < 40 {
        return Err(anyhow!("Packet too short"));
    }
    
    let ip_packet = Ipv4Packet::new(&packet[..20])
        .ok_or_else(|| anyhow!("Invalid IP packet"))?;
    
    let tcp_packet = TcpPacket::new(&packet[20..])
        .ok_or_else(|| anyhow!("Invalid TCP packet"))?;
    
    let response = TcpResponse {
        source_ip: IpAddr::V4(ip_packet.get_source()),
        source_port: tcp_packet.get_source(),
        dest_port: tcp_packet.get_destination(),
        flags: tcp_packet.get_flags(),
        sequence: tcp_packet.get_sequence(),
        acknowledgement: tcp_packet.get_acknowledgement(),
    };
    
    Ok(response)
}

/// TCP response information
#[derive(Debug, Clone)]
pub struct TcpResponse {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub dest_port: u16,
    pub flags: u8,
    pub sequence: u32,
    pub acknowledgement: u32,
}

impl TcpResponse {
    /// Check if this is a SYN-ACK response
    pub fn is_syn_ack(&self) -> bool {
        (self.flags & (TcpFlags::SYN | TcpFlags::ACK)) == (TcpFlags::SYN | TcpFlags::ACK)
    }
    
    /// Check if this is a RST response
    pub fn is_rst(&self) -> bool {
        (self.flags & TcpFlags::RST) != 0
    }
}

/// Get the local IP address for the default route
fn get_local_ip() -> Result<IpAddr> {
    // Simple implementation - in practice, this should determine the best local IP
    // based on the target network
    Ok(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))) // Let the OS choose
}

// Note: check_raw_socket_privileges() has been moved to socket_utils.rs
// to avoid code duplication and is re-exported from lib.rs