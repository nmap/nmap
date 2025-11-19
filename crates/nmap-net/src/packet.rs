use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Raw packet crafting utilities for R-Map
/// This replaces the need for libpcap/libdnet C dependencies

#[derive(Debug, Clone)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
}

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

#[derive(Debug, Clone)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest_of_header: u32,
}

impl Default for TcpFlags {
    fn default() -> Self {
        Self {
            fin: false,
            syn: false,
            rst: false,
            psh: false,
            ack: false,
            urg: false,
            ece: false,
            cwr: false,
        }
    }
}

impl TcpFlags {
    pub fn syn() -> Self {
        Self {
            syn: true,
            ..Default::default()
        }
    }

    pub fn syn_ack() -> Self {
        Self {
            syn: true,
            ack: true,
            ..Default::default()
        }
    }

    pub fn ack() -> Self {
        Self {
            ack: true,
            ..Default::default()
        }
    }

    pub fn rst() -> Self {
        Self {
            rst: true,
            ..Default::default()
        }
    }

    pub fn to_u8(&self) -> u8 {
        let mut flags = 0u8;
        if self.fin { flags |= 0x01; }
        if self.syn { flags |= 0x02; }
        if self.rst { flags |= 0x04; }
        if self.psh { flags |= 0x08; }
        if self.ack { flags |= 0x10; }
        if self.urg { flags |= 0x20; }
        if self.ece { flags |= 0x40; }
        if self.cwr { flags |= 0x80; }
        flags
    }
}

impl Ipv4Header {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8) -> Self {
        Self {
            version: 4,
            ihl: 5,
            tos: 0,
            total_length: 0, // Will be calculated
            identification: rand::random(),
            flags: 0x40, // Don't fragment
            fragment_offset: 0,
            ttl: 64,
            protocol,
            checksum: 0, // Will be calculated
            src_addr: src,
            dst_addr: dst,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);
        
        bytes.push((self.version << 4) | self.ihl);
        bytes.push(self.tos);
        bytes.extend_from_slice(&self.total_length.to_be_bytes());
        bytes.extend_from_slice(&self.identification.to_be_bytes());
        bytes.extend_from_slice(&((self.flags as u16) << 13 | self.fragment_offset).to_be_bytes());
        bytes.push(self.ttl);
        bytes.push(self.protocol);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.src_addr.octets());
        bytes.extend_from_slice(&self.dst_addr.octets());
        
        bytes
    }

    pub fn calculate_checksum(&mut self) {
        self.checksum = 0;
        let bytes = self.to_bytes();
        self.checksum = calculate_checksum(&bytes);
    }
}

impl TcpHeader {
    pub fn new(src_port: u16, dst_port: u16, flags: TcpFlags) -> Self {
        Self {
            src_port,
            dst_port,
            seq_num: rand::random(),
            ack_num: 0,
            data_offset: 5, // 20 bytes
            flags,
            window_size: 65535,
            checksum: 0, // Will be calculated
            urgent_ptr: 0,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);
        
        bytes.extend_from_slice(&self.src_port.to_be_bytes());
        bytes.extend_from_slice(&self.dst_port.to_be_bytes());
        bytes.extend_from_slice(&self.seq_num.to_be_bytes());
        bytes.extend_from_slice(&self.ack_num.to_be_bytes());
        bytes.push((self.data_offset << 4) | 0); // Reserved bits
        bytes.push(self.flags.to_u8());
        bytes.extend_from_slice(&self.window_size.to_be_bytes());
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.urgent_ptr.to_be_bytes());
        
        bytes
    }

    pub fn calculate_checksum(&mut self, src_ip: IpAddr, dst_ip: IpAddr, payload: &[u8]) {
        self.checksum = 0;
        let tcp_bytes = self.to_bytes();
        
        // Create pseudo header for checksum calculation
        let mut pseudo_header = Vec::new();
        
        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                pseudo_header.extend_from_slice(&src.octets());
                pseudo_header.extend_from_slice(&dst.octets());
                pseudo_header.push(0); // Reserved
                pseudo_header.push(6); // TCP protocol
                pseudo_header.extend_from_slice(&((tcp_bytes.len() + payload.len()) as u16).to_be_bytes());
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                pseudo_header.extend_from_slice(&src.octets());
                pseudo_header.extend_from_slice(&dst.octets());
                pseudo_header.extend_from_slice(&((tcp_bytes.len() + payload.len()) as u32).to_be_bytes());
                pseudo_header.extend_from_slice(&[0, 0, 0, 6]); // Next header = TCP
            }
            _ => return, // Mixed IP versions not supported
        }
        
        pseudo_header.extend_from_slice(&tcp_bytes);
        pseudo_header.extend_from_slice(payload);
        
        self.checksum = calculate_checksum(&pseudo_header);
    }
}

impl UdpHeader {
    pub fn new(src_port: u16, dst_port: u16, payload_len: u16) -> Self {
        Self {
            src_port,
            dst_port,
            length: 8 + payload_len,
            checksum: 0, // Will be calculated
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8);
        
        bytes.extend_from_slice(&self.src_port.to_be_bytes());
        bytes.extend_from_slice(&self.dst_port.to_be_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        
        bytes
    }

    pub fn calculate_checksum(&mut self, src_ip: IpAddr, dst_ip: IpAddr, payload: &[u8]) {
        self.checksum = 0;
        let udp_bytes = self.to_bytes();
        
        // Create pseudo header for checksum calculation
        let mut pseudo_header = Vec::new();
        
        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                pseudo_header.extend_from_slice(&src.octets());
                pseudo_header.extend_from_slice(&dst.octets());
                pseudo_header.push(0); // Reserved
                pseudo_header.push(17); // UDP protocol
                pseudo_header.extend_from_slice(&self.length.to_be_bytes());
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                pseudo_header.extend_from_slice(&src.octets());
                pseudo_header.extend_from_slice(&dst.octets());
                pseudo_header.extend_from_slice(&(self.length as u32).to_be_bytes());
                pseudo_header.extend_from_slice(&[0, 0, 0, 17]); // Next header = UDP
            }
            _ => return, // Mixed IP versions not supported
        }
        
        pseudo_header.extend_from_slice(&udp_bytes);
        pseudo_header.extend_from_slice(payload);
        
        self.checksum = calculate_checksum(&pseudo_header);
    }
}

impl IcmpHeader {
    pub fn echo_request(id: u16, seq: u16) -> Self {
        Self {
            icmp_type: 8, // Echo Request
            code: 0,
            checksum: 0, // Will be calculated
            rest_of_header: ((id as u32) << 16) | (seq as u32),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8);
        
        bytes.push(self.icmp_type);
        bytes.push(self.code);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.rest_of_header.to_be_bytes());
        
        bytes
    }

    pub fn calculate_checksum(&mut self, payload: &[u8]) {
        self.checksum = 0;
        let mut data = self.to_bytes();
        data.extend_from_slice(payload);
        self.checksum = calculate_checksum(&data);
    }
}

/// Calculate Internet checksum (RFC 1071)
pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    
    // Sum all 16-bit words
    for chunk in data.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    
    // Add the odd byte if present
    if data.len() % 2 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }
    
    // Add carry bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // One's complement
    !(sum as u16)
}

/// Packet builder for creating raw network packets
pub struct PacketBuilder {
    buffer: Vec<u8>,
}

impl PacketBuilder {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    pub fn add_ipv4_header(&mut self, mut header: Ipv4Header) -> &mut Self {
        header.total_length = (self.buffer.len() + 20) as u16; // Will be updated later
        header.calculate_checksum();
        self.buffer.extend_from_slice(&header.to_bytes());
        self
    }

    pub fn add_tcp_header(&mut self, mut header: TcpHeader, src_ip: IpAddr, dst_ip: IpAddr, payload: &[u8]) -> &mut Self {
        header.calculate_checksum(src_ip, dst_ip, payload);
        self.buffer.extend_from_slice(&header.to_bytes());
        self
    }

    pub fn add_udp_header(&mut self, mut header: UdpHeader, src_ip: IpAddr, dst_ip: IpAddr, payload: &[u8]) -> &mut Self {
        header.calculate_checksum(src_ip, dst_ip, payload);
        self.buffer.extend_from_slice(&header.to_bytes());
        self
    }

    pub fn add_icmp_header(&mut self, mut header: IcmpHeader, payload: &[u8]) -> &mut Self {
        header.calculate_checksum(payload);
        self.buffer.extend_from_slice(&header.to_bytes());
        self
    }

    pub fn add_payload(&mut self, payload: &[u8]) -> &mut Self {
        self.buffer.extend_from_slice(payload);
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.buffer
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for PacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_tcp_syn_packet() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        
        let ip_header = Ipv4Header::new(src_ip, dst_ip, 6); // TCP
        let tcp_header = TcpHeader::new(12345, 80, TcpFlags::syn());
        
        let mut builder = PacketBuilder::new();
        let packet = builder
            .add_ipv4_header(ip_header)
            .add_tcp_header(tcp_header, IpAddr::V4(src_ip), IpAddr::V4(dst_ip), &[])
            .build();
        
        assert_eq!(packet.len(), 40); // 20 bytes IP + 20 bytes TCP
        assert_eq!(packet[0] >> 4, 4); // IPv4
        assert_eq!(packet[9], 6); // TCP protocol
    }

    #[test]
    fn test_checksum_calculation() {
        let data = vec![0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c];
        let checksum = calculate_checksum(&data);
        // This should produce a valid checksum for the test data
        assert_ne!(checksum, 0);
    }
}