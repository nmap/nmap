use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Create a raw socket for packet crafting
pub fn create_raw_socket(protocol: Protocol) -> Result<Socket> {
    let domain = Domain::IPV4; // TODO: Support IPv6
    let socket = Socket::new(domain, Type::STREAM, Some(protocol))?;
    
    // Set socket options
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    
    Ok(socket)
}

/// Create a TCP socket
pub fn create_tcp_socket() -> Result<Socket> {
    let domain = Domain::IPV4; // TODO: Support IPv6
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    
    Ok(socket)
}

/// Create a UDP socket
pub fn create_udp_socket() -> Result<Socket> {
    let domain = Domain::IPV4; // TODO: Support IPv6
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    
    Ok(socket)
}

/// Check if we have the necessary privileges for raw sockets
pub fn check_raw_socket_privileges() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // On Windows, raw sockets require admin privileges or special capabilities
        // This is a simplified check
        false
    }
}

/// Bind socket to a specific interface
pub fn bind_to_interface(socket: &Socket, interface: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        let interface_cstr = CString::new(interface)?;
        socket.bind_device(Some(interface_cstr.as_bytes_with_nul()))?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Interface binding is platform-specific
        // For now, just return success on other platforms
        let _ = interface;
    }
    
    Ok(())
}

/// Set socket timeout
pub fn set_socket_timeout(socket: &Socket, timeout: Duration) -> Result<()> {
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    Ok(())
}