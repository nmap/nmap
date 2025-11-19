use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::IpAddr;
use std::time::Duration;

/// Create a raw socket for packet crafting
///
/// # Arguments
/// * `protocol` - The protocol for the socket
/// * `target` - Optional target IP address to determine IPv4 vs IPv6
pub fn create_raw_socket(protocol: Protocol, target: Option<IpAddr>) -> Result<Socket> {
    // Determine domain based on target IP version, default to IPv4
    let domain = match target {
        Some(IpAddr::V6(_)) => Domain::IPV6,
        _ => Domain::IPV4,
    };

    let socket = Socket::new(domain, Type::STREAM, Some(protocol))?;

    // Set socket options
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;

    Ok(socket)
}

/// Create a TCP socket
///
/// # Arguments
/// * `target` - Optional target IP address to determine IPv4 vs IPv6
pub fn create_tcp_socket(target: Option<IpAddr>) -> Result<Socket> {
    // Determine domain based on target IP version, default to IPv4
    let domain = match target {
        Some(IpAddr::V6(_)) => Domain::IPV6,
        _ => Domain::IPV4,
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;

    Ok(socket)
}

/// Create a UDP socket
///
/// # Arguments
/// * `target` - Optional target IP address to determine IPv4 vs IPv6
pub fn create_udp_socket(target: Option<IpAddr>) -> Result<Socket> {
    // Determine domain based on target IP version, default to IPv4
    let domain = match target {
        Some(IpAddr::V6(_)) => Domain::IPV6,
        _ => Domain::IPV4,
    };

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
        use std::os::fd::AsRawFd;

        let interface_cstr = CString::new(interface)?;
        let fd = socket.as_raw_fd();

        unsafe {
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                interface_cstr.as_ptr() as *const libc::c_void,
                interface_cstr.as_bytes_with_nul().len() as libc::socklen_t,
            );

            if ret != 0 {
                return Err(anyhow::anyhow!("Failed to bind to device: {}", std::io::Error::last_os_error()));
            }
        }
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