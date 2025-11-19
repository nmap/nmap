use std::fmt;

pub type Result<T> = std::result::Result<T, NmapError>;

#[derive(Debug)]
pub enum NmapError {
    /// Network-related errors
    Network(String),
    /// Target parsing errors
    InvalidTarget(String),
    /// Port specification errors
    InvalidPortSpec(String),
    /// Permission/privilege errors
    Permission(String),
    /// Configuration errors
    Config(String),
    /// I/O errors
    Io(std::io::Error),
    /// Parsing errors
    Parse(String),
    /// Timeout errors
    Timeout(String),
    /// Generic errors
    Other(String),
    /// Insufficient privileges (e.g., raw socket access)
    InsufficientPrivileges(String),
    /// Socket creation failed
    SocketCreationFailed,
    /// Socket configuration failed
    SocketConfigurationFailed,
    /// Packet creation failed
    PacketCreationFailed,
    /// Send failed
    SendFailed,
    /// Connection failed
    ConnectionFailed,
    /// No response received
    NoResponse,
    /// Insufficient data
    InsufficientData,
    /// Invalid packet
    InvalidPacket,
}

impl fmt::Display for NmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NmapError::Network(msg) => write!(f, "Network error: {}", msg),
            NmapError::InvalidTarget(msg) => write!(f, "Invalid target: {}", msg),
            NmapError::InvalidPortSpec(msg) => write!(f, "Invalid port specification: {}", msg),
            NmapError::Permission(msg) => write!(f, "Permission error: {}", msg),
            NmapError::Config(msg) => write!(f, "Configuration error: {}", msg),
            NmapError::Io(err) => write!(f, "I/O error: {}", err),
            NmapError::Parse(msg) => write!(f, "Parse error: {}", msg),
            NmapError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            NmapError::Other(msg) => write!(f, "Error: {}", msg),
            NmapError::InsufficientPrivileges(msg) => write!(f, "Insufficient privileges: {}", msg),
            NmapError::SocketCreationFailed => write!(f, "Socket creation failed"),
            NmapError::SocketConfigurationFailed => write!(f, "Socket configuration failed"),
            NmapError::PacketCreationFailed => write!(f, "Packet creation failed"),
            NmapError::SendFailed => write!(f, "Send operation failed"),
            NmapError::ConnectionFailed => write!(f, "Connection failed"),
            NmapError::NoResponse => write!(f, "No response received"),
            NmapError::InsufficientData => write!(f, "Insufficient data"),
            NmapError::InvalidPacket => write!(f, "Invalid packet"),
        }
    }
}

impl std::error::Error for NmapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NmapError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for NmapError {
    fn from(err: std::io::Error) -> Self {
        NmapError::Io(err)
    }
}

impl From<anyhow::Error> for NmapError {
    fn from(err: anyhow::Error) -> Self {
        NmapError::Other(err.to_string())
    }
}