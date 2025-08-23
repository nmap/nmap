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