use axum::extract::ConnectInfo;
use std::net::SocketAddr;
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::{KeyExtractor, SmartIpKeyExtractor},
    GovernorError, GovernorLayer,
};

/// Rate limiter configuration for general API endpoints
/// Allows 10 requests per minute per IP address
pub fn api_rate_limiter() -> GovernorLayer<'static, SmartIpKeyExtractor> {
    let config = Box::new(
        GovernorConfigBuilder::default()
            .per_second(10)
            .burst_size(10)
            .finish()
            .expect("Failed to build rate limiter config"),
    );

    GovernorLayer {
        config: Box::leak(config),
    }
}

/// Strict rate limiter for scan creation endpoints
/// Allows 2 requests per minute per IP address
pub fn scan_rate_limiter() -> GovernorLayer<'static, SmartIpKeyExtractor> {
    let config = Box::new(
        GovernorConfigBuilder::default()
            .per_minute(2)
            .burst_size(2)
            .finish()
            .expect("Failed to build strict rate limiter config"),
    );

    GovernorLayer {
        config: Box::leak(config),
    }
}

/// WebSocket connection rate limiter
/// Allows 5 connections per minute per IP address
pub fn websocket_rate_limiter() -> GovernorLayer<'static, SmartIpKeyExtractor> {
    let config = Box::new(
        GovernorConfigBuilder::default()
            .per_minute(5)
            .burst_size(5)
            .finish()
            .expect("Failed to build websocket rate limiter config"),
    );

    GovernorLayer {
        config: Box::leak(config),
    }
}

/// Custom IP extractor for rate limiting
/// Extracts IP address from ConnectInfo or X-Forwarded-For header
#[derive(Clone, Copy, Debug)]
pub struct IpExtractor;

impl KeyExtractor for IpExtractor {
    type Key = SocketAddr;

    fn extract<B>(&self, req: &axum::http::Request<B>) -> Result<Self::Key, GovernorError> {
        // Try to get IP from ConnectInfo extension
        if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
            return Ok(*addr);
        }

        // Fallback: try X-Forwarded-For header (for reverse proxies)
        if let Some(forwarded) = req.headers().get("x-forwarded-for") {
            if let Ok(forwarded_str) = forwarded.to_str() {
                if let Some(ip_str) = forwarded_str.split(',').next() {
                    if let Ok(ip) = ip_str.trim().parse() {
                        return Ok(SocketAddr::new(ip, 0));
                    }
                }
            }
        }

        // Default fallback
        Err(GovernorError::UnableToExtractKey)
    }

    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some(key.ip().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_creation() {
        // Just ensure rate limiters can be created without panicking
        let _api = api_rate_limiter();
        let _scan = scan_rate_limiter();
        let _ws = websocket_rate_limiter();
    }
}
