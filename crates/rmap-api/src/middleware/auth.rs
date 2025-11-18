use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::env;

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,      // Subject (user ID)
    pub exp: usize,       // Expiration time
    pub iat: usize,       // Issued at
    pub role: String,     // User role (admin, user, etc.)
}

/// Authentication middleware that validates JWT tokens
pub async fn auth_middleware(
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract Authorization header
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    let auth_header = match auth_header {
        Some(header) => header,
        None => {
            tracing::warn!("Missing Authorization header");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Extract token from "Bearer <token>" format
    let token = match auth_header.strip_prefix("Bearer ") {
        Some(token) => token,
        None => {
            tracing::warn!("Invalid Authorization header format");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Get JWT secret from environment
    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| {
        tracing::warn!("JWT_SECRET not set, using default (INSECURE)");
        "default-secret-change-me".to_string()
    });

    // Validate JWT token
    let validation = Validation::new(Algorithm::HS256);
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    );

    match token_data {
        Ok(data) => {
            // Store claims in request extensions for later use
            req.extensions_mut().insert(data.claims);
            Ok(next.run(req).await)
        }
        Err(err) => {
            tracing::warn!("JWT validation failed: {:?}", err);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Extract claims from request extensions
pub fn extract_claims(req: &Request) -> Option<Claims> {
    req.extensions().get::<Claims>().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_jwt_encoding_decoding() {
        let secret = "test-secret";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: "test-user".to_string(),
            exp: now + 3600,
            iat: now,
            role: "admin".to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let validation = Validation::new(Algorithm::HS256);
        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .unwrap();

        assert_eq!(decoded.claims.sub, "test-user");
        assert_eq!(decoded.claims.role, "admin");
    }
}
