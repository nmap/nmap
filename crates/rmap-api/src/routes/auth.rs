use axum::{http::StatusCode, Json};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::middleware::Claims;

/// Login request payload
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Register request payload
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
}

/// Auth response with JWT token
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires_in: usize,
    pub user: UserInfo,
}

/// User information
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub username: String,
    pub role: String,
}

/// Login endpoint
///
/// For demo purposes, this validates against environment variables:
/// - API_USERNAME (default: "admin")
/// - API_PASSWORD_HASH (bcrypt hash, default: "admin")
pub async fn login(
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    tracing::info!("Login attempt for user: {}", payload.username);

    // Get credentials from environment (in production, use a database)
    let valid_username = env::var("API_USERNAME").unwrap_or_else(|_| "admin".to_string());
    let password_hash = env::var("API_PASSWORD_HASH").unwrap_or_else(|_| {
        // Default hash for password "admin"
        "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYKKVrCHfQu".to_string()
    });

    // Validate username
    if payload.username != valid_username {
        tracing::warn!("Invalid username: {}", payload.username);
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Validate password
    match verify(&payload.password, &password_hash) {
        Ok(valid) => {
            if !valid {
                tracing::warn!("Invalid password for user: {}", payload.username);
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        Err(err) => {
            tracing::error!("Password verification error: {:?}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    // Generate JWT token
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize;

    let expires_in = 3600; // 1 hour
    let claims = Claims {
        sub: payload.username.clone(),
        exp: now + expires_in,
        iat: now,
        role: "admin".to_string(), // In production, fetch from database
    };

    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| {
        tracing::warn!("JWT_SECRET not set, using default (INSECURE)");
        "default-secret-change-me".to_string()
    });

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|err| {
        tracing::error!("Failed to encode JWT: {:?}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!("Login successful for user: {}", payload.username);

    Ok(Json(AuthResponse {
        token,
        expires_in,
        user: UserInfo {
            username: payload.username,
            role: claims.role,
        },
    }))
}

/// Register endpoint (optional - for demo/testing)
///
/// This is a simplified registration that just returns success.
/// In production, this would store the user in a database.
pub async fn register(
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    tracing::info!("Registration attempt for user: {}", payload.username);

    // Validate input
    if payload.username.is_empty() || payload.password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Hash password
    let password_hash = hash(&payload.password, DEFAULT_COST).map_err(|err| {
        tracing::error!("Failed to hash password: {:?}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!("Registration successful for user: {}", payload.username);
    tracing::info!("Password hash (store this as API_PASSWORD_HASH): {}", password_hash);

    Ok(Json(serde_json::json!({
        "message": "Registration successful",
        "username": payload.username,
        "password_hash": password_hash,
        "note": "In production, store this hash in a database. For testing, set API_PASSWORD_HASH environment variable."
    })))
}

/// Utility function to generate a password hash
/// This can be used to pre-generate hashes for API_PASSWORD_HASH
pub fn generate_password_hash(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "test-password-123";
        let hash = generate_password_hash(password).unwrap();
        assert!(verify(password, &hash).unwrap());
        assert!(!verify("wrong-password", &hash).unwrap());
    }

    #[test]
    fn test_default_admin_password() {
        // Test that "admin" matches the default hash
        let default_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYKKVrCHfQu";
        assert!(verify("admin", default_hash).unwrap());
    }
}
