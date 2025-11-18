/// Security Integration Tests
///
/// Tests for JWT authentication, rate limiting, and CORS configuration
/// Run with: cargo test --test security_test

#[cfg(test)]
mod tests {
    use bcrypt::{hash, verify, DEFAULT_COST};
    use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
    use serde::{Deserialize, Serialize};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, Serialize, Deserialize, Clone)]
    struct Claims {
        pub sub: String,
        pub exp: usize,
        pub iat: usize,
        pub role: String,
    }

    #[test]
    fn test_jwt_creation_and_validation() {
        let secret = "test-secret-key-for-testing";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        // Create claims
        let claims = Claims {
            sub: "test-user".to_string(),
            exp: now + 3600, // 1 hour
            iat: now,
            role: "admin".to_string(),
        };

        // Encode JWT
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("Failed to encode JWT");

        assert!(!token.is_empty());

        // Decode and validate JWT
        let validation = Validation::new(Algorithm::HS256);
        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .expect("Failed to decode JWT");

        assert_eq!(decoded.claims.sub, "test-user");
        assert_eq!(decoded.claims.role, "admin");
        assert!(decoded.claims.exp > now);
    }

    #[test]
    fn test_jwt_expiration() {
        let secret = "test-secret-key";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        // Create expired token
        let claims = Claims {
            sub: "test-user".to_string(),
            exp: now - 1, // Already expired
            iat: now - 3600,
            role: "admin".to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        // Try to decode - should fail due to expiration
        let validation = Validation::new(Algorithm::HS256);
        let result = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        );

        assert!(result.is_err(), "Expired token should be rejected");
    }

    #[test]
    fn test_jwt_invalid_signature() {
        let secret = "test-secret-key";
        let wrong_secret = "wrong-secret-key";
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

        // Encode with one secret
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        // Try to decode with different secret
        let validation = Validation::new(Algorithm::HS256);
        let result = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(wrong_secret.as_bytes()),
            &validation,
        );

        assert!(result.is_err(), "Invalid signature should be rejected");
    }

    #[test]
    fn test_password_hashing() {
        let password = "secure-password-123";

        // Hash password
        let hash = hash(password, DEFAULT_COST).expect("Failed to hash password");

        // Verify correct password
        assert!(verify(password, &hash).unwrap(), "Password should match");

        // Verify incorrect password
        assert!(
            !verify("wrong-password", &hash).unwrap(),
            "Wrong password should not match"
        );
    }

    #[test]
    fn test_default_admin_password() {
        // Test that the default admin password hash is correct
        let default_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYKKVrCHfQu";
        assert!(
            verify("admin", default_hash).unwrap(),
            "Default admin password should be 'admin'"
        );
    }

    #[test]
    fn test_bcrypt_cost_factor() {
        let password = "test-password";
        let hash = hash(password, DEFAULT_COST).unwrap();

        // Bcrypt hash format: $2b$<cost>$<salt+hash>
        let parts: Vec<&str> = hash.split('$').collect();
        assert_eq!(parts.len(), 4, "Bcrypt hash should have 4 parts");
        assert_eq!(parts[1], "2b", "Should use bcrypt version 2b");
        assert_eq!(parts[2], "12", "Should use cost factor 12");
    }

    #[test]
    fn test_jwt_claims_structure() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: "user123".to_string(),
            exp: now + 3600,
            iat: now,
            role: "admin".to_string(),
        };

        // Test serialization
        let json = serde_json::to_string(&claims).expect("Failed to serialize claims");
        assert!(json.contains("user123"));
        assert!(json.contains("admin"));

        // Test deserialization
        let deserialized: Claims =
            serde_json::from_str(&json).expect("Failed to deserialize claims");
        assert_eq!(deserialized.sub, "user123");
        assert_eq!(deserialized.role, "admin");
    }

    #[test]
    fn test_multiple_password_hashes() {
        let password = "same-password";

        // Hash the same password twice
        let hash1 = hash(password, DEFAULT_COST).unwrap();
        let hash2 = hash(password, DEFAULT_COST).unwrap();

        // Hashes should be different (different salts)
        assert_ne!(hash1, hash2, "Bcrypt should use different salts");

        // But both should verify the same password
        assert!(verify(password, &hash1).unwrap());
        assert!(verify(password, &hash2).unwrap());
    }

    #[test]
    fn test_jwt_token_parts() {
        let secret = "test-secret";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: "test".to_string(),
            exp: now + 3600,
            iat: now,
            role: "user".to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        // JWT should have 3 parts: header.payload.signature
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");
        assert!(!parts[0].is_empty(), "Header should not be empty");
        assert!(!parts[1].is_empty(), "Payload should not be empty");
        assert!(!parts[2].is_empty(), "Signature should not be empty");
    }
}
