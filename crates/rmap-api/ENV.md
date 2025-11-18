# R-Map API Environment Variables

This document describes the environment variables used by the R-Map API server for security configuration.

## Security Configuration

### JWT_SECRET (Required for Production)

**Description:** Secret key used to sign and verify JWT tokens.

**Default:** `default-secret-change-me` (INSECURE - only for development)

**Production Setup:**
```bash
# Generate a secure random secret (Linux/macOS)
export JWT_SECRET=$(openssl rand -base64 32)

# Or use a strong password
export JWT_SECRET="your-very-long-and-secure-secret-key-here"
```

**Security Notes:**
- Must be at least 32 characters long
- Should be randomly generated
- Keep this secret secure - anyone with this key can forge valid tokens
- Never commit this to version control
- Rotate regularly in production

---

### API_USERNAME (Optional)

**Description:** Username for API authentication.

**Default:** `admin`

**Setup:**
```bash
export API_USERNAME="your-username"
```

---

### API_PASSWORD_HASH (Optional)

**Description:** Bcrypt hash of the API password.

**Default:** `$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYKKVrCHfQu` (hash of "admin")

**Generate a New Hash:**

1. Using the API register endpoint:
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-secure-password"
  }'
```

2. Using Rust code:
```rust
use bcrypt::{hash, DEFAULT_COST};

fn main() {
    let password = "your-secure-password";
    let hash = hash(password, DEFAULT_COST).unwrap();
    println!("Password hash: {}", hash);
}
```

3. Using online bcrypt generator (use trusted sources only):
   - https://bcrypt-generator.com/ (rounds = 12)

**Setup:**
```bash
export API_PASSWORD_HASH='$2b$12$...'
```

**Security Notes:**
- Always use bcrypt cost factor of 12 or higher
- Never store plaintext passwords
- The hash contains the salt, so it's safe to store

---

## Complete Production Setup Example

```bash
# 1. Generate secure JWT secret
export JWT_SECRET=$(openssl rand -base64 32)

# 2. Set your username
export API_USERNAME="admin"

# 3. Generate password hash (use register endpoint or Rust code)
# Example hash for password "MySecureP@ssw0rd!"
export API_PASSWORD_HASH='$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYKKVrCHfQu'

# 4. Start the server
cd /home/user/R-map/crates/rmap-api
cargo run --release
```

---

## Environment Files

### Development (.env.development)
```bash
# Development environment - INSECURE, DO NOT USE IN PRODUCTION
JWT_SECRET=dev-secret-change-in-production
API_USERNAME=admin
API_PASSWORD_HASH=$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYKKVrCHfQu
```

### Production (.env.production)
```bash
# Production environment
JWT_SECRET=<generate-with-openssl-rand>
API_USERNAME=<your-secure-username>
API_PASSWORD_HASH=<bcrypt-hash-of-secure-password>
```

**Important:**
- Add `.env*` to `.gitignore`
- Never commit environment files with secrets
- Use a secrets management service in production (e.g., AWS Secrets Manager, HashiCorp Vault)

---

## Testing Authentication

### 1. Login to Get JWT Token
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin"
  }'
```

**Response:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_in": 3600,
  "user": {
    "username": "admin",
    "role": "admin"
  }
}
```

### 2. Use Token for Protected Endpoints
```bash
# Set token as environment variable
export TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# Make authenticated request
curl -X GET http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Test Without Token (Should Fail)
```bash
curl -X GET http://localhost:8080/api/v1/scans
# Expected: 401 Unauthorized
```

---

## Rate Limiting

The API implements the following rate limits per IP address:

| Endpoint Type | Rate Limit | Burst Size |
|--------------|------------|------------|
| General API | 10 requests/second | 10 |
| Scan Creation/Start | 2 requests/minute | 2 |
| WebSocket Connections | 5 connections/minute | 5 |

**Testing Rate Limits:**
```bash
# This should fail after 10 requests in quick succession
for i in {1..15}; do
  curl -X GET http://localhost:8080/health
done
```

---

## CORS Configuration

The API allows requests from:
- `http://localhost:3000` (Node-RED)
- `http://localhost:5173` (Svelte dev server)
- `http://127.0.0.1:3000`
- `http://127.0.0.1:5173`

**Allowed Methods:** GET, POST, DELETE, PUT, PATCH

**Allowed Headers:** Content-Type, Authorization

**Credentials:** Enabled

To add more origins, modify `src/main.rs`:
```rust
let cors = CorsLayer::new()
    .allow_origin("http://your-domain.com".parse::<HeaderValue>().unwrap())
    // ... other origins
```

---

## Security Checklist for Production

- [ ] Set strong `JWT_SECRET` (minimum 32 characters)
- [ ] Change default username/password
- [ ] Use bcrypt hash with cost factor ≥ 12
- [ ] Enable HTTPS/TLS (use reverse proxy like nginx)
- [ ] Configure firewall to restrict access
- [ ] Implement IP whitelisting if needed
- [ ] Set up logging and monitoring
- [ ] Regular security audits
- [ ] Keep dependencies updated
- [ ] Use secrets management service
- [ ] Implement proper database instead of environment variables
- [ ] Add refresh token mechanism
- [ ] Implement account lockout after failed attempts
- [ ] Add audit logging for all actions

---

## Future Improvements

For production use, consider implementing:

1. **Database-backed authentication** - Replace environment variables with PostgreSQL/MySQL
2. **Refresh tokens** - Implement token refresh mechanism
3. **Role-based access control (RBAC)** - Different permissions for different users
4. **OAuth2/OIDC** - Integration with enterprise identity providers
5. **Multi-factor authentication (MFA)** - Enhanced security
6. **Account management** - Password reset, email verification, etc.
7. **Session management** - Track and revoke active sessions
8. **Audit logging** - Comprehensive audit trail
9. **API key authentication** - Alternative to JWT for service-to-service
10. **Rate limiting per user** - Currently limited by IP only
