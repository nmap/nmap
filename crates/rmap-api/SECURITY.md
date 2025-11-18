# R-Map API Security Guide

## Overview

The R-Map API server has been hardened with enterprise-grade security features:

✅ **JWT Authentication** - All scan endpoints require valid JWT tokens
✅ **Rate Limiting** - Protection against DoS and brute force attacks
✅ **Secure CORS** - Restricted to specific frontend origins
✅ **Password Hashing** - Bcrypt with cost factor 12
✅ **Environment-based Configuration** - Secrets never hardcoded

---

## Quick Start

### 1. Install and Run (Development)

```bash
# Navigate to API directory
cd /home/user/R-map/crates/rmap-api

# Build and run
cargo build
cargo run
```

**Default credentials (INSECURE - change for production):**
- Username: `admin`
- Password: `admin`

### 2. Login to Get JWT Token

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
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTczMTk2MTIwMCwiaWF0IjoxNzMxOTU3NjAwLCJyb2xlIjoiYWRtaW4ifQ.signature",
  "expires_in": 3600,
  "user": {
    "username": "admin",
    "role": "admin"
  }
}
```

### 3. Use Token for API Requests

```bash
# Save token to environment variable
export TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# Create a scan (requires authentication)
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Network Scan",
    "targets": ["192.168.1.0/24"],
    "scan_type": "quick"
  }'

# List scans
curl -X GET http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN"
```

---

## Production Setup

### Step 1: Generate Secure JWT Secret

```bash
# Generate random secret (32+ characters)
export JWT_SECRET=$(openssl rand -base64 32)

# Example output: "8zVx5KmF9Lp2Qs3Rt7Yw1Ea4Bc6Nd0Hj="
```

### Step 2: Create Secure Password

```bash
# Method 1: Use the register endpoint
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "YourSecureP@ssw0rd123!"
  }'

# Copy the "password_hash" from the response
```

**Response:**
```json
{
  "message": "Registration successful",
  "username": "admin",
  "password_hash": "$2b$12$abc123...",
  "note": "Store this hash in API_PASSWORD_HASH environment variable"
}
```

### Step 3: Configure Environment

```bash
# Set environment variables
export JWT_SECRET="8zVx5KmF9Lp2Qs3Rt7Yw1Ea4Bc6Nd0Hj="
export API_USERNAME="admin"
export API_PASSWORD_HASH='$2b$12$abc123...'

# Run the server
cargo run --release
```

### Step 4: Create .env File (Optional)

```bash
# Create .env file (DO NOT COMMIT TO GIT)
cat > .env << EOF
JWT_SECRET=$(openssl rand -base64 32)
API_USERNAME=admin
API_PASSWORD_HASH=\$2b\$12\$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYKKVrCHfQu
EOF

# Add to .gitignore
echo ".env" >> .gitignore
```

---

## Security Features Explained

### 1. JWT Authentication

**What it protects:** All scan-related endpoints
**How it works:**
- User logs in with username/password
- Server returns JWT token (valid for 1 hour)
- Client includes token in `Authorization: Bearer <token>` header
- Server validates token signature and expiration

**Protected endpoints:**
- `POST /api/v1/scans` - Create scan
- `GET /api/v1/scans` - List scans
- `GET /api/v1/scans/:id` - Get scan details
- `DELETE /api/v1/scans/:id` - Delete scan
- `POST /api/v1/scans/:id/start` - Start scan
- `GET /api/v1/scans/:id/hosts` - Get hosts
- `GET /api/v1/hosts/:id` - Get host details
- `GET /api/v1/scans/:id/vulnerabilities` - Get vulnerabilities
- `WS /ws` - WebSocket connection

**Public endpoints (no auth required):**
- `GET /health` - Health check
- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/register` - Register (demo)

### 2. Rate Limiting

**General API endpoints:** 10 requests/second per IP
**Scan creation/start:** 2 requests/minute per IP
**WebSocket connections:** 5 connections/minute per IP

**How it works:**
- Uses token bucket algorithm
- Limits based on source IP address
- Returns `429 Too Many Requests` when limit exceeded

**Testing rate limits:**
```bash
# This will be rate limited after 10 requests
for i in {1..15}; do
  curl http://localhost:8080/health
  sleep 0.1
done
```

### 3. CORS Configuration

**Before (INSECURE):**
```rust
.allow_origin(Any)  // ❌ Allows requests from ANY domain
```

**After (SECURE):**
```rust
.allow_origin("http://localhost:3000".parse().unwrap())
.allow_origin("http://localhost:5173".parse().unwrap())
// Only allows specific domains
```

**Allowed origins:**
- `http://localhost:3000` - Node-RED
- `http://localhost:5173` - Svelte dev server
- `http://127.0.0.1:3000`
- `http://127.0.0.1:5173`

**Allowed methods:** GET, POST, DELETE, PUT, PATCH
**Allowed headers:** Content-Type, Authorization
**Credentials:** Enabled

---

## API Testing Examples

### Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'
```

### Create Scan (Authenticated)
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Security Audit",
    "targets": ["10.0.0.1", "10.0.0.2"],
    "scan_type": "comprehensive"
  }'
```

### Start Scan
```bash
curl -X POST http://localhost:8080/api/v1/scans/{scan_id}/start \
  -H "Authorization: Bearer $TOKEN"
```

### Get Scan Results
```bash
curl -X GET http://localhost:8080/api/v1/scans/{scan_id} \
  -H "Authorization: Bearer $TOKEN"
```

### WebSocket Connection
```javascript
const ws = new WebSocket('ws://localhost:8080/ws', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});

ws.onmessage = (event) => {
  console.log('Scan update:', JSON.parse(event.data));
};
```

---

## Security Best Practices

### Development
- ✅ Use default credentials (`admin`/`admin`) for local testing only
- ✅ Keep `JWT_SECRET` in environment variables, never in code
- ✅ Test rate limiting to ensure it works correctly
- ✅ Verify CORS only allows your frontend origins

### Production
- 🔒 **NEVER** use default credentials in production
- 🔒 Generate strong random `JWT_SECRET` (32+ characters)
- 🔒 Use complex passwords (12+ characters, mixed case, symbols)
- 🔒 Enable HTTPS/TLS (use nginx reverse proxy)
- 🔒 Rotate JWT secret regularly
- 🔒 Implement proper user database (replace environment vars)
- 🔒 Add audit logging for security events
- 🔒 Monitor for suspicious activity
- 🔒 Keep dependencies updated (`cargo update`)
- 🔒 Use secrets management (AWS Secrets Manager, Vault)

### Common Mistakes to Avoid
- ❌ Committing `.env` files to git
- ❌ Using `Any` for CORS origins
- ❌ Storing passwords in plaintext
- ❌ Skipping authentication for "internal" endpoints
- ❌ Not implementing rate limiting
- ❌ Using weak JWT secrets

---

## Troubleshooting

### "401 Unauthorized" Error
**Cause:** Missing or invalid JWT token

**Solution:**
```bash
# 1. Login to get a new token
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' \
  | jq -r '.token')

# 2. Use the token
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/scans
```

### "429 Too Many Requests" Error
**Cause:** Rate limit exceeded

**Solution:** Wait for the rate limit window to expire (1 minute for scans, 1 second for general API)

### CORS Error in Browser
**Cause:** Frontend origin not in allowed list

**Solution:** Add your frontend URL to CORS configuration in `src/main.rs`:
```rust
.allow_origin("http://your-frontend.com".parse::<HeaderValue>().unwrap())
```

### "JWT_SECRET not set" Warning
**Cause:** Environment variable not configured

**Solution:**
```bash
export JWT_SECRET=$(openssl rand -base64 32)
```

---

## Migration Guide

### Updating Existing Installations

If you have an existing R-Map API installation:

1. **Update dependencies:**
   ```bash
   cd /home/user/R-map/crates/rmap-api
   cargo update
   cargo build
   ```

2. **Configure environment:**
   ```bash
   export JWT_SECRET=$(openssl rand -base64 32)
   export API_USERNAME="admin"
   export API_PASSWORD_HASH='$2b$12$...'
   ```

3. **Update API clients:**
   - All API calls now require `Authorization: Bearer <token>` header
   - Add login flow to get token
   - Handle 401 errors (token expired, re-login)
   - Handle 429 errors (rate limited, retry with backoff)

4. **Update CORS origins:**
   - Verify frontend origins are in the allowed list
   - Remove any that shouldn't be there

---

## Additional Resources

- [JWT.io](https://jwt.io/) - JWT debugger and validator
- [OWASP API Security](https://owasp.org/www-project-api-security/) - API security best practices
- [Bcrypt Calculator](https://bcrypt-generator.com/) - Generate password hashes
- Environment Variables: See [ENV.md](./ENV.md) for detailed configuration

---

## Support

For security issues or questions:
1. Check troubleshooting section above
2. Review environment variable documentation (ENV.md)
3. Check server logs for detailed error messages
4. Ensure all dependencies are up to date

**DO NOT** share JWT secrets or password hashes in issues or support requests!
