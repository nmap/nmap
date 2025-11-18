# R-Map API Security Quick Reference

## 🚀 Quick Start

### 1. Start Server (Development)
```bash
cd /home/user/R-map/crates/rmap-api
cargo run
```

Default credentials: `admin` / `admin`

### 2. Login & Get Token
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

### 3. Use Token
```bash
export TOKEN="<token_from_login>"
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/scans
```

---

## 📋 API Endpoints

### Public (No Auth)
```
GET  /health                       - Health check
POST /api/v1/auth/login            - Get JWT token
POST /api/v1/auth/register         - Generate password hash (demo)
```

### Protected (Requires: `Authorization: Bearer <token>`)
```
POST   /api/v1/scans                - Create scan (2/min)
GET    /api/v1/scans                - List scans
GET    /api/v1/scans/:id            - Get scan
DELETE /api/v1/scans/:id            - Delete scan
POST   /api/v1/scans/:id/start      - Start scan (2/min)
GET    /api/v1/scans/:id/hosts      - Get hosts
GET    /api/v1/hosts/:id            - Get host
GET    /api/v1/scans/:id/vulnerabilities - Get vulns
WS     /ws                          - WebSocket (5/min)
```

---

## 🔑 Environment Variables

```bash
# Production setup
export JWT_SECRET=$(openssl rand -base64 32)
export API_USERNAME="admin"
export API_PASSWORD_HASH='$2b$12$...'
```

**Generate password hash:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YourSecurePassword"}'
# Copy password_hash from response
```

---

## 🚦 Rate Limits

| Endpoint | Limit | Burst |
|----------|-------|-------|
| General API | 10/sec | 10 |
| Scan create/start | 2/min | 2 |
| WebSocket | 5/min | 5 |

---

## 🛡️ CORS Origins

- `http://localhost:3000` (Node-RED)
- `http://localhost:5173` (Svelte)
- `http://127.0.0.1:3000`
- `http://127.0.0.1:5173`

---

## 📝 Example Requests

### Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin"
  }'
```

### Create Scan
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Network Scan",
    "targets": ["192.168.1.0/24"]
  }'
```

### List Scans
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/scans
```

### WebSocket (JavaScript)
```javascript
const token = "your_jwt_token";
const ws = new WebSocket('ws://localhost:8080/ws', {
  headers: { 'Authorization': `Bearer ${token}` }
});

ws.onmessage = (e) => console.log(JSON.parse(e.data));
```

---

## 🔧 Troubleshooting

### 401 Unauthorized
- Token missing or invalid
- Token expired (1 hour lifetime)
- Solution: Login again to get new token

### 429 Too Many Requests
- Rate limit exceeded
- Solution: Wait 1 second (API) or 1 minute (scans)

### CORS Error
- Origin not in allowed list
- Solution: Add origin in `src/main.rs`

---

## 📚 Documentation

- **Detailed Setup:** [SECURITY.md](./SECURITY.md)
- **Environment Vars:** [ENV.md](./ENV.md)
- **Full Summary:** [IMPLEMENTATION_SUMMARY.md](./IMPLEMENTATION_SUMMARY.md)

---

## ⚡ Common Tasks

### Change Password
```bash
# 1. Generate new hash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"NewPassword123!"}'

# 2. Set environment variable
export API_PASSWORD_HASH='$2b$12$...'  # from response

# 3. Restart server
```

### Test Rate Limiting
```bash
# Should fail after 10 requests
for i in {1..15}; do curl http://localhost:8080/health; done
```

### Check JWT Secret
```bash
# Make sure it's set (production)
echo $JWT_SECRET

# If not set, generate one
export JWT_SECRET=$(openssl rand -base64 32)
```

---

## 🔒 Security Checklist

### Development
- ✅ Default `admin`/`admin` credentials OK for local testing
- ✅ JWT_SECRET can use default (warning will show)

### Production
- ⚠️ MUST set strong JWT_SECRET
- ⚠️ MUST change default password
- ⚠️ MUST use HTTPS (nginx reverse proxy)
- ⚠️ Consider database for user management
- ⚠️ Enable audit logging
- ⚠️ Monitor for suspicious activity

---

## 🐛 Testing

### Security Tests
```bash
cd /home/user/R-map/crates/rmap-api
cargo test --test security_test
```

### Manual Testing
```bash
# Health check (no auth)
curl http://localhost:8080/health

# Login
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' \
  | jq -r '.token')

# Test authenticated endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/scans
```

---

**Quick tip:** Bookmark this page for fast reference during development!
