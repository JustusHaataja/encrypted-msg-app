# E2EE Messaging Backend

A secure, end-to-end encrypted (E2EE) 1-to-1 messaging backend with **zero-knowledge server design**. The server is intentionally "dumb" - it never sees plaintext messages or private keys.

## 🔐 Security Model

### Zero-Knowledge Architecture
- **Server NEVER:**
  - Encrypts or decrypts messages
  - Generates or stores private keys
  - Derives session keys
  - Inspects message content

- **Server ONLY:**
  - Verifies Ed25519 signatures for authentication
  - Stores encrypted messages as opaque data
  - Issues short-lived JWT tokens
  - Auto-deletes expired messages

### Authentication
- Passwordless authentication using **Ed25519 identity keys**
- Challenge-response flow:
  1. Client requests challenge nonce
  2. Client signs nonce with private identity key
  3. Server verifies signature with stored public key
  4. Server issues JWT (15-30 min lifetime)

## 🛠️ Tech Stack

- **Language:** Python 3.11+
- **Framework:** FastAPI
- **ASGI Server:** Uvicorn
- **Database:** PostgreSQL
- **ORM:** SQLAlchemy (async)
- **Migrations:** Alembic
- **Crypto:** cryptography (official library)
- **Auth:** JWT (python-jose)

## 📁 Project Structure

```
msg-app/
├── app/
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration from environment
│   ├── models/              # SQLAlchemy models
│   │   ├── user.py          # User model (public keys only)
│   │   └── message.py       # EncryptedMessage model
│   ├── schemas/             # Pydantic schemas
│   │   ├── user.py          # User request/response schemas
│   │   ├── message.py       # Message schemas
│   │   └── auth.py          # Authentication schemas
│   ├── auth/                # Authentication logic
│   │   ├── challenge.py     # Challenge-response flow
│   │   └── jwt.py           # JWT token management
│   ├── handlers/            # API route handlers
│   │   ├── users.py         # User registration & key retrieval
│   │   ├── auth.py          # Authentication endpoints
│   │   └── messages.py      # Message send/receive
│   ├── jobs/                # Background tasks
│   │   └── cleanup.py       # Expired message deletion
│   └── database/            # Database session management
├── alembic/                 # Database migrations
│   ├── env.py
│   └── versions/
├── alembic.ini
├── requirements.txt
├── .env.example
└── README.md
```

## 🗄️ Database Models

### User
- `user_id` (UUID, primary key)
- `ik_pub` (Base64 string) - Identity Key public
- `ek_pub` (Base64 string) - Ephemeral Key public
- `created_at` (UTC timestamp)

### EncryptedMessage
- `message_id` (UUID, primary key)
- `sender_id` (UUID, indexed)
- `receiver_id` (UUID, indexed)
- `ciphertext` (Base64 string) - Encrypted message payload
- `nonce` (Base64 string) - Encryption nonce
- `signature` (Base64 string) - Ed25519 signature
- `expires_at` (UTC timestamp, indexed)
- `created_at` (UTC timestamp)

**No plaintext fields exist.**

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL 13+

### Installation

1. **Clone and navigate to project:**
```bash
cd msg-app
```

2. **Create virtual environment:**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Set up PostgreSQL database:**
```bash
# Create database
createdb e2ee_msg_db

# Or using psql:
psql -U postgres
CREATE DATABASE e2ee_msg_db;
\q
```

5. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your settings
```

Required `.env` variables:
```env
DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5432/e2ee_msg_db
JWT_SECRET_KEY=your-secret-key-change-this-in-production
JWT_EXPIRATION_MINUTES=15
```

6. **Run database migrations:**
```bash
alembic upgrade head
```

7. **Start the server:**
```bash
python -m app.main
```

Or using uvicorn directly:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Server runs at: `http://localhost:8000`

### Development Mode

```bash
# Auto-reload on code changes
uvicorn app.main:app --reload

# Access interactive API docs
# OpenAPI: http://localhost:8000/docs
# ReDoc: http://localhost:8000/redoc
```

## 📡 API Endpoints

### User Management

#### Register User
```http
POST /users/register
Content-Type: application/json

{
  "ik_pub": "base64_encoded_identity_public_key",
  "ek_pub": "base64_encoded_ephemeral_public_key"
}
```

**Response:** User object with `user_id`

#### Get User Keys
```http
GET /users/{user_id}/keys
```

**Response:** Public keys for key exchange

### Authentication

#### Request Challenge
```http
POST /auth/challenge
Content-Type: application/json

{
  "user_id": "uuid"
}
```

**Response:** Challenge nonce (client must sign with IK_priv)

#### Verify Challenge
```http
POST /auth/verify
Content-Type: application/json

{
  "user_id": "uuid",
  "nonce": "base64_challenge_nonce",
  "signature": "base64_ed25519_signature"
}
```

**Response:** JWT access token

### Messaging

#### Send Message
```http
POST /messages
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "receiver_id": "uuid",
  "ciphertext": "base64_encrypted_message",
  "nonce": "base64_nonce",
  "signature": "base64_signature",
  "expires_at": "2026-01-24T12:00:00Z"
}
```

**Constraints:**
- `expires_at` must be future timestamp
- Maximum TTL: 72 hours from now

#### Get Messages
```http
GET /messages?since=2026-01-21T00:00:00Z
Authorization: Bearer <jwt_token>
```

**Response:** Array of encrypted messages for authenticated user

## 🔒 Security Features

### Rate Limiting
- Authentication endpoints are rate-limited
- Prevents brute-force attacks
- Configurable via `RATE_LIMIT_ENABLED`

### JWT Security
- Short-lived tokens (15-30 min)
- Contains only `user_id` and expiration
- No sensitive data in payload

### Message Retention
- Messages auto-delete after `expires_at`
- Background cleanup task runs every 5 minutes
- No message backups or archives

### Minimal Error Messages
- Authentication failures return generic "Authentication failed"
- Prevents user enumeration
- Logs detailed errors server-side only

## 🧪 Testing with cURL

### 1. Register a user
```bash
curl -X POST http://localhost:8000/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "ik_pub": "test_identity_key_public",
    "ek_pub": "test_ephemeral_key_public"
  }'
```

### 2. Request authentication challenge
```bash
curl -X POST http://localhost:8000/auth/challenge \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "YOUR_USER_ID_HERE"
  }'
```

### 3. Get user keys
```bash
curl http://localhost:8000/users/YOUR_USER_ID_HERE/keys
```

**Note:** For actual authentication, you need a client that can generate Ed25519 signatures.

## 🔧 Configuration

All configuration via environment variables (`.env` file):

```env
# Database
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/dbname

# JWT
JWT_SECRET_KEY=your-secret-key-min-32-chars
JWT_ALGORITHM=HS256
JWT_EXPIRATION_MINUTES=15

# Server
HOST=0.0.0.0
PORT=8000
RELOAD=false

# Security
RATE_LIMIT_ENABLED=true
CHALLENGE_NONCE_BYTES=32
CHALLENGE_EXPIRATION_SECONDS=60

# Message Retention
MAX_MESSAGE_TTL_HOURS=72
CLEANUP_INTERVAL_SECONDS=300
```

## 📊 Database Migrations

### Create new migration
```bash
alembic revision --autogenerate -m "Description of changes"
```

### Apply migrations
```bash
alembic upgrade head
```

### Rollback migration
```bash
alembic downgrade -1
```

## ⚠️ Security Assumptions

This backend **assumes**:

1. **TLS is enforced** - All communication over HTTPS in production
2. **Clients handle all encryption** - Server never touches crypto operations
3. **Clients protect private keys** - Server only stores public keys
4. **Server can be compromised** - Design ensures compromise reveals no plaintext
5. **PostgreSQL is secured** - Database access is restricted
6. **JWT secrets are protected** - Use strong, random secrets in production

## 🚧 Production Checklist

Before deploying to production:

- [ ] Use strong, random `JWT_SECRET_KEY` (min 32 bytes)
- [ ] Configure CORS `allow_origins` to specific domains
- [ ] Enable TLS/HTTPS (use reverse proxy like Nginx)
- [ ] Use managed PostgreSQL (AWS RDS, Azure Database, etc.)
- [ ] Replace in-memory challenge store with Redis
- [ ] Set `RELOAD=false` in production
- [ ] Configure proper logging and monitoring
- [ ] Set up database backups (encrypted at rest)
- [ ] Review and adjust rate limits
- [ ] Use environment variable management (not .env files)
- [ ] Implement proper secret rotation

## 🤝 Client Integration

This backend is designed for React Native E2EE clients that:

1. Generate Ed25519 identity key pairs locally
2. Perform all encryption/decryption client-side
3. Use libsodium or similar for crypto operations
4. Never send private keys or plaintext to server

**Example client flow:**
1. Generate IK (identity key pair) and EK (ephemeral key)
2. Register: Send IK_pub and EK_pub to `/users/register`
3. Authenticate: Sign challenge nonce, verify at `/auth/verify`
4. Send message: Encrypt locally, post ciphertext to `/messages`
5. Receive: Fetch encrypted messages, decrypt locally

## 📝 License

This project is provided as-is for educational and production use.

## 🆘 Support

For issues or questions:
- Check server logs for detailed error messages
- Verify PostgreSQL connection and database existence
- Ensure all environment variables are set correctly
- Review API documentation at `/docs`

---

**Remember: The server is intentionally "dumb" by design. It knows nothing about your messages.**
