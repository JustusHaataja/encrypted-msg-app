# E2EE Messaging Backend Tests

Comprehensive integration tests for the zero-knowledge E2EE messaging API.

## Setup

Install test dependencies:
```bash
pip install -r requirements-dev.txt
```

## Running Tests

Run all tests:
```bash
pytest
```

Run with verbose output:
```bash
pytest -v
```

Run specific test file:
```bash
pytest tests/test_api.py
```

Run specific test class:
```bash
pytest tests/test_api.py::TestAuthentication
```

Run specific test:
```bash
pytest tests/test_api.py::TestAuthentication::test_complete_auth_flow
```

Run with coverage:
```bash
pytest --cov=app --cov-report=html
```

## Test Coverage

The test suite covers:

### ✅ Health Endpoints
- Health check endpoint
- Root endpoint security information

### ✅ User Registration
- Successful user registration
- Duplicate identity key rejection
- Public key retrieval
- Non-existent user handling

### ✅ Authentication
- Challenge nonce request
- Complete Ed25519 signature verification flow
- Invalid signature rejection
- Non-existent user authentication

### ✅ Messaging
- Sending encrypted messages
- Authentication requirement enforcement
- Message retrieval by receiver
- Message expiration validation
- Zero-knowledge data handling

## Test Structure

All tests use:
- **pytest-asyncio** for async test support
- **httpx** for async HTTP client
- **cryptography** for real Ed25519 key generation
- Real signature verification (no mocking)

## Security Testing

Tests verify:
- Server never sees private keys
- All crypto operations are client-side (except signature verification)
- Messages are stored as opaque encrypted data
- Authentication requires valid Ed25519 signatures
- JWT tokens are properly issued and validated

## Notes

- Tests use in-memory SQLite database (if configured)
- Each test is isolated and doesn't affect others
- Real cryptographic operations are performed
- No external services required (uses test client)
