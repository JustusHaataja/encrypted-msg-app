"""
Integration tests for E2EE messaging API.
Tests user registration, authentication, and messaging endpoints.
"""
import pytest
from httpx import AsyncClient
from datetime import datetime, timezone, timedelta
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.main import app


@pytest.fixture
async def client():
    """Create async HTTP client for testing."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def ed25519_keypair():
    """Generate Ed25519 key pair for testing authentication."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Convert to Base64
    private_bytes = private_key.private_bytes(
        encoding=__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.Raw,
        format=__import__('cryptography.hazmat.primitives.serialization', fromlist=['PrivateFormat']).PrivateFormat.Raw,
        encryption_algorithm=__import__('cryptography.hazmat.primitives.serialization', fromlist=['NoEncryption']).NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.Raw,
        format=__import__('cryptography.hazmat.primitives.serialization', fromlist=['PublicFormat']).PublicFormat.Raw
    )
    
    return {
        "private_key": private_key,
        "private_key_b64": base64.b64encode(private_bytes).decode('utf-8'),
        "public_key_b64": base64.b64encode(public_bytes).decode('utf-8')
    }


class TestHealthEndpoints:
    """Test basic server health and info endpoints."""
    
    @pytest.mark.asyncio
    async def test_health_check(self, client):
        """Test health check endpoint."""
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}
    
    @pytest.mark.asyncio
    async def test_root_endpoint(self, client):
        """Test root endpoint returns security info."""
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["security_model"] == "zero-knowledge"
        assert "server_capabilities" in data
        assert "server_limitations" in data


class TestUserRegistration:
    """Test user registration endpoints."""
    
    @pytest.mark.asyncio
    async def test_register_new_user(self, client, ed25519_keypair):
        """Test successful user registration."""
        response = await client.post(
            "/users/register",
            json={
                "ik_pub": ed25519_keypair["public_key_b64"],
                "ek_pub": "test_ephemeral_key_base64"
            }
        )
        assert response.status_code == 201
        data = response.json()
        assert "user_id" in data
        assert data["ik_pub"] == ed25519_keypair["public_key_b64"]
        assert data["ek_pub"] == "test_ephemeral_key_base64"
        assert "created_at" in data
    
    @pytest.mark.asyncio
    async def test_register_duplicate_identity_key(self, client, ed25519_keypair):
        """Test that duplicate identity keys are rejected."""
        # Register first user
        await client.post(
            "/users/register",
            json={
                "ik_pub": ed25519_keypair["public_key_b64"],
                "ek_pub": "test_ephemeral_key_1"
            }
        )
        
        # Try to register with same identity key
        response = await client.post(
            "/users/register",
            json={
                "ik_pub": ed25519_keypair["public_key_b64"],
                "ek_pub": "test_ephemeral_key_2"
            }
        )
        assert response.status_code == 409
        assert "already registered" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_get_user_keys(self, client, ed25519_keypair):
        """Test retrieving user public keys."""
        # Register user first
        register_response = await client.post(
            "/users/register",
            json={
                "ik_pub": ed25519_keypair["public_key_b64"],
                "ek_pub": "test_ephemeral_key"
            }
        )
        user_id = register_response.json()["user_id"]
        
        # Get user keys
        response = await client.get(f"/users/{user_id}/keys")
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == user_id
        assert data["ik_pub"] == ed25519_keypair["public_key_b64"]
        assert data["ek_pub"] == "test_ephemeral_key"
    
    @pytest.mark.asyncio
    async def test_get_nonexistent_user_keys(self, client):
        """Test getting keys for non-existent user."""
        fake_uuid = "00000000-0000-0000-0000-000000000000"
        response = await client.get(f"/users/{fake_uuid}/keys")
        assert response.status_code == 404


class TestAuthentication:
    """Test challenge-response authentication flow."""
    
    @pytest.mark.asyncio
    async def test_challenge_request(self, client, ed25519_keypair):
        """Test requesting authentication challenge."""
        # Register user first
        register_response = await client.post(
            "/users/register",
            json={
                "ik_pub": ed25519_keypair["public_key_b64"],
                "ek_pub": "test_ephemeral_key"
            }
        )
        user_id = register_response.json()["user_id"]
        
        # Request challenge
        response = await client.post(
            "/auth/challenge",
            json={"user_id": user_id}
        )
        assert response.status_code == 200
        data = response.json()
        assert "nonce" in data
        assert "expires_in" in data
    
    @pytest.mark.asyncio
    async def test_challenge_nonexistent_user(self, client):
        """Test challenge request for non-existent user."""
        fake_uuid = "00000000-0000-0000-0000-000000000000"
        response = await client.post(
            "/auth/challenge",
            json={"user_id": fake_uuid}
        )
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_complete_auth_flow(self, client, ed25519_keypair):
        """Test complete authentication flow with signature verification."""
        # Register user
        register_response = await client.post(
            "/users/register",
            json={
                "ik_pub": ed25519_keypair["public_key_b64"],
                "ek_pub": "test_ephemeral_key"
            }
        )
        user_id = register_response.json()["user_id"]
        
        # Request challenge
        challenge_response = await client.post(
            "/auth/challenge",
            json={"user_id": user_id}
        )
        nonce_b64 = challenge_response.json()["nonce"]
        
        # Sign challenge with private key
        nonce_bytes = base64.b64decode(nonce_b64)
        signature = ed25519_keypair["private_key"].sign(nonce_bytes)
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        # Verify challenge
        verify_response = await client.post(
            "/auth/verify",
            json={
                "user_id": user_id,
                "nonce": nonce_b64,
                "signature": signature_b64
            }
        )
        assert verify_response.status_code == 200
        data = verify_response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data
    
    @pytest.mark.asyncio
    async def test_verify_with_invalid_signature(self, client, ed25519_keypair):
        """Test that invalid signatures are rejected."""
        # Register user
        register_response = await client.post(
            "/users/register",
            json={
                "ik_pub": ed25519_keypair["public_key_b64"],
                "ek_pub": "test_ephemeral_key"
            }
        )
        user_id = register_response.json()["user_id"]
        
        # Request challenge
        challenge_response = await client.post(
            "/auth/challenge",
            json={"user_id": user_id}
        )
        nonce_b64 = challenge_response.json()["nonce"]
        
        # Use invalid signature
        invalid_signature_b64 = base64.b64encode(b"invalid_signature_bytes_here").decode('utf-8')
        
        # Try to verify
        verify_response = await client.post(
            "/auth/verify",
            json={
                "user_id": user_id,
                "nonce": nonce_b64,
                "signature": invalid_signature_b64
            }
        )
        assert verify_response.status_code == 401


class TestMessaging:
    """Test encrypted message endpoints."""
    
    async def create_authenticated_user(self, client, ed25519_keypair):
        """Helper to create user and get auth token."""
        # Register user
        register_response = await client.post(
            "/users/register",
            json={
                "ik_pub": ed25519_keypair["public_key_b64"],
                "ek_pub": "test_ephemeral_key"
            }
        )
        user_id = register_response.json()["user_id"]
        
        # Get auth token
        challenge_response = await client.post(
            "/auth/challenge",
            json={"user_id": user_id}
        )
        nonce_b64 = challenge_response.json()["nonce"]
        nonce_bytes = base64.b64decode(nonce_b64)
        signature = ed25519_keypair["private_key"].sign(nonce_bytes)
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        verify_response = await client.post(
            "/auth/verify",
            json={
                "user_id": user_id,
                "nonce": nonce_b64,
                "signature": signature_b64
            }
        )
        token = verify_response.json()["access_token"]
        
        return user_id, token
    
    @pytest.mark.asyncio
    async def test_send_message(self, client, ed25519_keypair):
        """Test sending an encrypted message."""
        # Create two users
        sender_id, sender_token = await self.create_authenticated_user(client, ed25519_keypair)
        
        # Create another keypair for receiver
        receiver_keypair = Ed25519PrivateKey.generate()
        receiver_pub_bytes = receiver_keypair.public_key().public_bytes(
            encoding=__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.Raw,
            format=__import__('cryptography.hazmat.primitives.serialization', fromlist=['PublicFormat']).PublicFormat.Raw
        )
        receiver_pub_b64 = base64.b64encode(receiver_pub_bytes).decode('utf-8')
        
        receiver_response = await client.post(
            "/users/register",
            json={"ik_pub": receiver_pub_b64, "ek_pub": "receiver_ek"}
        )
        receiver_id = receiver_response.json()["user_id"]
        
        # Send message
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        response = await client.post(
            "/messages",
            json={
                "receiver_id": receiver_id,
                "ciphertext": "encrypted_message_base64",
                "nonce": "nonce_base64",
                "signature": "signature_base64",
                "expires_at": expires_at
            },
            headers={"Authorization": f"Bearer {sender_token}"}
        )
        assert response.status_code == 201
        data = response.json()
        assert data["sender_id"] == sender_id
        assert data["receiver_id"] == receiver_id
        assert data["ciphertext"] == "encrypted_message_base64"
    
    @pytest.mark.asyncio
    async def test_send_message_without_auth(self, client):
        """Test that sending messages requires authentication."""
        fake_receiver = "00000000-0000-0000-0000-000000000000"
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        
        response = await client.post(
            "/messages",
            json={
                "receiver_id": fake_receiver,
                "ciphertext": "encrypted",
                "nonce": "nonce",
                "signature": "sig",
                "expires_at": expires_at
            }
        )
        assert response.status_code == 403  # No auth header
    
    @pytest.mark.asyncio
    async def test_get_messages(self, client, ed25519_keypair):
        """Test retrieving messages for authenticated user."""
        sender_id, sender_token = await self.create_authenticated_user(client, ed25519_keypair)
        
        # Create receiver
        receiver_keypair = Ed25519PrivateKey.generate()
        receiver_pub_bytes = receiver_keypair.public_key().public_bytes(
            encoding=__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.Raw,
            format=__import__('cryptography.hazmat.primitives.serialization', fromlist=['PublicFormat']).PublicFormat.Raw
        )
        receiver_pub_b64 = base64.b64encode(receiver_pub_bytes).decode('utf-8')
        
        receiver_response = await client.post(
            "/users/register",
            json={"ik_pub": receiver_pub_b64, "ek_pub": "receiver_ek"}
        )
        receiver_id = receiver_response.json()["user_id"]
        
        # Get receiver token
        challenge_response = await client.post(
            "/auth/challenge",
            json={"user_id": receiver_id}
        )
        nonce_b64 = challenge_response.json()["nonce"]
        nonce_bytes = base64.b64decode(nonce_b64)
        signature = receiver_keypair.sign(nonce_bytes)
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        verify_response = await client.post(
            "/auth/verify",
            json={
                "user_id": receiver_id,
                "nonce": nonce_b64,
                "signature": signature_b64
            }
        )
        receiver_token = verify_response.json()["access_token"]
        
        # Send message to receiver
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        await client.post(
            "/messages",
            json={
                "receiver_id": receiver_id,
                "ciphertext": "encrypted_message",
                "nonce": "nonce",
                "signature": "sig",
                "expires_at": expires_at
            },
            headers={"Authorization": f"Bearer {sender_token}"}
        )
        
        # Receiver gets their messages
        response = await client.get(
            "/messages",
            headers={"Authorization": f"Bearer {receiver_token}"}
        )
        assert response.status_code == 200
        messages = response.json()
        assert len(messages) == 1
        assert messages[0]["sender_id"] == sender_id
        assert messages[0]["receiver_id"] == receiver_id
    
    @pytest.mark.asyncio
    async def test_message_expiration_validation(self, client, ed25519_keypair):
        """Test that messages with invalid expiration are rejected."""
        sender_id, sender_token = await self.create_authenticated_user(client, ed25519_keypair)
        
        # Create receiver
        receiver_keypair = Ed25519PrivateKey.generate()
        receiver_pub_bytes = receiver_keypair.public_key().public_bytes(
            encoding=__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.Raw,
            format=__import__('cryptography.hazmat.primitives.serialization', fromlist=['PublicFormat']).PublicFormat.Raw
        )
        receiver_pub_b64 = base64.b64encode(receiver_pub_bytes).decode('utf-8')
        
        receiver_response = await client.post(
            "/users/register",
            json={"ik_pub": receiver_pub_b64, "ek_pub": "receiver_ek"}
        )
        receiver_id = receiver_response.json()["user_id"]
        
        # Try to send message with past expiration
        past_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        response = await client.post(
            "/messages",
            json={
                "receiver_id": receiver_id,
                "ciphertext": "encrypted",
                "nonce": "nonce",
                "signature": "sig",
                "expires_at": past_time
            },
            headers={"Authorization": f"Bearer {sender_token}"}
        )
        assert response.status_code == 422  # Validation error
