"""
Challenge-response authentication using Ed25519 signatures.
Server ONLY verifies signatures - never signs or decrypts.
"""
import base64
import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from app.config import settings

logger = logging.getLogger(__name__)

# In-memory challenge store (use Redis in production)
# Format: {user_id: (nonce, expires_at)}
_challenge_store: dict[str, tuple[bytes, datetime]] = {}


def generate_challenge() -> str:
    """
    Generate a random challenge nonce.
    Returns Base64-encoded random bytes.
    """
    nonce_bytes = secrets.token_bytes(settings.CHALLENGE_NONCE_BYTES)
    return base64.b64encode(nonce_bytes).decode('utf-8')


def store_challenge(user_id: str, nonce: str) -> None:
    """
    Store challenge nonce with expiration.
    In production, use Redis with TTL.
    """
    nonce_bytes = base64.b64decode(nonce)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=settings.CHALLENGE_EXPIRATION_SECONDS)
    _challenge_store[user_id] = (nonce_bytes, expires_at)


def get_challenge(user_id: str) -> Optional[bytes]:
    """
    Retrieve and validate stored challenge.
    Returns None if expired or not found.
    """
    if user_id not in _challenge_store:
        return None
    
    nonce_bytes, expires_at = _challenge_store[user_id]
    
    # Check expiration
    if datetime.now(timezone.utc) > expires_at:
        del _challenge_store[user_id]
        return None
    
    return nonce_bytes


def verify_challenge_signature(
    user_id: str,
    nonce_b64: str,
    signature_b64: str,
    public_key_b64: str
) -> bool:
    """
    Verify Ed25519 signature of challenge nonce.
    
    This is the ONLY cryptographic operation the server performs
    on client data - signature verification for authentication.
    
    Returns True if signature is valid, False otherwise.
    """
    try:
        # Retrieve stored challenge
        stored_nonce = get_challenge(user_id)
        if stored_nonce is None:
            logger.warning(f"No stored challenge for user {user_id}")
            return False
        
        # Decode submitted nonce
        submitted_nonce = base64.b64decode(nonce_b64)
        
        # Verify nonce matches
        if stored_nonce != submitted_nonce:
            logger.warning(f"Nonce mismatch for user {user_id}")
            return False
        
        # Decode public key and signature
        public_key_bytes = base64.b64decode(public_key_b64)
        signature_bytes = base64.b64decode(signature_b64)
        
        # Load Ed25519 public key
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        
        # Verify signature
        public_key.verify(signature_bytes, submitted_nonce)
        
        # Clear used challenge
        del _challenge_store[user_id]
        
        return True
    
    except InvalidSignature as e:
        logger.warning(f"Invalid signature for user {user_id}: {e}")
        return False
    except (ValueError, KeyError) as e:
        logger.warning(f"Challenge verification error for user {user_id}: {e}")
        return False
