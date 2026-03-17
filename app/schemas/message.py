"""
Message schemas for encrypted message handling.
Server treats all crypto fields as opaque data.
"""
from pydantic import BaseModel, Field, field_validator
from uuid import UUID
from datetime import datetime, timezone


class MessageCreate(BaseModel):
    """
    Encrypted message submission.
    All fields are opaque to the server.
    """
    receiver_id: UUID = Field(..., description="Recipient user ID")
    ciphertext: str = Field(..., description="Encrypted message payload (Base64)")
    nonce: str = Field(..., description="Nonce used for encryption (Base64)")
    signature: str = Field(..., description="Ed25519 signature from sender (Base64)")
    expires_at: datetime = Field(..., description="Message expiration timestamp (UTC)")
    
    @field_validator('expires_at')
    @classmethod
    def validate_expiration(cls, v: datetime) -> datetime:
        """
        Ensure expires_at is:
        1. In the future
        2. Not more than MAX_MESSAGE_TTL_HOURS from now
        """
        from app.config import settings
        now = datetime.now(timezone.utc)
        max_expiry = now.replace(tzinfo = timezone.utc) + \
                     __import__('datetime').timedelta(hours = settings.MAX_MESSAGE_TTL_HOURS)
        
        # Ensure timezone-aware
        if v.tzinfo is None:
            v = v.replace(tzinfo = timezone.utc)
        
        if v <= now:
            raise ValueError("expires_at must be in the future")
        if v > max_expiry:
            raise ValueError(f"expires_at cannot exceed {settings.MAX_MESSAGE_TTL_HOURS} hours from now")
        
        return v


class MessageResponse(BaseModel):
    """
    Encrypted message response.
    Server returns encrypted data as-is.
    """
    message_id: UUID
    sender_id: UUID
    receiver_id: UUID
    ciphertext: str
    nonce: str
    signature: str
    expires_at: datetime
    created_at: datetime
    
    class Config:
        from_attributes = True
