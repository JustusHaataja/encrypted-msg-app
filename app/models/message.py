"""
EncryptedMessage model.
Stores ONLY encrypted data - server cannot decrypt.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base


class EncryptedMessage(Base):
    __tablename__ = "encrypted_messages"
    
    # Primary key
    message_id = Column(
        UUID(as_uuid = True),
        primary_key = True,
        default = uuid.uuid4
    )
    
    # Sender and receiver (indexed for queries)
    sender_id = Column(
        UUID(as_uuid = True),
        nullable = False,
        index = True
    )

    receiver_id = Column(
        UUID(as_uuid = True),
        nullable = False,
        index = True
    )
    
    # Encrypted payload (Base64 encoded) - server treats as opaque data
    ciphertext = Column(String, nullable = False)
    nonce = Column(String, nullable = False)
    signature = Column(String, nullable = False)  # Ed25519 signature from sender
    
    # Expiration for auto-deletion
    expires_at = Column(
        DateTime(timezone = True),
        nullable = False,
        index = True
    )

    created_at = Column(
        DateTime(timezone = True),
        nullable = False,
        default = lambda: datetime.now(timezone.utc)
    )
    
    __table_args__ = (
        Index('ix_receiver_created', 'receiver_id', 'created_at'),
    )
    
    def __repr__(self):
        return f"<EncryptedMessage(message_id={self.message_id}, sender={self.sender_id}, receiver={self.receiver_id})>"
