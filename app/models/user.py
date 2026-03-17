"""
User model.
Stores only public keys - NEVER private keys.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base


class User(Base):
    __tablename__ = "users"
    
    # Primary key
    user_id = Column(UUID(as_uuid = True), primary_key = True, default = uuid.uuid4)
    
    # Public keys only (Base64 encoded)
    ik_pub = Column(String, nullable = False, unique = True)  # Identity Key public
    ek_pub = Column(String, nullable = False)  # Ephemeral Key public
    
    # Metadata
    created_at = Column(
        DateTime(timezone = True),
        nullable = False,
        default = lambda: datetime.now(timezone.utc)
    )
    
    def __repr__(self):
        return f"<User(user_id={self.user_id})>"
