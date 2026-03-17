"""
User schemas for request/response validation.
"""
from pydantic import BaseModel, Field
from uuid import UUID
from datetime import datetime


class UserRegister(BaseModel):
    """
    Registration payload.
    Client sends only public keys.
    """
    ik_pub: str = Field(..., description="Identity Key public (Base64)")
    ek_pub: str = Field(..., description="Ephemeral Key public (Base64)")


class UserResponse(BaseModel):
    """
    User information response.
    """
    user_id: UUID
    ik_pub: str
    ek_pub: str
    created_at: datetime
    
    class Config:
        from_attributes = True


class UserKeysResponse(BaseModel):
    """
    Public keys only - for key exchange.
    """
    user_id: UUID
    ik_pub: str
    ek_pub: str
    
    class Config:
        from_attributes = True
