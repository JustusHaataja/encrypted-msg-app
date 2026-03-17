"""
Authentication schemas.
Challenge-response flow using Ed25519 signatures.
"""
from pydantic import BaseModel, Field
from uuid import UUID


class ChallengeRequest(BaseModel):
    """
    Request authentication challenge.
    """
    user_id: UUID = Field(..., description = "User requesting authentication")


class ChallengeResponse(BaseModel):
    """
    Server-generated challenge nonce.
    Client must sign this with their IK_priv.
    """
    nonce: str = Field(..., description = "Random challenge nonce (Base64)")
    expires_in: int = Field(..., description = "Challenge validity in seconds")


class VerifyRequest(BaseModel):
    """
    Challenge verification request.
    Client submits signed nonce.
    """
    user_id: UUID = Field(..., description = "User ID")
    nonce: str = Field(..., description = "Challenge nonce (Base64)")
    signature: str = Field(..., description = "Ed25519 signature of nonce (Base64)")


class TokenResponse(BaseModel):
    """
    JWT token response after successful authentication.
    """
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description = "Token validity in seconds")
