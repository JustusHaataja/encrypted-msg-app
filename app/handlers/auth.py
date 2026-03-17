"""
Authentication handlers.
Challenge-response flow with Ed25519 signatures.
"""
import logging
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models.user import User
from app.schemas.auth import (
    ChallengeRequest,
    ChallengeResponse,
    VerifyRequest,
    TokenResponse
)
from app.auth.challenge import (
    generate_challenge,
    store_challenge,
    verify_challenge_signature
)
from app.auth.jwt import create_access_token
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix = "/auth", tags = ["auth"])


@router.post("/challenge", response_model = ChallengeResponse)
async def request_challenge(
    request: ChallengeRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Request authentication challenge.
    
    Server generates a random nonce.
    Client must sign with their IK_priv and submit to /auth/verify.
    """
    # Verify user exists
    result = await db.execute(
        select(User).where(User.user_id == request.user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        # Minimal error to prevent user enumeration
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Authentication failed"
        )
    
    # Generate and store challenge
    nonce = generate_challenge()
    store_challenge(str(request.user_id), nonce)
    
    return ChallengeResponse(
        nonce = nonce,
        expires_in = settings.CHALLENGE_EXPIRATION_SECONDS
    )


@router.post("/verify", response_model = TokenResponse)
async def verify_challenge(
    request: VerifyRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Verify signed challenge and issue JWT.
    
    Server verifies the Ed25519 signature using stored IK_pub.
    This is the ONLY crypto operation server performs on client data.
    """
    # Retrieve user and their public key
    result = await db.execute(
        select(User).where(User.user_id == request.user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Authentication failed"
        )
    
    # Verify signature
    is_valid = verify_challenge_signature(
        user_id = str(request.user_id),
        nonce_b64 = request.nonce,
        signature_b64 = request.signature,
        public_key_b64 = str(user.ik_pub)
    )
    
    if not is_valid:
        logger.warning(f"Challenge verification failed for user {request.user_id}")
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Authentication failed"
        )
    
    # Issue JWT token
    access_token = create_access_token(user.user_id)
    
    return TokenResponse(
        access_token = access_token,
        token_type = "bearer",
        expires_in = settings.JWT_EXPIRATION_MINUTES * 60
    )
