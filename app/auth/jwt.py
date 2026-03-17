"""
JWT token management.
Tokens contain ONLY user_id and expiration - no sensitive data.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional
from uuid import UUID
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import settings

# HTTP Bearer token scheme
security = HTTPBearer()


def create_access_token(user_id: UUID) -> str:
    """
    Create a short-lived JWT access token.
    Payload contains only user_id and standard claims.
    """
    expires_delta = timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)
    expire = datetime.now(timezone.utc) + expires_delta
    
    payload = {
        "sub": str(user_id),  # Subject: user_id
        "exp": expire,        # Expiration
        "iat": datetime.now(timezone.utc),  # Issued at
    }
    
    encoded_jwt = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm = settings.JWT_ALGORITHM
    )
    
    return encoded_jwt


def decode_access_token(token: str) -> Optional[UUID]:
    """
    Decode and validate JWT token.
    Returns user_id if valid, None otherwise.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms = [settings.JWT_ALGORITHM]
        )

        user_id_str = payload.get("sub")
        if user_id_str is None:
            return None
        
        return UUID(user_id_str)
    
    except JWTError:
        return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> UUID:
    """
    FastAPI dependency to extract and validate current user from JWT.
    Raises 401 if token is invalid or missing.
    """
    token = credentials.credentials
    user_id = decode_access_token(token)
    
    if user_id is None:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Invalid authentication",
        )
    
    return user_id
