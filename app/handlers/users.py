"""
User management handlers.
Handles registration and key retrieval.
"""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models.user import User
from app.schemas.user import UserRegister, UserResponse, UserKeysResponse

router = APIRouter(prefix="/users", tags=["users"])


@router.post("/register", response_model = UserResponse, status_code = status.HTTP_201_CREATED)
async def register_user(
    user_data: UserRegister,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user.
    
    Client sends only public keys.
    Server NEVER generates or stores private keys.
    """
    # Check if IK_pub already registered
    result = await db.execute(
        select(User).where(User.ik_pub == user_data.ik_pub)
    )
    existing_user = result.scalar_one_or_none()
    
    if existing_user:
        raise HTTPException(
            status_code = status.HTTP_409_CONFLICT,
            detail = "Identity key already registered"
        )
    
    # Create new user
    new_user = User(
        ik_pub = user_data.ik_pub,
        ek_pub = user_data.ek_pub
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    return new_user


@router.get("/{user_id}/keys", response_model = UserKeysResponse)
async def get_user_keys(
    user_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve public keys for a user.
    
    Used for key exchange before sending encrypted messages.
    Returns ONLY public keys.
    """
    result = await db.execute(
        select(User).where(User.user_id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "User not found"
        )
    
    return user


@router.get("/pubkey/{ik_pub}", response_model = UserResponse)
async def get_user_by_pubkey(
    ik_pub: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Look up a user by their identity public key.
    
    Used to find users to message.
    """
    result = await db.execute(
        select(User).where(User.ik_pub == ik_pub)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "User not found"
        )
    
    return user
