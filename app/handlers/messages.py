"""
Message handlers.
Handles encrypted message storage and retrieval.
Server treats all crypto fields as opaque data.
"""
from uuid import UUID
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from app.database import get_db
from app.models.message import EncryptedMessage
from app.schemas.message import MessageCreate, MessageResponse
from app.auth.jwt import get_current_user
from app.handlers.websocket import notify_new_message

router = APIRouter(prefix="/messages", tags=["messages"])


@router.post("", response_model = MessageResponse, status_code = status.HTTP_201_CREATED)
async def send_message(
    message: MessageCreate,
    db: AsyncSession = Depends(get_db),
    current_user: UUID = Depends(get_current_user)
):
    """
    Store an encrypted message.
    
    Server does NOT:
    - Decrypt or inspect ciphertext
    - Validate encryption
    - Generate or derive keys
    
    Server ONLY stores opaque encrypted data.
    """
    # Create encrypted message record
    new_message = EncryptedMessage(
        sender_id = current_user,
        receiver_id = message.receiver_id,
        ciphertext = message.ciphertext,
        nonce = message.nonce,
        signature = message.signature,
        expires_at = message.expires_at
    )
    
    db.add(new_message)
    await db.commit()
    await db.refresh(new_message)
    
    # Notify receiver via WebSocket if connected
    await notify_new_message(message.receiver_id)
    # Also notify sender so their UI updates immediately
    await notify_new_message(current_user)
    
    return new_message


@router.get("", response_model = list[MessageResponse])
async def get_messages(
    limit: int = Query(100, description = "Maximum number of messages to return"),
    since: Optional[datetime] = Query(None, description = "Retrieve messages since this timestamp"),
    db: AsyncSession = Depends(get_db),
    current_user: UUID = Depends(get_current_user)
):
    """
    Retrieve encrypted messages for authenticated user.
    
    Returns all messages where user is either sender OR receiver.
    Server returns encrypted data as-is without decryption.
    """
    query = select(EncryptedMessage).where(
        or_(
            EncryptedMessage.receiver_id == current_user,
            EncryptedMessage.sender_id == current_user
        )
    )
    
    if since:
        # Ensure timezone-aware
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        query = query.where(EncryptedMessage.created_at > since)
    
    # Order by creation time and limit results
    query = query.order_by(EncryptedMessage.created_at.asc()).limit(limit)
    
    result = await db.execute(query)
    messages = result.scalars().all()
    
    return messages
