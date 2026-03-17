"""
Background task to delete expired messages.
Runs periodically to enforce message retention policy.
"""
import asyncio
from datetime import datetime, timezone
from sqlalchemy import delete
from app.database import async_session_maker
from app.models.message import EncryptedMessage
from app.config import settings
import logging

logger = logging.getLogger(__name__)


async def cleanup_expired_messages():
    """
    Delete all messages where expires_at < now.
    Enforces zero-knowledge principle: no message backups.
    """
    while True:
        try:
            async with async_session_maker() as session:
                now = datetime.now(timezone.utc)
                
                # Delete expired messages
                stmt = delete(EncryptedMessage).where(
                    EncryptedMessage.expires_at < now
                )
                
                result = await session.execute(stmt)
                await session.commit()
                
                deleted_count = result.rowcount
                if deleted_count > 0:
                    logger.info(f"Deleted {deleted_count} expired messages")
        
        except Exception as e:
            logger.error(f"Error in cleanup task: {e}")
        
        # Wait before next cleanup
        await asyncio.sleep(settings.CLEANUP_INTERVAL_SECONDS)


def start_cleanup_task():
    """
    Start the background cleanup task.
    Called during app startup.
    """
    asyncio.create_task(cleanup_expired_messages())
    logger.info("Started message cleanup background task")
