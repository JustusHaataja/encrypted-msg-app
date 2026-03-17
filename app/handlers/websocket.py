"""
WebSocket handler for real-time messaging.
Handles WebSocket connections with JWT authentication.
"""
from uuid import UUID
from typing import Dict
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
from app.auth.jwt import decode_access_token
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])

# Active WebSocket connections: {user_id: WebSocket}
active_connections: Dict[str, WebSocket] = {}


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(...)):
    """
    WebSocket endpoint for real-time message notifications.
    
    Client connects with JWT token as query parameter.
    Server sends notifications when new messages arrive.
    """
    # Authenticate via JWT token
    try:
        user_id = decode_access_token(token)
        if not user_id:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except Exception as e:
        logger.error(f"WebSocket auth failed: {e}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    # Accept connection
    await websocket.accept()
    user_id_str = str(user_id)
    active_connections[user_id_str] = websocket
    logger.info(f"WebSocket connected: {user_id_str}")
    
    try:
        # Keep connection alive
        while True:
            # Wait for any message from client (ping/pong)
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: {user_id_str}")
    finally:
        # Remove from active connections
        if user_id_str in active_connections:
            del active_connections[user_id_str]


async def notify_new_message(receiver_id: UUID):
    """
    Notify a user about a new message via WebSocket.
    Called when a new message is sent to them.
    """
    receiver_id_str = str(receiver_id)
    if receiver_id_str in active_connections:
        try:
            ws = active_connections[receiver_id_str]
            await ws.send_json({"type": "new_message"})
            logger.info(f"Notified {receiver_id_str} of new message")
        except Exception as e:
            logger.error(f"Failed to notify {receiver_id_str}: {e}")
            # Remove dead connection
            if receiver_id_str in active_connections:
                del active_connections[receiver_id_str]
