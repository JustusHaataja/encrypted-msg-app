"""
Main FastAPI application.
Zero-knowledge E2EE messaging server.
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.config import settings
from app.handlers import users, auth, messages, websocket
from app.jobs.cleanup import start_cleanup_task

# Configure logging
logging.basicConfig(
    level = logging.INFO,
    format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Rate limiter
limiter = Limiter(key_func=get_remote_address)


async def rate_limit_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle rate limit exceeded exceptions."""
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded"}
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Starts background tasks on startup.
    """
    logger.info("Starting E2EE messaging server...")
    
    # Start background cleanup task
    start_cleanup_task()
    
    logger.info("Server started successfully")
    
    yield
    
    logger.info("Shutting down server...")


# Create FastAPI app
app = FastAPI(
    title = "E2EE Messaging Server",
    description = "Zero-knowledge end-to-end encrypted messaging backend",
    version = "1.0.0",
    lifespan = lifespan
)

# Add rate limiter
if settings.RATE_LIMIT_ENABLED:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exception_handler)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins = ["*"],  # Configure properly in production
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"],
)

# Include routers
app.include_router(users.router)
app.include_router(auth.router)
app.include_router(messages.router)
app.include_router(websocket.router)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/")
async def root():
    """
    Root endpoint with security information.
    """
    return {
        "name": "E2EE Messaging Server",
        "security_model": "zero-knowledge",
        "encryption": "client-side only",
        "server_capabilities": [
            "Store encrypted messages (opaque data)",
            "Verify Ed25519 signatures for authentication",
            "Issue JWT tokens",
            "Auto-delete expired messages"
        ],
        "server_limitations": [
            "Cannot decrypt messages",
            "Cannot generate or store private keys",
            "Cannot derive session keys",
            "Cannot read message content"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host = settings.HOST,
        port = settings.PORT,
        reload = settings.RELOAD
    )
