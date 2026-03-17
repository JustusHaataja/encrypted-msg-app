"""
Application configuration.
Uses environment variables for all sensitive data.
"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str
    
    # JWT
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 15
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    RELOAD: bool = False
    
    # Security
    RATE_LIMIT_ENABLED: bool = True
    CHALLENGE_NONCE_BYTES: int = 32
    CHALLENGE_EXPIRATION_SECONDS: int = 60
    
    # Message retention
    MAX_MESSAGE_TTL_HOURS: int = 72
    CLEANUP_INTERVAL_SECONDS: int = 300
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
