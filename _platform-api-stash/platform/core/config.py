"""Configuration management using Pydantic Settings"""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    """Application settings"""

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite:///./sysscore.db"

    # Redis (for caching and idempotency)
    REDIS_URL: str = "redis://localhost:6379/0"

    # CORS
    CORS_ORIGINS: List[str] = ["*"]

    # Auth
    HMAC_SECRET_KEY: str = "change-me-in-production"
    OAUTH2_SECRET_KEY: str = "change-me-in-production"
    OAUTH2_ALGORITHM: str = "HS256"

    # Agent auth (pre-shared keys per agent)
    AGENT_KEYS: dict = {}  # agent_id -> secret_key mapping

    # Webhooks
    WEBHOOK_TIMEOUT: int = 5  # seconds
    WEBHOOK_MAX_RETRIES: int = 3
    WEBHOOK_BACKOFF_BASE: float = 2.0

    # Pagination
    DEFAULT_PAGE_SIZE: int = 100
    MAX_PAGE_SIZE: int = 1000

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 1000

    # Logging
    LOG_LEVEL: str = "INFO"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()

