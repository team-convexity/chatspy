from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """
    Environment-based configuration
    """
    
    ENV: str = "development"
    LOG_LEVEL: str = "INFO"
    DATABASE_URL: str | None = None
    
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8",
        extra="ignore"
    )

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

# quick access to configuration
settings = get_settings()
