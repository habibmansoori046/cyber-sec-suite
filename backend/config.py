"""Application configuration — loads from .env or environment variables."""

from pydantic_settings import BaseSettings
from typing import List
import json


class Settings(BaseSettings):
    # ── Database ──────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://cybersec:changeme@localhost:5432/cybersec"

    # ── Redis ─────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── JWT ───────────────────────────────────────────────────
    SECRET_KEY: str = "change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ── AI ────────────────────────────────────────────────────
    ANTHROPIC_API_KEY: str = ""

    # ── Tool Paths ────────────────────────────────────────────
    NMAP_PATH: str = "/usr/bin/nmap"
    ZAP_API_KEY: str = ""
    ZAP_BASE_URL: str = "http://localhost:8080"
    YARA_RULES_DIR: str = "/app/yara_rules"

    # ── App ───────────────────────────────────────────────────
    CORS_ORIGINS: str = '["http://localhost:3000","http://localhost:5173"]'
    LOG_LEVEL: str = "INFO"
    REPORTS_DIR: str = "/app/reports"
    SCAN_RESULTS_DIR: str = "/app/scan_results"

    @property
    def cors_origins_list(self) -> List[str]:
        return json.loads(self.CORS_ORIGINS)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
