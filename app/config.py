"""Application configuration. All secrets come from the environment."""
import os
from pathlib import Path

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The project's .env, wherever the app or scripts/rescan.py is launched from.
# Real environment variables still take precedence over the file.
ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ENV_FILE, extra="ignore")

    SECRET_KEY: str = "dev-only-change-me"
    DATABASE_URL: str = "sqlite:///./phishlens.db"
    JWT_EXPIRE_MINUTES: int = 60
    CORS_ORIGINS: str = ""
    SCAN_RATE_LIMIT_PER_HOUR: int = 20
    STRIPE_SECRET_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_PRICE_ID: str = ""
    APP_NAME: str = "PhishLens"
    APP_URL: str = "http://localhost:8000"
    # None = auto: Secure cookies when APP_URL is https
    COOKIE_SECURE: bool | None = None

    @property
    def cookie_secure(self) -> bool:
        if self.COOKIE_SECURE is not None:
            return self.COOKIE_SECURE
        return self.APP_URL.startswith("https://")
    # Outbound email for monitor alerts (optional — leave empty to disable;
    # alerts still appear in the dashboard either way)
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    SMTP_USE_TLS: bool = True
    # Optional VirusTotal reputation badge. Free/public keys are licensed for
    # non-commercial use only: use a premium key before shipping.
    VIRUSTOTAL_API_KEY: str = ""
    VIRUSTOTAL_RATE_PER_MIN: int = 4      # free tier quota
    VIRUSTOTAL_CACHE_HOURS: int = 12

    @model_validator(mode="after")
    def _platform_url(self):
        # Render sets RENDER_EXTERNAL_URL (https://<service>.onrender.com);
        # use it unless APP_URL was configured explicitly.
        render_url = os.environ.get("RENDER_EXTERNAL_URL", "").rstrip("/")
        if render_url and "APP_URL" not in self.model_fields_set:
            self.APP_URL = render_url
        return self

    @field_validator("DATABASE_URL")
    @classmethod
    def _sqlalchemy_scheme(cls, v: str) -> str:
        # Render/Heroku hand out "postgres://" or bare "postgresql://" URLs.
        # SQLAlchemy rejects the first and picks a driver by version for the
        # second, so pin the installed psycopg (v3) driver explicitly.
        for prefix in ("postgres://", "postgresql://"):
            if v.startswith(prefix):
                return "postgresql+psycopg://" + v[len(prefix):]
        return v

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


settings = Settings()
