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
    # Sessions: a short access token, renewed from a rotating refresh token
    # until the session has been idle too long or reaches its maximum age.
    ACCESS_TOKEN_MINUTES: int = 15
    SESSION_IDLE_MINUTES: int = 120
    SESSION_MAX_HOURS: int = 12
    # Platform admin password (/platform): creates companies and their owners.
    # It never opens a company's data. Empty = platform page off.
    ADMIN_PASSWORD: str = ""
    # Temporary passwords that admins send to new users expire after this.
    TEMP_PASSWORD_HOURS: int = 72
    # Refuse passwords found in breaches (Have I Been Pwned range API: only
    # the first 5 characters of the SHA-1 leave the server).
    PASSWORD_BREACH_CHECK: bool = True
    # Login-details emails each company can send per hour.
    CREDENTIAL_EMAILS_PER_HOUR: int = 50
    CORS_ORIGINS: str = ""
    SCAN_RATE_LIMIT_PER_HOUR: int = 20
    # Optional per-team cap on monitored domains for public instances (0 = unlimited).
    MAX_MONITORS_PER_TEAM: int = 0
    # Hosted plans (Free / Pro / MSP, set per company at /platform). Off = every
    # company gets everything, which is what a self-hosted copy wants.
    PLANS_ENABLED: bool = False
    # Public sign-up at /signup: anyone with a working email address gets a
    # free company account (login details go to that address, which proves
    # it is theirs). Off = companies are created at /platform only. Needs the
    # server mail settings (SMTP_*).
    SIGNUP_ENABLED: bool = False
    SIGNUPS_PER_IP_PER_HOUR: int = 5
    SIGNUPS_PER_HOUR: int = 100
    # Shown on the Terms/Privacy pages and footer of your instance.
    CONTACT_EMAIL: str = ""
    SOURCE_URL: str = "https://github.com/xsignon-secure/PhishLens"
    # Rescan monitors from inside the app every N hours (0 = off; use cron instead).
    RESCAN_INTERVAL_HOURS: float = 0
    # Fetch DMARC / TLS-RPT reports from the report mailbox every N minutes (0 = off).
    REPORT_FETCH_MINUTES: float = 0
    # "memory" (one worker) or "database" (shared by several workers/instances).
    RATE_LIMIT_STORAGE: str = "memory"
    # RPKI check for mail server routes; asks RIPEstat (an external API), so opt-in.
    RPKI_CHECK: bool = False
    # Post-quantum (ML-KEM) key exchange test against the website; needs Python 3.15+
    # with OpenSSL 3.5+, and reports "not checked" elsewhere.
    PQC_CHECK: bool = True
    # Visual lookalike check: fetch registered lookalike domains' websites and
    # compare logo, site icon, title and brand name with yours. Off by default
    # (it fetches other people's websites). VISUAL_SCREENSHOTS also compares
    # headless-browser screenshots; needs `pip install playwright` and
    # `playwright install chromium`, and ~300 MB more RAM.
    VISUAL_LOOKALIKE_CHECK: bool = False
    VISUAL_SCREENSHOTS: bool = False
    # Optional GeoIP country database (.mmdb) for DMARC report senders; needs
    # `pip install maxminddb`. Free: DB-IP Lite Country or MaxMind GeoLite2 Country.
    GEOIP_DB: str = ""
    # Hosted DMARC / SPF / MTA-STS records live in a zone PhishLens controls
    # (e.g. "hosted.phishlens.example") on Cloudflare DNS. Leave empty to
    # disable hosting.
    HOSTED_ZONE: str = ""
    HOSTED_CLOUDFLARE_TOKEN: str = ""
    HOSTED_CLOUDFLARE_ZONE_ID: str = ""
    # Default rua= for hosted DMARC records: the mailbox read by
    # scripts/fetch_dmarc_reports.py.
    HOSTED_DMARC_RUA: str = ""
    # Domain Connect one-click publishing (docs/DOMAIN-CONNECT.md). Off unless
    # all three are set and the templates are registered with DNS hosts.
    DOMAIN_CONNECT_PROVIDER_ID: str = ""
    DOMAIN_CONNECT_PROVIDER_NAME: str = "PhishLens"
    DOMAIN_CONNECT_PRIVATE_KEY: str = ""  # PEM; "\n" escapes are fine
    DOMAIN_CONNECT_KEY_DOMAIN: str = ""   # where the public key TXT records live
    DOMAIN_CONNECT_KEY_ID: str = "_dck1"
    # TLS-RPT report mailbox for hosted TLS-RPT (defaults to HOSTED_DMARC_RUA).
    HOSTED_TLSRPT_RUA: str = ""
    # "Send a test email" analyzer: an address in the report mailbox that
    # scripts/fetch_dmarc_reports.py reads. Each test gets local+token@domain,
    # so the mailbox must accept plus addressing (Gmail, Microsoft 365 and
    # most hosts do).
    MAILTEST_ADDRESS: str = ""
    # Hostname customers CNAME mta-sts.<their domain> to (defaults to APP_URL's host).
    MTA_STS_TARGET: str = ""
    # Optional: let PhishLens add mta-sts.<domain> as a Render custom domain
    # (Render then issues its TLS certificate).
    RENDER_API_KEY: str = ""
    RENDER_SERVICE_ID: str = ""
    APP_NAME: str = "PhishLens"
    # AI assistant: a server-wide Anthropic API key (optional). Companies can
    # also bring their own key in the dashboard, which is used instead.
    ANTHROPIC_API_KEY: str = ""
    ASSISTANT_MODEL: str = "claude-opus-5-5"
    # Or a server-wide key for any other provider (see app/ai_providers.py):
    # AI_PROVIDER=openai AI_API_KEY=... AI_MODEL=... (AI_BASE_URL for custom/azure).
    AI_PROVIDER: str = ""
    # Plain-language summary on every report, written by the server's AI key
    # (never a company's). Capped per day; above the cap, or with no key, a
    # fixed-text summary is shown instead. SUMMARY_MODEL defaults to the
    # provider's model, or claude-haiku-5-5 with ANTHROPIC_API_KEY.
    PUBLIC_AI_SUMMARY: bool = True
    PUBLIC_AI_SUMMARY_DAILY_LIMIT: int = 300
    SUMMARY_MODEL: str = ""
    AI_API_KEY: str = ""
    AI_MODEL: str = ""
    AI_BASE_URL: str = ""
    # Self-hosted only: let companies point the assistant at a private or
    # http endpoint (e.g. Ollama on the local network). Keep off when hosted.
    AI_ALLOW_PRIVATE_ENDPOINTS: bool = False
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
    # Optional VirusTotal reputation badge. The free public API key is fine for
    # this non-commercial tool; each self-hoster uses their own key.
    VIRUSTOTAL_API_KEY: str = ""
    VIRUSTOTAL_RATE_PER_MIN: int = 4      # free tier quota
    VIRUSTOTAL_CACHE_HOURS: int = 12
    # Phishing URL checker (/tools). RDAP gives domain age; the feeds are opt-in.
    URL_CHECK_RDAP: bool = True
    SAFE_BROWSING_API_KEY: str = ""
    URLHAUS_AUTH_KEY: str = ""
    OPENPHISH_FEED: bool = False

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
