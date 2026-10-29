"""Data model.

Multi-tenancy: every tenant-owned row carries tenant_id. All queries MUST
filter by tenant_id (see app/deps.py). There is no code path that reads
another tenant's rows.
"""
import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, false
from sqlalchemy.orm import relationship

from .database import Base


def _uid() -> str:
    return uuid.uuid4().hex


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String(32), primary_key=True, default=_uid)
    name = Column(String(200), nullable=False)
    webhook_url = Column(String(500), nullable=True)
    webhook_secret = Column(String(100), nullable=True)
    # White-label branding for reports, PDFs and alert emails (MSPs).
    brand_name = Column(String(100), nullable=True)
    brand_color = Column(String(7), nullable=True)  # "#rrggbb"
    brand_logo = Column(Text, nullable=True)  # base64 PNG/JPEG, small
    report_footer = Column(String(300), nullable=True)
    # Extra alert recipients, e.g. a PSA's email-to-ticket inbox.
    alert_emails = Column(JSON, nullable=True)
    # Scheduled PDF reports by email: off | weekly | monthly.
    report_schedule = Column(String(10), nullable=False, default="off", server_default="off")
    report_sent_at = Column(DateTime, nullable=True)
    # Alert exports (app/integrations.py). Secrets inside are encrypted.
    siem = Column(JSON, nullable=True)
    psa = Column(JSON, nullable=True)
    # SSO (OpenID Connect). Secrets are stored encrypted (app/crypto.py).
    sso_issuer = Column(String(300), nullable=True)
    sso_client_id = Column(String(300), nullable=True)
    sso_client_secret = Column(Text, nullable=True)
    sso_email_domain = Column(String(253), nullable=True, unique=True)
    sso_enforced = Column(Boolean, nullable=False, default=False)
    # Everyone signing in with a password must use an authenticator app.
    mfa_required = Column(Boolean, nullable=False, default=False)
    # Unused since SCIM was removed; kept so old databases need no migration.
    scim_token_hash = Column(String(64), nullable=True, unique=True)
    # PGP public key: failure (RUF) report details are stored encrypted to it.
    ruf_pgp_key = Column(Text, nullable=True)
    ruf_pgp_fingerprint = Column(String(64), nullable=True)
    sso_protocol = Column(String(10), nullable=True)  # oidc | saml (None = oidc for older rows)
    saml_entity_id = Column(String(500), nullable=True)
    saml_sso_url = Column(String(1000), nullable=True)
    saml_idp_cert = Column(Text, nullable=True)
    # Customer's own DNS provider for one-click fixes; the token is encrypted.
    dns_provider = Column(String(20), nullable=True)  # cloudflare | digitalocean | desec
    dns_token = Column(Text, nullable=True)
    # active | suspended. A suspended company can't sign in; its data is kept.
    status = Column(String(20), nullable=False, default="active", server_default="active")
    # The company's own outgoing mail server for login details and alerts:
    # {host, port, security, username, password (encrypted), from_address,
    # from_name}. The password is write-only: no API returns it.
    smtp = Column(JSON, nullable=True)
    # Optional wording for the login-details email (plain text).
    welcome_subject = Column(String(200), nullable=True)
    welcome_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="tenant", cascade="all, delete-orphan")
    monitors = relationship("Monitor", back_populates="tenant", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(String(32), primary_key=True, default=_uid)
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=False, index=True)
    email = Column(String(320), nullable=False, unique=True, index=True)
    password_hash = Column(String(200), nullable=False)
    full_name = Column(String(200), nullable=True)
    # owner (created by the platform admin) | admin | member
    role = Column(String(20), nullable=False, default="member")
    # pending (temporary password not changed yet) | active | suspended
    status = Column(String(20), nullable=False, default="active", server_default="active")
    is_active = Column(Boolean, nullable=False, default=True)
    # Accounts are created by an admin with a one-time temporary password.
    must_change_password = Column(Boolean, nullable=False, default=False, server_default=false())
    temp_password_expires_at = Column(DateTime, nullable=True)
    # Brute-force lockout: consecutive failures and when the lock lifts.
    failed_logins = Column(Integer, nullable=False, default=0, server_default="0")
    locked_until = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    # sha256 of each unused one-time recovery code for the authenticator app.
    recovery_codes = Column(JSON, nullable=True)
    # Login-details email: sending | sent | failed | manual (shown to the admin).
    credentials_status = Column(String(20), nullable=True)
    credentials_error = Column(String(300), nullable=True)
    credentials_sent_at = Column(DateTime, nullable=True)
    is_verified = Column(Boolean, nullable=False, default=False)
    totp_secret = Column(String(200), nullable=True)  # Fernet-encrypted (app/crypto.py)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    # Last TOTP time-step accepted: a code can't be used twice.
    totp_last_step = Column(Integer, nullable=True)
    # Bumped to sign out every session (password reset, "sign out everywhere").
    token_version = Column(Integer, nullable=False, default=0, server_default="0")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    tenant = relationship("Tenant", back_populates="users")


class UserSession(Base):
    """One signed-in browser or device. The access token names its session,
    so ending the session ends the access token too. Refresh tokens rotate on
    every use; presenting an old one again ends the whole session (replay)."""
    __tablename__ = "user_sessions"

    id = Column(String(32), primary_key=True, default=_uid)
    user_id = Column(String(32), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=False, index=True)
    refresh_hash = Column(String(64), nullable=False, unique=True, index=True)
    prev_refresh_hash = Column(String(64), nullable=True, index=True)
    rotated_at = Column(DateTime, nullable=True)
    device = Column(String(200), nullable=True)
    ip = Column(String(64), nullable=True)
    mfa_at = Column(DateTime, nullable=True)  # last authenticator-code check (step-up)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(40), nullable=True)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(32), primary_key=True, default=_uid)
    # tenant_id NULL => anonymous public scan (the funnel). Never listed for any tenant.
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=True, index=True)
    domain = Column(String(253), nullable=False, index=True)
    score = Column(Integer, nullable=False)
    grade = Column(String(2), nullable=False)
    result = Column(JSON, nullable=False)  # full check breakdown
    is_public = Column(Boolean, nullable=False, default=False)  # shareable link
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    tenant = relationship("Tenant", back_populates="scans")


class Monitor(Base):
    __tablename__ = "monitors"
    __table_args__ = (UniqueConstraint("tenant_id", "domain", name="uq_monitor_tenant_domain"),)

    id = Column(String(32), primary_key=True, default=_uid)
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=False, index=True)
    domain = Column(String(253), nullable=False)
    last_score = Column(Integer, nullable=True)
    last_checked_at = Column(DateTime, nullable=True)
    alert_on_drop = Column(Boolean, nullable=False, default=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    # Registered lookalike domains seen at the last scheduled check, so the
    # next check alerts only on newly registered ones.
    lookalikes = Column(JSON, nullable=True)
    lookalikes_checked_at = Column(DateTime, nullable=True)
    client = Column(String(100), nullable=True)  # MSP: which customer this domain belongs to
    # What raises an alert on rescans: none | essential | balanced | comprehensive
    alert_level = Column(String(20), nullable=False, default="balanced", server_default="balanced")

    tenant = relationship("Tenant", back_populates="monitors")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(32), primary_key=True, default=_uid)
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=False, index=True)
    monitor_id = Column(String(32), ForeignKey("monitors.id"), nullable=False)
    kind = Column(String(40), nullable=False)  # score_drop | check_failed | cert_expiring
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class DnsChange(Base):
    """One email-security DNS record that changed between two monitor scans.
    Kept whatever the alert level, so the timeline is complete."""
    __tablename__ = "dns_changes"

    id = Column(String(32), primary_key=True, default=_uid)
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=False, index=True)
    monitor_id = Column(String(32), ForeignKey("monitors.id"), nullable=False, index=True)
    domain = Column(String(253), nullable=False)
    record = Column(String(20), nullable=False)  # SPF | DMARC | DKIM | MX | NS | A ...
    old = Column(JSON, nullable=False)
    new = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class ApiKey(Base):
    """Tenant-scoped keys for automation/SIEM integrations. Only the hash is stored."""
    __tablename__ = "api_keys"

    id = Column(String(32), primary_key=True, default=_uid)
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=False, index=True)
    user_id = Column(String(32), ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)  # sha256 hex
    prefix = Column(String(12), nullable=False)  # first chars, for identification
    last_used_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class AuthToken(Base):
    """Single-use tokens: email verification, password reset, team invites."""
    __tablename__ = "auth_tokens"

    id = Column(String(32), primary_key=True, default=_uid)
    user_id = Column(String(32), ForeignKey("users.id"), nullable=True, index=True)
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=True, index=True)
    purpose = Column(String(30), nullable=False, index=True)  # verify_email | password_reset | invite
    token_hash = Column(String(64), nullable=False, unique=True, index=True)  # sha256 hex
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    extra = Column(JSON, nullable=True)  # e.g. {"email": ..., "role": "member"}
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class AuditEvent(Base):
    """Append-only security audit log. Never updated or deleted by the app."""
    __tablename__ = "audit_events"

    id = Column(String(32), primary_key=True, default=_uid)
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=True, index=True)
    user_id = Column(String(32), ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(60), nullable=False, index=True)
    detail = Column(JSON, nullable=True)
    ip = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class DmarcReport(Base):
    """One DMARC aggregate (RUA) report, as sent by a mailbox provider."""
    __tablename__ = "dmarc_reports"
    __table_args__ = (UniqueConstraint("tenant_id", "org_name", "report_id",
                                       name="uq_dmarc_report_tenant_org_id"),)

    id = Column(String(32), primary_key=True, default=_uid)
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=False, index=True)
    domain = Column(String(253), nullable=False, index=True)
    org_name = Column(String(200), nullable=False)
    report_id = Column(String(200), nullable=False)
    date_begin = Column(DateTime, nullable=True, index=True)
    date_end = Column(DateTime, nullable=True)
    policy = Column(JSON, nullable=True)
    records = Column(JSON, nullable=False)
    message_count = Column(Integer, nullable=False, default=0)
    pass_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ForensicReport(Base):
    """One DMARC failure (RUF / ARF) report. Only headers are kept: never the
    message body, which can contain the recipient's mail."""
    __tablename__ = "forensic_reports"

    id = Column(String(32), primary_key=True, default=_uid)
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=False, index=True)
    domain = Column(String(253), nullable=False, index=True)
    reporter = Column(String(200), nullable=True)
    source_ip = Column(String(64), nullable=True)
    arrival_date = Column(DateTime, nullable=True)
    auth_failure = Column(String(100), nullable=True)
    delivery_result = Column(String(50), nullable=True)
    original_mail_from = Column(String(320), nullable=True)
    header_from = Column(String(320), nullable=True)
    subject = Column(String(300), nullable=True)
    auth_results = Column(Text, nullable=True)
    # With a team PGP key, the fields above that identify people (From,
    # MAIL FROM, subject, Authentication-Results) live only in here.
    encrypted = Column(Text, nullable=True)
    fingerprint = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (UniqueConstraint("tenant_id", "fingerprint", name="uq_forensic_tenant_fp"),)


class HostedRecord(Base):
    """A DMARC / SPF / MTA-STS record PhishLens publishes on a customer's
    behalf. The customer delegates once (CNAME or include) and later changes
    are made here instead of in their DNS."""
    __tablename__ = "hosted_records"
    __table_args__ = (UniqueConstraint("tenant_id", "domain", "kind", name="uq_hosted_tenant_domain_kind"),)

    id = Column(String(32), primary_key=True, default=_uid)
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=False, index=True)
    domain = Column(String(253), nullable=False, index=True)
    kind = Column(String(20), nullable=False)  # dmarc | spf | mta_sts
    config = Column(JSON, nullable=False)
    published = Column(JSON, nullable=True)  # {record name: value} last pushed to DNS
    policy_id = Column(String(32), nullable=True)  # MTA-STS id, changes with the policy
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class TlsReport(Base):
    """One SMTP TLS report (TLS-RPT, RFC 8460): how sending servers fared
    when they tried to deliver to this domain over TLS."""
    __tablename__ = "tls_reports"
    __table_args__ = (UniqueConstraint("tenant_id", "org_name", "report_id",
                                       name="uq_tls_report_tenant_org_id"),)

    id = Column(String(32), primary_key=True, default=_uid)
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=False, index=True)
    domain = Column(String(253), nullable=False, index=True)
    org_name = Column(String(200), nullable=False)
    report_id = Column(String(200), nullable=False)
    date_begin = Column(DateTime, nullable=True, index=True)
    date_end = Column(DateTime, nullable=True)
    policies = Column(JSON, nullable=False)
    success_count = Column(Integer, nullable=False, default=0)
    failure_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class JobLease(Base):
    """A short lease so only one worker/instance runs a scheduled job."""
    __tablename__ = "job_leases"

    name = Column(String(50), primary_key=True)
    holder = Column(String(64), nullable=False)
    expires_at = Column(DateTime, nullable=False)


class RateCounter(Base):
    """Fixed-window request counters, used when RATE_LIMIT_STORAGE=database so
    limits hold across several workers or instances."""
    __tablename__ = "rate_counters"

    key = Column(String(200), primary_key=True)
    window_start = Column(DateTime, nullable=False)
    count = Column(Integer, nullable=False, default=0)


class MailTest(Base):
    """One "send a test email" check: the user mails a one-off address and the
    report-mailbox fetcher stores what the receiving server saw."""
    __tablename__ = "mail_tests"

    id = Column(String(32), primary_key=True, default=_uid)
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=False, index=True)
    user_id = Column(String(32), ForeignKey("users.id"), nullable=False)
    token = Column(String(32), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    received_at = Column(DateTime, nullable=True)
    result = Column(JSON, nullable=True)
