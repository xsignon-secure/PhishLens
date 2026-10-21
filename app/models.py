"""Data model.

Multi-tenancy: every tenant-owned row carries tenant_id. All queries MUST
filter by tenant_id (see app/deps.py). There is no code path that reads
another tenant's rows.
"""
import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from .database import Base


def _uid() -> str:
    return uuid.uuid4().hex


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String(32), primary_key=True, default=_uid)
    name = Column(String(200), nullable=False)
    plan = Column(String(20), nullable=False, default="free")  # free | pro
    stripe_customer_id = Column(String(100), nullable=True)
    webhook_url = Column(String(500), nullable=True)
    webhook_secret = Column(String(100), nullable=True)
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
    role = Column(String(20), nullable=False, default="owner")  # owner | member
    is_active = Column(Boolean, nullable=False, default=True)
    is_verified = Column(Boolean, nullable=False, default=False)
    totp_secret = Column(String(64), nullable=True)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    tenant = relationship("Tenant", back_populates="users")


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

    tenant = relationship("Tenant", back_populates="monitors")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(32), primary_key=True, default=_uid)
    tenant_id = Column(String(32), ForeignKey("tenants.id"), nullable=False, index=True)
    monitor_id = Column(String(32), ForeignKey("monitors.id"), nullable=False)
    kind = Column(String(40), nullable=False)  # score_drop | check_failed | cert_expiring
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


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
