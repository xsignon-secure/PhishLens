"""Pydantic schemas for the JSON API."""
from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class ApiKeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class ApiKeyOut(BaseModel):
    id: str
    name: str
    prefix: str
    created_at: str
    last_used_at: str | None = None


class WebhookIn(BaseModel):
    url: str = Field(min_length=1, max_length=500)
    secret: str = Field(min_length=16, max_length=100)


class ScanIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


AlertLevel = Literal["none", "essential", "balanced", "comprehensive"]


class MonitorIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    client: str | None = Field(default=None, max_length=100)
    alert_level: AlertLevel = "balanced"


class MonitorUpdateIn(BaseModel):
    client: str | None = Field(default=None, max_length=100)
    alert_level: AlertLevel | None = None


class BrandingIn(BaseModel):
    brand_name: str | None = Field(default=None, max_length=100)
    brand_color: str | None = Field(default=None, max_length=7)
    report_footer: str | None = Field(default=None, max_length=300)
    logo: str | None = Field(default=None, max_length=400_000)  # base64 / data URL; "" removes
    alert_emails: list[EmailStr] = Field(default_factory=list, max_length=5)


class HeadersIn(BaseModel):
    headers: str = Field(min_length=1, max_length=262144)


class LookalikeIn(BaseModel):
    domain: str = Field(min_length=1, max_length=2048)
