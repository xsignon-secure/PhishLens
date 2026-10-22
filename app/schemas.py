"""Pydantic schemas for the JSON API."""
from pydantic import BaseModel, EmailStr, Field


class SignupIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    company: str = Field(min_length=1, max_length=200)
    invite_token: str | None = None


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class MfaChallengeIn(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=8)


class MfaVerifyIn(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class MfaDisableIn(BaseModel):
    password: str


class PasswordForgotIn(BaseModel):
    email: EmailStr


class PasswordResetIn(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=72)


class VerifyEmailIn(BaseModel):
    token: str


class UserOut(BaseModel):
    id: str
    email: str
    role: str
    tenant_id: str
    tenant_name: str
    is_verified: bool = False
    mfa_enabled: bool = False


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class MfaRequiredOut(BaseModel):
    mfa_required: bool = True
    mfa_token: str


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


class InviteIn(BaseModel):
    email: EmailStr


class ScanIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


class MonitorIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    client: str | None = Field(default=None, max_length=100)


class MonitorUpdateIn(BaseModel):
    client: str | None = Field(default=None, max_length=100)


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
