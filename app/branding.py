"""White-label branding for MSPs: their name, colour, logo and footer on
reports, PDFs and alert emails instead of PhishLens's."""
import base64
import io
import re


MAX_LOGO_BYTES = 200 * 1024
_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


class BrandingError(ValueError):
    pass


def for_tenant(tenant) -> dict | None:
    """Branding to apply, or None."""
    if tenant is None:
        return None
    if not (tenant.brand_name or tenant.brand_color or tenant.brand_logo or tenant.report_footer):
        return None
    return {"name": tenant.brand_name, "color": tenant.brand_color,
            "footer": tenant.report_footer,
            "logo": base64.b64decode(tenant.brand_logo) if tenant.brand_logo else None,
            "logo_data_url": logo_data_url(tenant.brand_logo)}


def logo_data_url(b64: str | None) -> str | None:
    if not b64:
        return None
    mime = "image/png" if base64.b64decode(b64[:16] + "==")[:4] == b"\x89PNG" else "image/jpeg"
    return f"data:{mime};base64,{b64}"


def clean_color(value: str | None) -> str | None:
    if not value:
        return None
    if not _COLOR.match(value):
        raise BrandingError("Colour must look like #1a2b3c")
    return value.lower()


def clean_logo(b64: str | None) -> str | None:
    """Accept a small PNG or JPEG, re-encoded as PNG so nothing but pixels is kept."""
    if not b64:
        return None
    if "," in b64 and b64.startswith("data:"):
        b64 = b64.split(",", 1)[1]
    try:
        raw = base64.b64decode(b64, validate=True)
    except ValueError:
        raise BrandingError("Logo isn't valid base64")
    if len(raw) > MAX_LOGO_BYTES:
        raise BrandingError("Logo must be under 200 KB")
    if not (raw[:8] == b"\x89PNG\r\n\x1a\n" or raw[:3] == b"\xff\xd8\xff"):
        raise BrandingError("Logo must be a PNG or JPEG")
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(raw))
        img.verify()
        img = Image.open(io.BytesIO(raw))
        if img.width * img.height > 4_000_000:
            raise BrandingError("Logo is too large")
        img.thumbnail((600, 200))
        out = io.BytesIO()
        img.convert("RGBA").save(out, format="PNG")
        raw = out.getvalue()
    except BrandingError:
        raise
    except Exception:
        raise BrandingError("Couldn't read that image")
    return base64.b64encode(raw).decode()
