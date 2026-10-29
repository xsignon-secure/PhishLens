"""Interface translations for the public pages.

Catalogs live in app/locales/<lang>.json and map the English text, exactly as
written in the templates' _("...") calls, to the translation. A missing entry
falls back to English, so a partial catalog is safe. The language comes from
the `lang` cookie (set by the footer picker), then Accept-Language.
"""
import json
from pathlib import Path

from jinja2 import pass_context
from markupsafe import Markup

LANGS = {"en": "English", "es": "Español", "fr": "Français", "de": "Deutsch",
         "pt": "Português", "hi": "हिन्दी", "it": "Italiano", "nl": "Nederlands", "ja": "日本語"}
_DIR = Path(__file__).resolve().parent / "locales"
_catalogs: dict[str, dict[str, str]] = {
    p.stem: json.loads(p.read_text(encoding="utf-8")) for p in _DIR.glob("*.json") if p.stem in LANGS}


def pick(request) -> str:
    if request is None:
        return "en"
    cookie = (request.cookies.get("lang") or "").lower()
    if cookie in LANGS:
        return cookie
    ranked = []
    for part in request.headers.get("accept-language", "").split(","):
        tag, _, q = part.strip().partition(";q=")
        try:
            ranked.append((float(q) if q else 1.0, tag.split("-")[0].lower()))
        except ValueError:
            continue
    for _, tag in sorted(ranked, key=lambda x: -x[0]):
        if tag in LANGS:
            return tag
    return "en"


def translate(lang: str, text: str) -> str:
    return _catalogs.get(lang, {}).get(text) or text


@pass_context
def gettext(ctx, text: str) -> Markup:
    # Catalogs are part of the codebase (reviewed like templates), so their
    # text is trusted markup, the same as the template it replaces.
    return Markup(translate(pick(ctx.get("request")), text))


@pass_context
def current_lang(ctx) -> str:
    return pick(ctx.get("request"))


@pass_context
def catalog(ctx) -> dict:
    """The current language's catalog, for the page's JavaScript (_t in app.js)."""
    return _catalogs.get(pick(ctx.get("request")), {})


def install(env) -> None:
    env.globals.update(_=gettext, current_lang=current_lang, languages=LANGS, i18n_catalog=catalog)
