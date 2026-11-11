"""Page-level checks for the web UI that need no browser."""
import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.database import Base, engine as sa_engine
from app.main import app

TEMPLATES = Path("app/templates")


def test_dashboard_calls_only_defined_loaders():
    # A loader called but never defined throws a ReferenceError that stops
    # every later panel (API keys, webhooks, audit log) from loading.
    src = (TEMPLATES / "dashboard.html").read_text(encoding="utf-8") + Path("app/static/app.js").read_text(encoding="utf-8")
    called = set(re.findall(r"\b(load[A-Z]\w*)\(\)", src))
    defined = set(re.findall(r"(?:async\s+)?function\s+(load[A-Z]\w*)\s*\(", src))
    assert called <= defined, called - defined


def test_pages_have_theme_toggle_and_new_footer():
    Base.metadata.create_all(bind=sa_engine)
    c = TestClient(app)
    for path in ("/", "/tools", "/login", "/help"):
        html = c.get(path).text
        assert 'id="theme-toggle"' in html and 'class="site-footer"' in html, path
        assert "phishlens_theme" in html  # theme is applied before first paint


def test_stylesheet_has_light_and_dark_tokens():
    css = Path("app/static/style.css").read_text(encoding="utf-8")
    assert '[data-theme="dark"]' in css
    # Text colours come from tokens, so dark-only white text can't creep back in.
    assert "color: #fff;" not in css
