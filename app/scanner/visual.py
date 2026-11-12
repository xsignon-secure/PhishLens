"""Visual lookalike check: does a registered lookalike domain show a copy of
the customer's website?

For each lookalike that has a website, the page is fetched (public hosts
only, through net.safe_fetch_head) and compared with the customer's own page:

- favicon and logo images, by perceptual hash (Pillow dHash), so a resized or
  re-encoded copy of the same icon still matches;
- the page title and the brand name in the visible text;
- whether the page asks for a password (a login form).

With VISUAL_SCREENSHOTS on and the Python `playwright` package with Chromium
installed, a headless browser also takes a screenshot of both pages and
compares those. That needs ~300 MB more RAM, so it's off by default.

The whole check is off unless VISUAL_LOOKALIKE_CHECK is on: it fetches other
people's websites, and a hosted service may not want to do that for everyone.
"""
from __future__ import annotations

import difflib
import hashlib
import html
import io
import logging
import re
import urllib.parse
from datetime import datetime

from ..config import settings
from . import net

log = logging.getLogger("phishlens.visual")

PAGE_LIMIT = 400_000
IMAGE_LIMIT = 300_000
TIMEOUT = 8
MAX_IMAGES = 4
MAX_PER_RUN = 10          # lookalikes compared per monitor per scheduled run
RECHECK_DAYS = 7
IMPERSONATING = 60        # score at or above: looks like a copy of the site
SUSPICIOUS = 35

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_ICON = re.compile(r"<link\b[^>]*\brel=[\"']?[^\"'>]*icon[^\"'>]*[\"']?[^>]*>", re.I)
_IMG = re.compile(r"<img\b[^>]*>", re.I)
_HREF = re.compile(r"\bhref=[\"']([^\"']+)[\"']", re.I)
_SRC = re.compile(r"\bsrc=[\"']([^\"']+)[\"']", re.I)
_ALT = re.compile(r"\b(?:alt|class|id)=[\"']([^\"']*)[\"']", re.I)
_PASSWORD = re.compile(r"<input\b[^>]*type=[\"']?password", re.I)
_TAGS = re.compile(r"<script\b.*?</script>|<style\b.*?</style>|<[^>]+>", re.I | re.S)


def enabled() -> bool:
    return bool(settings.VISUAL_LOOKALIKE_CHECK)


# ------------------------------------------------------------------ fetching
def _fetch(url: str, limit: int) -> tuple[int, bytes] | None:
    try:
        return net.safe_fetch_head(url, timeout=TIMEOUT, limit=limit)
    except Exception:
        return None


def _page(domain: str) -> tuple[str, str] | None:
    """(final base URL, HTML) of the domain's home page."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        got = _fetch(url, PAGE_LIMIT)
        if got and got[0] < 500:
            return url, got[1].decode("utf-8", errors="replace")
    return None


def image_hash(data: bytes) -> str | None:
    """64-bit difference hash, hex; None when it isn't a readable image."""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception:
        return None
    if img.mode in ("RGBA", "LA", "P"):
        bg = Image.new("RGBA", img.size, (255, 255, 255, 255))
        img = Image.alpha_composite(bg, img.convert("RGBA"))
    small = img.convert("L").resize((9, 8), Image.Resampling.LANCZOS)
    px = list(small.getdata())
    bits = 0
    for row in range(8):
        for col in range(8):
            # A small margin keeps flat areas stable after resizing/re-encoding.
            bits = (bits << 1) | (px[row * 9 + col] > px[row * 9 + col + 1] + 4)
    return f"{bits:016x}"


def distance(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def _image_urls(base: str, page: str) -> list[str]:
    urls = []
    for tag in _ICON.findall(page):
        m = _HREF.search(tag)
        if m:
            urls.append(m.group(1))
    urls.append("/favicon.ico")
    for tag in _IMG.findall(page):
        alt = " ".join(_ALT.findall(tag)).lower()
        m = _SRC.search(tag)
        if m and "logo" in (alt + " " + m.group(1).lower()):
            urls.append(m.group(1))
    out = []
    for u in urls:
        if u.startswith("data:"):
            continue
        full = urllib.parse.urljoin(base, html.unescape(u))
        if full not in out and full.startswith(("http://", "https://")):
            out.append(full)
    return out[:MAX_IMAGES]


def _images(base: str, page: str) -> list[dict]:
    out = []
    for url in _image_urls(base, page):
        got = _fetch(url, IMAGE_LIMIT)
        if not got or got[0] >= 400 or not got[1]:
            continue
        h = image_hash(got[1])
        if h:
            out.append({"url": url, "hash": h, "sha": hashlib.sha256(got[1]).hexdigest()})
    return out


def _screenshot_hash(url: str) -> str | None:
    """Optional: a headless browser screenshot, hashed. Needs Playwright."""
    if not settings.VISUAL_SCREENSHOTS:
        return None
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    host = urllib.parse.urlparse(url).hostname or ""
    if not net.is_public_host(host):
        return None

    def guard(route):
        # The browser must not reach private addresses either (SSRF).
        h = urllib.parse.urlparse(route.request.url).hostname or ""
        return route.continue_() if h and net.is_public_host(h) else route.abort()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            try:
                page = browser.new_page(viewport={"width": 1280, "height": 800})
                page.route("**/*", guard)
                page.goto(url, timeout=TIMEOUT * 1000, wait_until="load")
                shot = page.screenshot()
            finally:
                browser.close()
    except Exception:
        log.info("screenshot of %s failed", url, exc_info=True)
        return None
    return image_hash(shot)


def fingerprint(domain: str) -> dict | None:
    """What a site looks like, as far as the comparison needs."""
    got = _page(domain)
    if not got:
        return None
    base, page = got
    m = _TITLE.search(page)
    title = html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:200] if m else ""
    text = html.unescape(re.sub(r"\s+", " ", _TAGS.sub(" ", page))).strip().lower()[:20000]
    return {"url": base, "title": title, "text": text, "login_form": bool(_PASSWORD.search(page)),
            "images": _images(base, page), "screenshot": _screenshot_hash(base)}


# ------------------------------------------------------------------ comparing
def brand_words(domain: str, brand_name: str | None = None) -> list[str]:
    from .lookalike import split_domain
    label, _ = split_domain(domain)
    words = {label.lower()}
    if brand_name:
        name = brand_name.strip().lower()
        if len(name) >= 3:
            words.add(name)
    return sorted(w for w in words if len(w) >= 3)


def compare(brand: dict, look: dict, words: list[str]) -> dict:
    """{score 0-100, verdict, reasons}: how much `look` looks like `brand`."""
    score, reasons = 0, []
    best = None
    for a in brand.get("images") or []:
        for b in look.get("images") or []:
            d = 0 if a["sha"] == b["sha"] else distance(a["hash"], b["hash"])
            best = d if best is None else min(best, d)
    if best is not None and best <= 6:
        score += 45
        reasons.append("Uses the same logo or site icon" if best == 0 else "Uses a near-identical logo or site icon")
    elif best is not None and best <= 12:
        score += 20
        reasons.append("Has a logo or site icon similar to yours")
    if brand.get("screenshot") and look.get("screenshot"):
        d = distance(brand["screenshot"], look["screenshot"])
        if d <= 10:
            score += 35
            reasons.append("The page looks almost the same as your website")
        elif d <= 18:
            score += 15
            reasons.append("The page layout resembles your website")
    if brand.get("title") and look.get("title"):
        ratio = difflib.SequenceMatcher(None, brand["title"].lower(), look["title"].lower()).ratio()
        if ratio >= 0.8:
            score += 20
            reasons.append(f"Same page title: “{look['title'][:80]}”")
        elif ratio >= 0.55:
            score += 10
            reasons.append(f"Similar page title: “{look['title'][:80]}”")
    text = look.get("text") or ""
    named = [w for w in words if re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", text)]
    if named:
        score += 15
        reasons.append(f"Mentions your brand name ({named[0]})")
    if look.get("login_form"):
        score += 15 if score else 5
        reasons.append("Asks for a password")
    score = min(score, 100)
    verdict = "impersonating" if score >= IMPERSONATING else "suspicious" if score >= SUSPICIOUS else "different"
    return {"score": score, "verdict": verdict, "reasons": reasons}


def check(domain: str, lookalike: str, brand_name: str | None = None, brand_fp: dict | None = None) -> dict:
    """Compare one lookalike's website with the brand's. Always returns a dict."""
    now = datetime.utcnow().isoformat() + "Z"
    brand_fp = brand_fp if brand_fp is not None else fingerprint(domain)
    look = fingerprint(lookalike)
    if look is None:
        return {"domain": lookalike, "score": 0, "verdict": "no_site", "reasons": ["No website answered"],
                "login_form": False, "title": None, "checked_at": now}
    if brand_fp is None:
        return {"domain": lookalike, "score": 0, "verdict": "unknown",
                "reasons": [f"Couldn't load {domain} to compare with"], "login_form": look["login_form"],
                "title": look["title"] or None, "checked_at": now}
    out = compare(brand_fp, look, brand_words(domain, brand_name))
    return {"domain": lookalike, **out, "login_form": look["login_form"], "title": look["title"] or None,
            "url": look["url"], "checked_at": now}


def due(previous: dict | None, now: datetime) -> bool:
    if not previous or not previous.get("checked_at"):
        return True
    try:
        at = datetime.fromisoformat(previous["checked_at"].rstrip("Z"))
    except ValueError:
        return True
    return (now - at).days >= RECHECK_DAYS


def check_monitor(monitor, brand_name: str | None, registered: list[dict]) -> list[dict]:
    """Scheduled: compare the monitor's lookalikes that have a website.
    Updates monitor.lookalike_visual; returns the ones that newly look like
    an impersonation."""
    if not enabled():
        return []
    now = datetime.utcnow()
    state = dict(monitor.lookalike_visual or {})
    current = {r["domain"] for r in registered}
    state = {d: v for d, v in state.items() if d in current}
    todo = [r["domain"] for r in registered if r.get("has_web") and due(state.get(r["domain"]), now)][:MAX_PER_RUN]
    if not todo:
        monitor.lookalike_visual = state
        return []
    brand_fp = fingerprint(monitor.domain)
    newly = []
    for name in todo:
        before = (state.get(name) or {}).get("verdict")
        try:
            res = check(monitor.domain, name, brand_name, brand_fp)
        except Exception:
            log.exception("visual check of %s failed", name)
            continue
        state[name] = res
        if res["verdict"] == "impersonating" and before != "impersonating":
            newly.append(res)
    monitor.lookalike_visual = state
    return newly
