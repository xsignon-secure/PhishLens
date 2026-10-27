"""Branded PDF export of a scan report (reportlab, pure Python, no system deps).

Everything in a scan result can come from the scanned domain's DNS (record
text, hostnames), so every string is XML-escaped before it reaches
reportlab's Paragraph markup.
"""
import io
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from .config import settings

BRAND = colors.HexColor("#4f46e5")
INK = colors.HexColor("#111827")
MUTED = colors.HexColor("#6b7280")
LINE = colors.HexColor("#e5e7eb")
STATUS_COLORS = {"pass": colors.HexColor("#059669"), "warn": colors.HexColor("#d97706"),
                 "fail": colors.HexColor("#dc2626")}
GRADE_COLORS = {"A": "#059669", "B": "#2563eb", "C": "#d97706", "D": "#ea580c", "F": "#dc2626"}

_base = getSampleStyleSheet()
S = {
    "h1": ParagraphStyle("h1", parent=_base["Title"], fontSize=20, leading=24, textColor=INK,
                         alignment=0, spaceAfter=2),
    "h2": ParagraphStyle("h2", parent=_base["Heading2"], fontSize=13, leading=16,
                         textColor=INK, spaceBefore=10, spaceAfter=6),
    "body": ParagraphStyle("body", parent=_base["BodyText"], fontSize=9.5, leading=13, textColor=INK),
    "muted": ParagraphStyle("muted", parent=_base["BodyText"], fontSize=8.5, leading=11, textColor=MUTED),
    "code": ParagraphStyle("code", parent=_base["Code"], fontSize=8, leading=10.5,
                           textColor=INK, backColor=colors.HexColor("#f3f4f6"),
                           leftIndent=0, borderPadding=(3, 3, 3, 3),
                           spaceBefore=5, spaceAfter=3, wordWrap="CJK"),
    "h3": ParagraphStyle("h3", parent=_base["Heading3"], fontSize=11, leading=14,
                         textColor=INK, spaceBefore=4, spaceAfter=2),
    "mono": ParagraphStyle("mono", fontName="Courier", fontSize=8.5, leading=11, textColor=INK,
                           wordWrap="CJK"),
    "warn": ParagraphStyle("warn", parent=_base["BodyText"], fontSize=9, leading=12,
                           textColor=colors.HexColor("#92400e"), backColor=colors.HexColor("#fef3c7"),
                           borderPadding=(3, 3, 3, 3), spaceBefore=4),
    "score": ParagraphStyle("score", fontName="Helvetica-Bold", fontSize=30, leading=34,
                            alignment=TA_CENTER, textColor=colors.white),
    "grade": ParagraphStyle("grade", fontName="Helvetica-Bold", fontSize=11, leading=14,
                            alignment=TA_CENTER, textColor=colors.white),
}


def _p(text, style="body"):
    return Paragraph(escape(str(text if text is not None else "")), S[style])


def _pdf_text(text) -> str:
    # The built-in Helvetica has no arrow glyph.
    return str(text or "").replace("→", ">")


ACTION_WORDS = {"add": "Add this record", "replace": "Change this record", "delete": "Delete this record"}
DIFFICULTY = {"easy": "Easy", "medium": "Medium", "hard": "Needs a technical person"}


def _guide_block(n: int, title: str, points: int | None, g: dict) -> list:
    """One fix card: what's wrong, the record fields, the steps."""
    meta = [f"+{points} points" if points else "", f"about {g['minutes']} min" if g.get("minutes") else "",
            DIFFICULTY.get(g.get("difficulty", ""), "")]
    block = [_p(f"{n}. {_pdf_text(g.get('headline') or title)}", "h3"),
             _p(" · ".join(m for m in meta if m), "muted")]
    if g.get("problem"):
        block.append(_p(_pdf_text(g["problem"])))
    if g.get("why"):
        block.append(_p("Why it matters: " + _pdf_text(g["why"]), "muted"))
    for rec in g.get("records") or []:
        value = rec.get("value") or ("(copy it from your email provider)" if rec.get("value_from_provider") else "")
        rows = [[_p("Type", "muted"), _p(rec.get("type", ""), "mono")],
                [_p("Name / Host", "muted"),
                 _p(f"{rec.get('host', '')}    (full name: {rec.get('fqdn', '')})", "mono")],
                [_p("Value", "muted"), _p(value, "mono")]]
        if rec.get("current"):
            rows.append([_p("Replaces", "muted"), _p(rec["current"], "mono")])
        t = Table(rows, colWidths=[26 * mm, None])
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("BOX", (0, 0), (-1, -1), 0.5, LINE),
                               ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
                               ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f9fafb"))]))
        block += [_p(ACTION_WORDS.get(rec.get("action"), "Add this record") + ":", "body"), t]
        if rec.get("note"):
            block.append(_p(_pdf_text(rec["note"]), "muted"))
    if g.get("file"):
        block += [_p("Publish this file at " + g["file"]["url"] + ":"),
                  Paragraph(escape(g["file"]["content"]).replace("\n", "<br/>"), S["code"])]
    steps = list(g.get("steps") or [])
    recs = g.get("records") or []
    if recs and not all(r.get("value_from_provider") for r in recs):
        steps = ["Sign in where your domain's DNS is managed and open its DNS records.",
                 ("Edit the existing record shown as Replaces, and put in the new value."
                  if recs[0].get("action") == "replace" else
                  "Add a new record and copy each field above into the matching box."),
                 "Save. Changes usually show within 5 minutes, and can take up to an hour."] + steps
    for i, step in enumerate(steps, 1):
        block.append(_p(f"Step {i}: {_pdf_text(step)}"))
    if g.get("warning"):
        block.append(_p("Watch out: " + _pdf_text(g["warning"]), "warn"))
    if g.get("next"):
        block.append(_p("Next: " + _pdf_text(g["next"]), "muted"))
    block.append(Spacer(1, 8))
    return [KeepTogether(block)]


def _date(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        return datetime.fromisoformat(iso.rstrip("Z")).strftime("%d %b %Y")
    except ValueError:
        return iso


def _make_header_footer(brand: dict | None):
    """Page decoration. `brand` (white-label) replaces the PhishLens name,
    colour and footer with the tenant's own."""
    brand = brand or {}
    name = brand.get("name") or settings.APP_NAME
    color = colors.HexColor(brand["color"]) if brand.get("color") else BRAND
    footer = brand.get("footer") or (
        f"Prepared by {name}" if brand.get("name") else f"Generated by {settings.APP_NAME} · {settings.APP_URL}")
    logo = None
    if brand.get("logo"):
        try:
            from reportlab.lib.utils import ImageReader
            logo = ImageReader(io.BytesIO(brand["logo"]))
        except Exception:
            logo = None

    def draw(canvas, doc):
        w, h = A4
        canvas.saveState()
        canvas.setFillColor(color)
        canvas.rect(0, h - 14 * mm, w, 14 * mm, stroke=0, fill=1)
        x = 15 * mm
        if logo is not None:
            iw, ih = logo.getSize()
            lh = 9 * mm
            lw = min(40 * mm, lh * iw / max(ih, 1))
            canvas.drawImage(logo, x, h - 11.5 * mm, width=lw, height=lh, mask="auto",
                             preserveAspectRatio=True)
            x += lw + 3 * mm
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 12)
        canvas.drawString(x, h - 9 * mm, name[:60])
        canvas.setFont("Helvetica", 9)
        canvas.drawRightString(w - 15 * mm, h - 9 * mm, "Email security report")
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(15 * mm, 9 * mm, footer[:150])
        canvas.drawRightString(w - 15 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()
    return draw


_header_footer = _make_header_footer(None)


def render(scan: dict, history: dict | None = None, share_url: str | None = None,
           brand: dict | None = None) -> bytes:
    """Render a scan (engine.scan_to_dict shape, or a bare result dict) to PDF bytes."""
    r = scan.get("result") or scan
    domain = r.get("domain") or scan.get("domain", "")
    score = int(r.get("score", scan.get("score", 0)) or 0)
    grade = str(r.get("grade", scan.get("grade", "F")))
    checks = r.get("checks") or []
    plan = r.get("action_plan") or []
    recs = r.get("recommendations") or []
    rep = r.get("reputation")
    history = history if history is not None else scan.get("history")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=22 * mm, bottomMargin=16 * mm,
                            title=f"{(brand or {}).get('name') or settings.APP_NAME} report: {domain}",
                            author=(brand or {}).get("name") or settings.APP_NAME)
    story = []

    # ---- headline: score tile + domain summary
    fails = sum(1 for c in checks if c.get("status") == "fail")
    warns = sum(1 for c in checks if c.get("status") == "warn")
    tile = Table([[Paragraph(str(score), S["score"])], [Paragraph(f"Grade {escape(grade)}", S["grade"])]],
                 colWidths=[32 * mm], rowHeights=[16 * mm, 7 * mm])
    tile.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(GRADE_COLORS.get(grade, "#dc2626"))),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    summary = [Paragraph(escape(domain), S["h1"]),
               _p(f"Scanned {_date(r.get('scanned_at') or scan.get('created_at'))}", "muted"),
               Spacer(1, 4),
               _p(f"{fails} failing · {warns} warnings · {len(checks)} checks")]
    trend = (history or {}).get("trend")
    if trend:
        d = trend["delta"]
        word = "up" if d > 0 else "down" if d < 0 else "unchanged"
        summary.append(_p(f"Score {word}: {trend['from_score']} → {trend['to_score']} "
                          f"since {_date(trend['since'])}"))
    if rep:
        if rep.get("known"):
            flagged = rep["malicious"] + rep["suspicious"]
            summary.append(_p(f"VirusTotal reputation: flagged by {flagged}/{rep['total']} vendors"))
        else:
            summary.append(_p("VirusTotal reputation: domain not yet analysed"))
    head = Table([[tile, summary]], colWidths=[36 * mm, None])
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                              ("LEFTPADDING", (0, 0), (0, 0), 0)]))
    story += [head, Spacer(1, 6)]

    # ---- action plan
    story.append(Paragraph("Fix these first", S["h2"]))
    guided = [c for c in checks if c.get("guide")]
    if plan:
        n = 0
        for item in plan:
            n += 1
            if item.get("guide"):
                story += _guide_block(n, item.get("check", ""), item.get("points"), item["guide"])
            else:
                story.append(KeepTogether([
                    _p(f"{n}. {item.get('check', '')}  (+{item.get('points', 0)} pts)"),
                    _p(item.get("fix", ""), "code"), Spacer(1, 4)]))
        planned = {item.get("check") for item in plan}
        rest = [c for c in guided if c.get("title") not in planned]
        if rest:
            story.append(Paragraph("Other fixes", S["h2"]))
            for c in rest:
                n += 1
                story += _guide_block(n, c.get("title", ""), (c.get("max_score") or 0) - (c.get("score") or 0),
                                      c["guide"])
    else:
        story.append(_p("Nothing urgent: this domain is in great shape."))

    # ---- findings table
    story.append(Paragraph("Findings", S["h2"]))
    rows = [[_p("Status", "muted"), _p("Check", "muted"), _p("Points", "muted"), _p("Details", "muted")]]
    for c in checks:
        status = c.get("status", "")
        badge = Paragraph(f'<font color="{STATUS_COLORS.get(status, MUTED).hexval()}"><b>'
                          f'{escape(status.upper())}</b></font>', S["body"])
        detail = [_p(c.get("details", ""))]
        detail += [_p("• " + str(x), "muted") for x in c.get("issues") or []]
        if c.get("guide"):
            detail.append(_p("Fix: " + _pdf_text(c["guide"].get("headline", "")) + " (see above)", "muted"))
        else:
            detail += [_p(f, "code") for f in c.get("fixes") or []]
        rows.append([badge, _p(c.get("title", "")), _p(f"{c.get('score', 0)}/{c.get('max_score', 0)}"),
                     detail])
    table = Table(rows, colWidths=[17 * mm, 30 * mm, 16 * mm, None], repeatRows=1)
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(table)

    # ---- next steps beyond DNS
    for rec in recs:
        block = [Paragraph(escape(rec.get("headline", "")), S["h2"]), _p(rec.get("body", ""))]
        for prod in rec.get("products") or []:
            block.append(_p(f"• {prod.get('name', '')}: {prod.get('blurb', '')}"))
        if rec.get("cta"):
            block.append(_p(f"{rec['cta'].get('label', '')}: {rec['cta'].get('href', '')}", "muted"))
        story.append(KeepTogether(block))

    story.append(Spacer(1, 10))
    if share_url:
        story.append(_p(f"Live report: {share_url}", "muted"))
    if rep and rep.get("url"):
        story.append(_p(f"VirusTotal report: {rep['url']}", "muted"))

    deco = _make_header_footer(brand)
    doc.build(story, onFirstPage=deco, onLaterPages=deco)
    return buf.getvalue()
