"""BIMI logo checks: the SVG Tiny Portable/Secure profile mailbox providers
require (draft-brand-indicators-for-message-identification, SVG Tiny PS).

Used by the free logo checker on /tools and by hosted BIMI, which only
stores and serves logos that pass."""
import re
import xml.etree.ElementTree as ET

MAX_BYTES = 32 * 1024
SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"
FORBIDDEN = {"script", "foreignObject", "image", "animate", "animateMotion", "animateColor",
             "animateTransform", "set", "video", "audio", "iframe", "a"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def check_svg(svg: str) -> dict:
    """{ok, errors, warnings, title}. ok means inboxes should accept the
    logo; warnings are about how it will look."""
    errors: list[str] = []
    warnings: list[str] = []
    raw = svg.encode("utf-8")
    if len(raw) > MAX_BYTES:
        errors.append(f"The logo is {len(raw) // 1024} KB; BIMI allows at most 32 KB.")
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", svg, re.I):
        # Never parse entity declarations (entity expansion attacks), and
        # SVG Tiny PS doesn't use them.
        errors.append("Remove the <!DOCTYPE> / <!ENTITY> declaration.")
        return {"ok": False, "errors": errors, "warnings": warnings, "title": None}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        return {"ok": False, "errors": errors + [f"Not valid XML: {exc}."], "warnings": warnings, "title": None}
    if root.tag != f"{{{SVG_NS}}}svg":
        errors.append('The file must be an <svg> element with xmlns="http://www.w3.org/2000/svg".')
        return {"ok": False, "errors": errors, "warnings": warnings, "title": None}
    if root.get("version") != "1.2":
        errors.append('The <svg> element needs version="1.2".')
    if root.get("baseProfile") != "tiny-ps":
        errors.append('The <svg> element needs baseProfile="tiny-ps".')
    if root.get("x") is not None or root.get("y") is not None:
        errors.append("Remove the x= and y= attributes from the <svg> element.")
    title_el = next((c for c in root if _local(c.tag) == "title"), None)
    title = (title_el.text or "").strip() if title_el is not None else ""
    if not title:
        errors.append("Add a <title> element (your brand name) directly inside <svg>.")
    bad = set()
    for el in root.iter():
        name = _local(el.tag)
        if name in FORBIDDEN:
            bad.add(f"<{name}>")
        for attr, value in el.attrib.items():
            a = _local(attr)
            if a.lower().startswith("on"):
                bad.add(f"{a}= (scripting)")
            if a == "href" and not value.startswith("#"):
                bad.add("links to external files")
            if a == "style" and "url(" in value and "url(#" not in value:
                bad.add("links to external files")
    for b in sorted(bad):
        errors.append(f"SVG Tiny PS doesn't allow {b}.")
    box = (root.get("viewBox") or "").replace(",", " ").split()
    if len(box) == 4:
        try:
            w, h = float(box[2]), float(box[3])
            if w <= 0 or h <= 0:
                errors.append("The viewBox width and height must be positive.")
            elif abs(w - h) > 0.01 * max(w, h):
                warnings.append("The logo isn't square. Inboxes show it in a square or circle, so it will be cropped or shrunk.")
        except ValueError:
            errors.append("The viewBox isn't four numbers.")
    else:
        warnings.append("Add a square viewBox (e.g. viewBox=\"0 0 100 100\") so the logo scales cleanly.")
    return {"ok": not errors, "errors": errors, "warnings": warnings, "title": title or None}
