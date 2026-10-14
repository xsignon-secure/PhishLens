"""Local preview QA v2: render a realistic canned scan through the REAL
renderReport()/bindReportInteractions() pipeline (the sandbox intercepts DNS,
so live scans are blocked by the SSRF guard here — correctly)."""
import asyncio
import json
import time
from playwright.async_api import async_playwright

BASE = "http://localhost:8000"
OUT = "/home/hatch/workspace/phishlens/preview"
EMAIL = f"preview-qa-{int(time.time())}@example.com"

# Realistic canned result, modeled on a typical mid-size company scan.
CANNED = {
    "domain": "example.com",
    "score": 64,
    "grade": "D",
    "scanned_at": "2026-10-09 15:58 UTC",
    "action_plan": [
        {"check": "DMARC", "points": 14,
         "fix": "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; fo=1"},
        {"check": "MTA-STS", "points": 6,
         "fix": "v=STSv1; id=20261009;"},
        {"check": "Web Security Headers", "points": 5,
         "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains"},
    ],
    "recommendations": [{
        "headline": "DNS fixes stop spoofing. They don't stop phishing.",
        "body": ("The records above stop attackers from sending email as YOUR domain — and they "
                 "are free to publish. What they cannot stop is an attacker emailing your team "
                 "from a lookalike domain and harvesting logins on a fake sign-in page. That is "
                 "how most breaches begin, and no DNS record fixes it. XSignOn AUTH BioPro "
                 "replaces passwords with hardware-bound FIDO2 credentials verified by on-device "
                 "fingerprint: there is no password to steal, and a fake login page cannot "
                 "complete the authentication. AMS provisions, monitors, and retires every key "
                 "across your workforce — with the audit evidence regulated environments need."),
        "products": [
            {"name": "AUTH BioPro",
             "blurb": "Phishing-resistant MFA: FIDO2 security key with on-device fingerprint."},
            {"name": "AMS",
             "blurb": "Authenticator lifecycle management: issuance to retirement, audit-ready."},
        ],
        "cta": {"label": "Get an enterprise quote", "href": "mailto:info@xsignon.com"},
        "contact": "info@xsignon.com · +1 469-897-9399",
    }],
    "checks": [
        {"title": "SPF", "status": "warn", "score": 6, "max_score": 10,
         "details": "SPF record published, but it authorizes a broad range and uses the ptr mechanism.",
         "issues": ["ptr mechanism causes slow, unreliable lookups", "includes a /16 network — overly broad"],
         "fixes": ["v=spf1 ip4:203.0.113.0/24 include:_spf.example.net -all"]},
        {"title": "DKIM", "status": "pass", "score": 10, "max_score": 10,
         "details": "Valid DKIM key found (selector 's1', 2048-bit RSA).", "issues": [], "fixes": []},
        {"title": "DMARC", "status": "fail", "score": 0, "max_score": 14,
         "details": "DMARC record exists but policy is 'none' — receivers take no action on forged mail.",
         "issues": ["Policy 'none' does not block spoofed mail", "No aggregate reports configured"],
         "fixes": ["v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; fo=1"]},
        {"title": "MX", "status": "pass", "score": 6, "max_score": 6,
         "details": "Two mail exchangers configured with valid hostnames.", "issues": [], "fixes": []},
        {"title": "SMTP TLS", "status": "pass", "score": 5, "max_score": 5,
         "details": "STARTTLS offered on all mail exchangers.", "issues": [], "fixes": []},
        {"title": "MTA-STS", "status": "fail", "score": 0, "max_score": 6,
         "details": "No MTA-STS policy published — mail delivery encryption is opportunistic only.",
         "issues": ["Missing _mta-sts TXT record"],
         "fixes": ["v=STSv1; id=20261009;"]},
        {"title": "TLS-RPT", "status": "warn", "score": 1, "max_score": 3,
         "details": "No TLS-RPT record — delivery TLS failures go unreported.",
         "issues": ["Missing _smtp._tls TXT record"],
         "fixes": ["v=TLSRPTv1; rua=mailto:tls-reports@example.com"]},
        {"title": "BIMI", "status": "warn", "score": 1, "max_score": 3,
         "details": "BIMI record present but the logo URL could not be validated.",
         "issues": ["Logo URL did not serve a valid SVG"],
         "fixes": ["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem"]},
        {"title": "CAA", "status": "warn", "score": 2, "max_score": 4,
         "details": "No CAA records — any certificate authority may issue for this domain.",
         "issues": ["Missing CAA records"],
         "fixes": ["0 issue \"letsencrypt.org\""]},
        {"title": "Blacklists", "status": "pass", "score": 4, "max_score": 4,
         "details": "Mail servers not listed on major public blocklists.", "issues": [], "fixes": []},
        {"title": "DNSSEC", "status": "warn", "score": 0, "max_score": 4,
         "details": "Zone is not signed with DNSSEC.", "issues": ["No DS record at the parent"], "fixes": []},
        {"title": "TLS Certificate", "status": "pass", "score": 8, "max_score": 8,
         "details": "Valid certificate, 62 days to expiry, modern TLS only.", "issues": [], "fixes": []},
        {"title": "Web Security Headers", "status": "warn", "score": 3, "max_score": 8,
         "details": "Several protective headers are missing.",
         "issues": ["Missing Strict-Transport-Security", "Missing Content-Security-Policy"],
         "fixes": ["Strict-Transport-Security: max-age=31536000; includeSubDomains"]},
    ],
}
CANNED_JS = json.dumps(CANNED)


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chromium")
        ctx = await browser.new_context(
            viewport={"width": 1440, "height": 900},
            permissions=["clipboard-read", "clipboard-write"],
        )
        page = await ctx.new_page()
        page.on("console", lambda m: print("CONSOLE:", m.type, m.text[:160]) if m.type == "error" else None)
        page.on("pageerror", lambda e: print("PAGEERROR:", str(e)[:200]))

        # 1. landing
        await page.goto(BASE + "/")
        await page.wait_for_timeout(900)
        await page.screenshot(path=f"{OUT}/01-landing.png")

        # 2. report via the real render pipeline
        await page.evaluate(
            """(data) => {
                 document.getElementById('scan-result').innerHTML = renderReport({result: data}, true);
                 bindReportInteractions(document.getElementById('scan-result'));
                 document.getElementById('scan-result').scrollIntoView();
               }""", CANNED)
        await page.wait_for_timeout(2500)
        await page.screenshot(path=f"{OUT}/02-report.png", full_page=True)

        # 3. expand a failing finding + copy a fix (JS clicks: reliable for details/summary)
        await page.evaluate(
            """() => {
                 const s = document.querySelectorAll('details.check summary')[2];
                 if (s) s.click();
               }""")
        await page.wait_for_timeout(600)
        await page.evaluate(
            """() => {
                 const b = document.querySelector('details.check[open] .copy-btn');
                 if (b) b.click();
               }""")
        await page.wait_for_timeout(700)
        await page.screenshot(path=f"{OUT}/03-findings-copy.png")

        # 4. help page
        await page.goto(BASE + "/help")
        await page.wait_for_timeout(800)
        await page.screenshot(path=f"{OUT}/04-help.png", full_page=True)

        # 5. signup -> welcome modal
        await page.goto(BASE + "/signup")
        await page.fill("input[name=email]", EMAIL)
        await page.fill("input[name=company]", "Preview Co")
        await page.fill("input[name=password]", "PreviewTest123!")
        await page.click("#signup-form button[type=submit]")
        await page.wait_for_selector(".modal", timeout=15000)
        await page.wait_for_timeout(700)
        await page.screenshot(path=f"{OUT}/05-welcome-modal.png")

        # 6. guided tour, first step
        await page.click("#welcome-tour")
        await page.wait_for_selector(".tour-card", timeout=10000)
        await page.wait_for_timeout(1000)
        await page.screenshot(path=f"{OUT}/06-tour.png")
        await page.click(".tour-skip")
        await page.wait_for_timeout(500)

        # 7. dashboard with KPI tiles + checklist
        await page.wait_for_selector("#kpis .kpi", timeout=15000)
        await page.wait_for_timeout(2000)
        await page.screenshot(path=f"{OUT}/07-dashboard.png", full_page=True)

        # 8. dashboard guided scan render + celebration toast
        await page.evaluate(
            """(data) => {
                 const el = document.getElementById('dash-report');
                 el.innerHTML = renderReport({result: data}, false);
                 bindReportInteractions(el);
                 el.scrollIntoView({behavior: 'smooth'});
                 setTimeout(() => toast('🎉 First scan complete! Work the action plan above.'), 1800);
               }""", CANNED)
        await page.wait_for_timeout(3400)
        await page.screenshot(path=f"{OUT}/08-dashboard-scan.png", full_page=True)

        await browser.close()
        print("OK - screenshots saved to", OUT)


asyncio.run(main())
