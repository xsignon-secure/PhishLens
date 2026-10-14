"""Local preview QA: capture screenshots of the redesigned PhishLens UI."""
import asyncio
import time
from playwright.async_api import async_playwright

BASE = "http://localhost:8000"
OUT = "/home/hatch/workspace/phishlens/preview"
EMAIL = f"preview-qa-{int(time.time())}@example.com"


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chromium")
        ctx = await browser.new_context(
            viewport={"width": 1440, "height": 900},
            permissions=["clipboard-read", "clipboard-write"],
        )
        page = await ctx.new_page()

        # 1. landing
        await page.goto(BASE + "/")
        await page.wait_for_timeout(900)
        await page.screenshot(path=f"{OUT}/01-landing.png")

        # 2. public scan
        await page.fill("#scan-domain", "example.com")
        await page.click("#scan-form button[type=submit]")
        await page.wait_for_selector(".report .ring-num", timeout=120000)
        await page.wait_for_timeout(2400)  # ring count-up finishes
        await page.screenshot(path=f"{OUT}/02-report.png", full_page=True)

        # 3. expand first finding + copy a fix
        summaries = await page.query_selector_all("details.check summary")
        if summaries:
            await summaries[0].click()
            await page.wait_for_timeout(500)
        copy_btn = await page.query_selector("details.check .copy-btn")
        if copy_btn:
            await copy_btn.click()
            await page.wait_for_timeout(600)
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
        await page.wait_for_timeout(600)
        await page.screenshot(path=f"{OUT}/05-welcome-modal.png")

        # 6. guided tour, first step
        await page.click("#welcome-tour")
        await page.wait_for_selector(".tour-card", timeout=10000)
        await page.wait_for_timeout(900)
        await page.screenshot(path=f"{OUT}/06-tour.png")
        await page.click(".tour-skip")
        await page.wait_for_timeout(500)

        # 7. dashboard with KPI tiles + checklist
        await page.wait_for_selector("#kpis .kpi", timeout=15000)
        await page.wait_for_timeout(1800)  # count-up + shimmer
        await page.screenshot(path=f"{OUT}/07-dashboard.png", full_page=True)

        # 8. run a dashboard scan for the guided flow
        await page.fill("#adhoc-domain", "example.com")
        await page.click("#adhoc-form button[type=submit]")
        await page.wait_for_selector("#dash-report .report .ring-num", timeout=120000)
        await page.wait_for_timeout(2400)
        await page.screenshot(path=f"{OUT}/08-dashboard-scan.png", full_page=True)

        await browser.close()
        print("OK - screenshots saved to", OUT)


asyncio.run(main())
