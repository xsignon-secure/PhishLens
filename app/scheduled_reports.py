"""Scheduled PDF reports: a weekly or monthly email to a team's owners (and
extra alert recipients) with the latest report for each monitored domain.
Sent by the rescan job, so it needs RESCAN_INTERVAL_HOURS or a cron'd
scripts/rescan.py, plus SMTP."""
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from . import mailer, models
from .config import settings

PERIODS = {"weekly": 7, "monthly": 30}
MAX_DOMAINS = 10


def is_due(tenant: models.Tenant, now: datetime) -> bool:
    days = PERIODS.get(tenant.report_schedule or "off")
    if not days:
        return False
    # A little slack so a job that runs at a slightly different hour each
    # time doesn't slip a whole period.
    return tenant.report_sent_at is None or now - tenant.report_sent_at >= timedelta(days=days, hours=-6)


def recipients(db: Session, tenant: models.Tenant) -> list[str]:
    from .workspace import real_email
    owners = [e for (e,) in db.query(models.User.email).filter(
        models.User.tenant_id == tenant.id, models.User.role == "owner", models.User.is_active.is_(True))
        if real_email(e)]
    return owners + [e for e in (tenant.alert_emails or []) if e not in owners]


def build(db: Session, tenant: models.Tenant) -> tuple[str, str, list] | None:
    """(subject, body, attachments) for the tenant, or None with nothing to report."""
    from .branding import for_tenant
    from .routers.scans import _pdf_bytes

    monitors = (db.query(models.Monitor)
                .filter(models.Monitor.tenant_id == tenant.id, models.Monitor.is_active.is_(True))
                .order_by(models.Monitor.client, models.Monitor.domain).all())
    lines, attachments = [], []
    for m in monitors[:MAX_DOMAINS]:
        scan = (db.query(models.Scan)
                .filter(models.Scan.tenant_id == tenant.id, models.Scan.domain == m.domain)
                .order_by(models.Scan.created_at.desc()).first())
        if not scan:
            continue
        pdf, filename = _pdf_bytes(scan, db, with_history=True)
        attachments.append((filename, pdf, "application/pdf"))
        client = f" [{m.client}]" if m.client else ""
        lines.append(f"- {m.domain}{client}: {scan.score}/100 (grade {scan.grade}), checked {scan.created_at:%Y-%m-%d}")
    if not attachments:
        return None
    name = (for_tenant(tenant) or {}).get("name") or settings.APP_NAME
    period = "Weekly" if tenant.report_schedule == "weekly" else "Monthly"
    more = (f"\n{len(monitors) - MAX_DOMAINS} more domains are on the dashboard." if len(monitors) > MAX_DOMAINS else "")
    body = (f"{period} email security report from {name}.\n\n" + "\n".join(lines) + more +
            f"\n\nThe PDF reports are attached. Dashboard: {settings.APP_URL}/dashboard\n"
            f"Change or stop these emails on the dashboard (Scheduled reports).\n")
    return f"{period} email security report: {len(attachments)} domain(s)", body, attachments


def send(db: Session, tenant: models.Tenant, now: datetime | None = None) -> bool:
    to = recipients(db, tenant)
    built = build(db, tenant)
    if not to or not built:
        return False
    subject, body, attachments = built
    if not mailer.send_email(to, subject, body, attachments=attachments):
        return False
    tenant.report_sent_at = now or datetime.utcnow()
    db.commit()
    return True


def send_due(db: Session, now: datetime | None = None) -> int:
    """Send every report that is due. Returns how many were sent."""
    if not mailer.is_configured():
        return 0
    now = now or datetime.utcnow()
    sent = 0
    for tenant in db.query(models.Tenant).filter(models.Tenant.report_schedule.in_(list(PERIODS))).all():
        if not is_due(tenant, now):
            continue
        try:
            sent += send(db, tenant, now)
        except Exception:
            db.rollback()  # one team's failure must not stop the others
    return sent
