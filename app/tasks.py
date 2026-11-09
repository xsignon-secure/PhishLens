"""Remediation tasks: assign a finding to a person with a due date.

A task tied to a scan check closes itself when a later scan of that domain
shows the check passing, so "done" means fixed, not just ticked."""
from datetime import date, datetime

from sqlalchemy.orm import Session

from . import mailer, models
from .config import settings


def overdue(task: models.RemediationTask, today: date | None = None) -> bool:
    return task.status == "open" and task.due_date is not None and task.due_date < (today or date.today())


def verify(db: Session, scan: models.Scan) -> list[models.RemediationTask]:
    """Close open tasks for this domain whose check now passes."""
    if not scan.tenant_id:
        return []
    passing = {c.get("key") for c in (scan.result or {}).get("checks", [])
               if c.get("key") and c.get("status") == "pass" and not c.get("errored")}
    if not passing:
        return []
    rows = (db.query(models.RemediationTask)
            .filter(models.RemediationTask.tenant_id == scan.tenant_id,
                    models.RemediationTask.domain == scan.domain,
                    models.RemediationTask.status == "open",
                    models.RemediationTask.check_key.in_(passing)).all())
    for t in rows:
        t.status, t.closed_by, t.closed_at = "done", "scan", datetime.utcnow()
    if rows:
        db.commit()
    return rows


def remind_overdue(db: Session, today: date | None = None) -> int:
    """Email each assignee once about tasks that passed their due date."""
    today = today or date.today()
    rows = (db.query(models.RemediationTask)
            .filter(models.RemediationTask.status == "open",
                    models.RemediationTask.due_date < today,
                    models.RemediationTask.reminded_at.is_(None),
                    models.RemediationTask.assignee_id.isnot(None)).all())
    by_user: dict[str, list[models.RemediationTask]] = {}
    for t in rows:
        by_user.setdefault(t.assignee_id, []).append(t)
    sent = 0
    for tasks in by_user.values():
        user = tasks[0].assignee
        if not user or not user.is_active or not mailer.real_email(user.email):
            continue
        lines = [f"- {t.domain}: {t.title} (due {t.due_date.isoformat()})" for t in tasks]
        body = ("These email security fixes assigned to you are past their due date:\n\n"
                + "\n".join(lines)
                + f"\n\nOpen your task list: {settings.APP_URL.rstrip('/')}/dashboard#tasks\n"
                "A task closes by itself once a scan shows the check passing.\n")
        if mailer.send_email([user.email], f"{len(tasks)} overdue email security task(s)", body,
                             tenant=user.tenant):
            sent += 1
        for t in tasks:  # mark even when mail is not set up, so we don't retry daily forever
            t.reminded_at = datetime.utcnow()
    db.commit()
    return sent
