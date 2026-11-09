"""Remediation workflow: assign findings to people, due dates, overdue view."""
from datetime import date, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, models, tasks
from ..database import get_db
from ..deps import get_current_user, normalize_domain, require_admin

router = APIRouter(prefix="/api/tasks", tags=["tasks"])


def _out(t: models.RemediationTask, clients: dict[str, str | None]) -> dict:
    return {"id": t.id, "domain": t.domain, "client": clients.get(t.domain), "check_key": t.check_key,
            "title": t.title, "note": t.note, "status": t.status,
            "assignee_id": t.assignee_id, "assignee": t.assignee.email if t.assignee else None,
            "due_date": t.due_date.isoformat() if t.due_date else None, "overdue": tasks.overdue(t),
            "created_by": t.created_by, "closed_by": t.closed_by,
            "closed_at": t.closed_at.isoformat() + "Z" if t.closed_at else None,
            "created_at": t.created_at.isoformat() + "Z"}


def _clients(db, tenant_id) -> dict[str, str | None]:
    return dict(db.query(models.Monitor.domain, models.Monitor.client)
                .filter(models.Monitor.tenant_id == tenant_id).all())


def _assignee(db, user, assignee_id):
    if not assignee_id:
        return None
    member = (db.query(models.User).filter(models.User.id == assignee_id, models.User.tenant_id == user.tenant_id,
                                           models.User.is_active.is_(True)).first())
    if not member:
        raise HTTPException(status_code=400, detail="That person is not in your company")
    return member.id


class TaskIn(BaseModel):
    domain: str = Field(max_length=253)
    check_key: str | None = Field(default=None, max_length=40)
    title: str | None = Field(default=None, max_length=300)
    note: str | None = Field(default=None, max_length=2000)
    assignee_id: str | None = Field(default=None, max_length=32)
    due_date: date | None = None


class TaskPatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    note: str | None = Field(default=None, max_length=2000)
    assignee_id: str | None = Field(default=None, max_length=32)
    due_date: date | None = None
    status: str | None = Field(default=None, pattern="^(open|done)$")


@router.get("")
def list_tasks(status: str = "open", mine: bool = False, db: Session = Depends(get_db),
               user: models.User = Depends(get_current_user)):
    q = db.query(models.RemediationTask).filter(models.RemediationTask.tenant_id == user.tenant_id)
    if status in ("open", "done"):
        q = q.filter(models.RemediationTask.status == status)
    if mine:
        q = q.filter(models.RemediationTask.assignee_id == user.id)
    rows = q.order_by(models.RemediationTask.created_at.desc()).limit(500).all()
    # Overdue first, then by due date (no date last).
    rows.sort(key=lambda t: (not tasks.overdue(t), t.due_date or date.max))
    clients = _clients(db, user.tenant_id)
    return [_out(t, clients) for t in rows]


@router.get("/summary")
def summary(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Open and overdue counts per client (MSPs) and per assignee."""
    rows = (db.query(models.RemediationTask)
            .filter(models.RemediationTask.tenant_id == user.tenant_id,
                    models.RemediationTask.status == "open").all())
    clients = _clients(db, user.tenant_id)
    by_client: dict[str, dict] = {}
    by_person: dict[str, dict] = {}
    for t in rows:
        for bucket, key in ((by_client, clients.get(t.domain) or ""), (by_person, t.assignee.email if t.assignee else "")):
            b = bucket.setdefault(key, {"open": 0, "overdue": 0})
            b["open"] += 1
            b["overdue"] += tasks.overdue(t)
    return {"open": len(rows), "overdue": sum(tasks.overdue(t) for t in rows),
            "mine": sum(1 for t in rows if t.assignee_id == user.id),
            "by_client": [{"client": k or None, **v} for k, v in sorted(by_client.items())],
            "by_assignee": [{"assignee": k or None, **v} for k, v in sorted(by_person.items())]}


@router.get("/findings")
def findings(domain: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Failing and warning checks in the latest scan of a domain, to assign."""
    domain = normalize_domain(domain)
    scan = (db.query(models.Scan).filter(models.Scan.tenant_id == user.tenant_id, models.Scan.domain == domain)
            .order_by(models.Scan.created_at.desc()).first())
    if not scan:
        return []
    taken = {k for (k,) in db.query(models.RemediationTask.check_key)
             .filter(models.RemediationTask.tenant_id == user.tenant_id, models.RemediationTask.domain == domain,
                     models.RemediationTask.status == "open")}
    return [{"key": c["key"], "title": c.get("title") or c["key"], "status": c.get("status"),
             "has_task": c["key"] in taken}
            for c in (scan.result or {}).get("checks", [])
            if c.get("key") and c.get("status") in ("fail", "warn")]


@router.post("", status_code=201)
def create(body: TaskIn, request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_admin)):
    domain = normalize_domain(body.domain)
    if not (db.query(models.Monitor).filter(models.Monitor.tenant_id == user.tenant_id,
                                            models.Monitor.domain == domain).first()):
        raise HTTPException(status_code=400, detail="Add the domain to your monitored domains first")
    title = (body.title or "").strip()
    if body.check_key:
        scan = (db.query(models.Scan).filter(models.Scan.tenant_id == user.tenant_id, models.Scan.domain == domain)
                .order_by(models.Scan.created_at.desc()).first())
        check = next((c for c in (scan.result or {}).get("checks", []) if c.get("key") == body.check_key), None) \
            if scan else None
        if not check:
            raise HTTPException(status_code=400, detail="That check is not in the latest scan of this domain")
        title = title or f"Fix {check.get('title') or body.check_key}"
        dup = (db.query(models.RemediationTask)
               .filter(models.RemediationTask.tenant_id == user.tenant_id, models.RemediationTask.domain == domain,
                       models.RemediationTask.check_key == body.check_key,
                       models.RemediationTask.status == "open").first())
        if dup:
            raise HTTPException(status_code=409, detail="There is already an open task for this finding")
    if not title:
        raise HTTPException(status_code=422, detail="Give the task a title")
    t = models.RemediationTask(tenant_id=user.tenant_id, domain=domain, check_key=body.check_key, title=title,
                               note=body.note, assignee_id=_assignee(db, user, body.assignee_id),
                               due_date=body.due_date, created_by=user.email)
    db.add(t)
    db.commit()
    audit.log_request(db, request, "task.create", user, {"task": t.id, "domain": domain, "check": body.check_key})
    return _out(t, _clients(db, user.tenant_id))


def _get(db, user, task_id) -> models.RemediationTask:
    t = (db.query(models.RemediationTask)
         .filter(models.RemediationTask.id == task_id, models.RemediationTask.tenant_id == user.tenant_id).first())
    if not t:
        raise HTTPException(status_code=404, detail="Task not found")
    return t


@router.patch("/{task_id}")
def update(task_id: str, body: TaskPatch, request: Request, db: Session = Depends(get_db),
           user: models.User = Depends(get_current_user)):
    """Admins change anything; the assignee can only mark their own task done or reopen it."""
    t = _get(db, user, task_id)
    admin = user.role in ("owner", "admin")
    fields = body.model_fields_set
    if not admin and (t.assignee_id != user.id or fields - {"status"}):
        raise HTTPException(status_code=403, detail="Only admins can change this task")
    if "title" in fields and body.title:
        t.title = body.title.strip()
    if "note" in fields:
        t.note = body.note
    if "assignee_id" in fields:
        t.assignee_id = _assignee(db, user, body.assignee_id)
        t.reminded_at = None
    if "due_date" in fields:
        t.due_date, t.reminded_at = body.due_date, None
    if body.status and body.status != t.status:
        t.status = body.status
        t.closed_by, t.closed_at = (user.email, datetime.utcnow()) if body.status == "done" else (None, None)
    db.commit()
    audit.log_request(db, request, "task.update", user, {"task": t.id, "fields": sorted(fields)})
    return _out(t, _clients(db, user.tenant_id))


@router.delete("/{task_id}", status_code=204)
def delete(task_id: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(require_admin)):
    t = _get(db, user, task_id)
    db.delete(t)
    db.commit()
    audit.log_request(db, request, "task.delete", user, {"task": task_id})
