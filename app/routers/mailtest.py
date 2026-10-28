""""Send a test email" analyzer: create a one-off address, mail it, and read
what the receiving server recorded (see app/mailtest.py)."""
import threading
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import mailtest, models
from ..database import get_db
from ..deps import get_current_user, rate_limit

router = APIRouter(prefix="/api/mailtest", tags=["mailtest"])
_fetching = threading.Lock()


def _require_configured() -> None:
    if not mailtest.is_configured():
        raise HTTPException(status_code=503, detail="Test emails aren't set up on this server "
                                                    "(MAILTEST_ADDRESS and a report mailbox are needed)")


def _get(db: Session, user: models.User, token: str) -> models.MailTest:
    test = (db.query(models.MailTest)
            .filter(models.MailTest.token == token.lower(), models.MailTest.tenant_id == user.tenant_id).first())
    if not test:
        raise HTTPException(status_code=404, detail="Test not found")
    return test


@router.get("/status")
def status(user: models.User = Depends(get_current_user)):
    return {"configured": mailtest.is_configured()}


@router.post("")
def create(request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    _require_configured()
    rate_limit(request, f"mailtest:{user.id}", 20)
    # Old tests are only an analysis; a week is plenty to read them.
    (db.query(models.MailTest)
     .filter(models.MailTest.tenant_id == user.tenant_id,
             models.MailTest.created_at < datetime.utcnow() - timedelta(days=7))
     .delete(synchronize_session=False))
    test = models.MailTest(tenant_id=user.tenant_id, user_id=user.id, token=mailtest.new_token())
    db.add(test)
    db.commit()
    return mailtest.as_dict(test)


@router.get("/{token}")
def read(token: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return mailtest.as_dict(_get(db, user, token))


@router.post("/{token}/check")
def check(token: str, request: Request, db: Session = Depends(get_db),
          user: models.User = Depends(get_current_user)):
    """Read the mailbox now instead of waiting for the next scheduled fetch."""
    test = _get(db, user, token)
    if test.received_at is None:
        _require_configured()
        rate_limit(request, f"mailtest-check:{user.tenant_id}", 60)
        if _fetching.acquire(blocking=False):  # one mailbox read at a time
            try:
                from scripts import fetch_dmarc_reports
                fetch_dmarc_reports.run()
            finally:
                _fetching.release()
        db.refresh(test)
    return mailtest.as_dict(test)
