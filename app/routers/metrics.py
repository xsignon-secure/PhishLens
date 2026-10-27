"""Prometheus / OpenMetrics export of a team's posture, for Grafana and SIEM
dashboards. Authenticate with an API key (X-API-Key) like the rest of the API:

    scrape_configs:
      - job_name: phishlens
        metrics_path: /api/metrics
        scheme: https
        static_configs: [{targets: ["phishlens.example.com"]}]
        authorization: {type: ApiKey}   # or: http_headers: {X-API-Key: {values: ["plk_..."]}}
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from ..deps import get_current_user

router = APIRouter(tags=["metrics"])


def _esc(v) -> str:
    return str(v or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _line(name: str, labels: dict, value) -> str:
    lab = ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items())
    return f"{name}{{{lab}}} {value}"


@router.get("/api/metrics", response_class=PlainTextResponse)
def metrics(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    tid = user.tenant_id
    out = [
        "# HELP phishlens_monitor_score Latest 0-100 email security score of a monitored domain.",
        "# TYPE phishlens_monitor_score gauge",
    ]
    monitors = db.query(models.Monitor).filter(models.Monitor.tenant_id == tid, models.Monitor.is_active.is_(True)).all()
    for m in monitors:
        if m.last_score is not None:
            out.append(_line("phishlens_monitor_score", {"domain": m.domain, "client": m.client or ""}, m.last_score))
    out += ["# HELP phishlens_monitor_last_checked_seconds Unix time of the last scan of a monitored domain.",
            "# TYPE phishlens_monitor_last_checked_seconds gauge"]
    for m in monitors:
        if m.last_checked_at:
            out.append(_line("phishlens_monitor_last_checked_seconds", {"domain": m.domain},
                             int((m.last_checked_at - datetime(1970, 1, 1)).total_seconds())))
    out += ["# HELP phishlens_lookalike_domains Registered lookalike domains found for a monitored domain.",
            "# TYPE phishlens_lookalike_domains gauge"]
    for m in monitors:
        out.append(_line("phishlens_lookalike_domains", {"domain": m.domain}, len(m.lookalikes or [])))

    since = datetime.utcnow() - timedelta(days=30)
    dmarc = (db.query(models.DmarcReport.domain, func.sum(models.DmarcReport.message_count),
                      func.sum(models.DmarcReport.pass_count))
             .filter(models.DmarcReport.tenant_id == tid, models.DmarcReport.date_begin >= since)
             .group_by(models.DmarcReport.domain).all())
    out += ["# HELP phishlens_dmarc_messages_30d Messages in DMARC aggregate reports, last 30 days.",
            "# TYPE phishlens_dmarc_messages_30d gauge"]
    out += [_line("phishlens_dmarc_messages_30d", {"domain": d}, int(total or 0)) for d, total, _ in dmarc]
    out += ["# HELP phishlens_dmarc_pass_ratio_30d Share of reported messages passing DMARC, last 30 days.",
            "# TYPE phishlens_dmarc_pass_ratio_30d gauge"]
    out += [_line("phishlens_dmarc_pass_ratio_30d", {"domain": d}, round((ok or 0) / total, 4))
            for d, total, ok in dmarc if total]

    tls = (db.query(models.TlsReport.domain, func.sum(models.TlsReport.success_count),
                    func.sum(models.TlsReport.failure_count))
           .filter(models.TlsReport.tenant_id == tid, models.TlsReport.date_begin >= since)
           .group_by(models.TlsReport.domain).all())
    out += ["# HELP phishlens_tls_failed_sessions_30d Failed inbound TLS sessions in TLS-RPT reports, last 30 days.",
            "# TYPE phishlens_tls_failed_sessions_30d gauge"]
    out += [_line("phishlens_tls_failed_sessions_30d", {"domain": d}, int(bad or 0)) for d, _, bad in tls]
    out += ["# HELP phishlens_tls_success_ratio_30d Share of inbound TLS sessions that succeeded, last 30 days.",
            "# TYPE phishlens_tls_success_ratio_30d gauge"]
    out += [_line("phishlens_tls_success_ratio_30d", {"domain": d}, round((ok or 0) / ((ok or 0) + (bad or 0)), 4))
            for d, ok, bad in tls if (ok or 0) + (bad or 0)]

    alerts = (db.query(func.count(models.Alert.id)).filter(
        models.Alert.tenant_id == tid, models.Alert.created_at >= datetime.utcnow() - timedelta(days=7)).scalar())
    out += ["# HELP phishlens_alerts_7d Drift and lookalike alerts raised in the last 7 days.",
            "# TYPE phishlens_alerts_7d gauge", f"phishlens_alerts_7d {int(alerts or 0)}"]
    return PlainTextResponse("\n".join(out) + "\n", media_type="text/plain; version=0.0.4")
