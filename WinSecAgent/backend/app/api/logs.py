"""Windows 日志读取 API 路由."""
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app import models, schemas
from app.db.session import get_db
from app.services.log_reader import read_windows_logs
from app.agents.pipeline import analyze_incident
from app.agents.event_context import serialize_windows_event
from app.services.analysis_view import assessment_for

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.post("/read", response_model=schemas.LogReadResponse)
def read_logs(payload: schemas.LogReadRequest):
    """读取 Windows 事件日志（真实数据或模拟数据）."""
    result = read_windows_logs(
        channels=payload.channels,
        suspicious_only=payload.suspicious_only,
        max_events=payload.max_events,
    )
    return result


@router.post("/import")
def import_to_alerts(
    payload: schemas.LogReadRequest,
    db: Session = Depends(get_db),
):
    """读取并保存待分析日志；事件 ID 和原始等级不直接形成告警。"""
    result = read_windows_logs(
        channels=payload.channels,
        suspicious_only=payload.suspicious_only,
        max_events=payload.max_events,
    )
    created = 0
    for evt in result["events"]:
        alert = models.Alert(
            title=f"EventID {evt.get('EventID')} - {evt.get('Channel', 'Unknown')}",
            raw_content=serialize_windows_event(evt, result["is_mock"]),
            source_type="windows_log",
            severity=_event_to_severity(evt.get("EventID", 0)),
            status="pending",
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        incident = models.Incident(alert_id=alert.id, status="pending")
        db.add(incident)
        db.commit()
        created += 1

    return {
        "ok": True,
        "logs_imported": created,
        "alerts_created": 0,
        "total_events": result["total_filtered"],
        "is_mock": result["is_mock"],
        "read_status": result.get("read_status", "success"),
        "warnings": result.get("warnings", []),
        "channel_results": result.get("channel_results", []),
    }


@router.post("/import-and-analyze")
def import_and_analyze(
    payload: schemas.LogReadRequest,
    db: Session = Depends(get_db),
):
    """导入日志并分析；仅有异常原文证据的结果形成告警。"""
    result = read_windows_logs(
        channels=payload.channels,
        suspicious_only=payload.suspicious_only,
        max_events=payload.max_events,
    )
    created = 0
    analyzed = 0
    alerts_created = 0
    for evt in result["events"]:
        alert = models.Alert(
            title=f"EventID {evt.get('EventID')} - {evt.get('Channel', 'Unknown')}",
            raw_content=serialize_windows_event(evt, result["is_mock"]),
            source_type="windows_log",
            severity=_event_to_severity(evt.get("EventID", 0)),
            status="pending",
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        incident = models.Incident(alert_id=alert.id, status="pending")
        db.add(incident)
        db.commit()
        db.refresh(incident)
        created += 1

        try:
            analyze_incident(db, incident.id)
            analyzed += 1
            alerts_created += int(assessment_for(incident)["queue"] == "alerts")
        except Exception:
            pass

    return {
        "ok": True,
        "logs_imported": created,
        "alerts_created": alerts_created,
        "incidents_analyzed": analyzed,
        "is_mock": result["is_mock"],
        "read_status": result.get("read_status", "success"),
        "warnings": result.get("warnings", []),
        "channel_results": result.get("channel_results", []),
    }


def _event_to_severity(event_id: int) -> str:
    """将 Windows 事件ID映射到风险等级."""
    critical_ids = {1116, 1117, 4697}
    high_ids = {4625, 4740, 7045}
    medium_ids = {4648, 4720, 4722, 4726, 4732}

    if event_id in critical_ids:
        return "critical"
    elif event_id in high_ids:
        return "high"
    elif event_id in medium_ids:
        return "medium"
    return "low"
