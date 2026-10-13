"""告警 API 路由."""
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.cases.demo_cases import DEMO_CASES
from app.db.session import get_db
from app.agents.event_context import extract_event_context, serialize_windows_event
from app.services.analysis_view import assessment_for

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.post("", response_model=schemas.AlertOut)
def create_alert(payload: schemas.AlertCreate, db: Session = Depends(get_db)):
    values = payload.model_dump(exclude={"windows_context"})
    values["status"] = "pending"
    if not (payload.raw_content or "").strip():
        raise HTTPException(status_code=422, detail="请输入日志原文")
    if payload.windows_context is not None:
        source = extract_event_context(payload.raw_content)
        if source["platform"] in ("Linux", "macOS"):
            raise HTTPException(status_code=422, detail="检测到其他平台日志，请使用 Windows 事件日志；历史外部平台记录仍可查看。")
        metadata = payload.windows_context
        values["raw_content"] = serialize_windows_event({
            "OriginalLog": payload.raw_content,
            **({"EventID": metadata.event_id} if metadata.event_id is not None else {}),
            **({"Channel": metadata.channel} if metadata.channel else {}),
            **({"Computer": metadata.computer} if metadata.computer else {}),
        }, is_demo=source["is_demo"])
        values["source_type"] = "windows_manual"
    alert = models.Alert(**values)
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


@router.get("", response_model=List[schemas.AlertOut])
def list_alerts(queue: Optional[Literal["logs", "alerts"]] = None, db: Session = Depends(get_db)):
    records = db.query(models.Alert).order_by(models.Alert.created_at.desc()).all()
    if queue is None:
        return records  # Legacy storage API; queue is determined by server-side assessment.
    return [record for record in records if
            (assessment_for(max(record.incidents, key=lambda i: i.id))["queue"] if record.incidents else "logs") == queue]


@router.get("/cases")
def list_demo_cases():
    return [{**{key: case[key] for key in ("id", "title", "severity")},
             "record_count": len(case.get("records", [case["raw_content"]])),
             "hint": case.get("hint", "单条演示输入；分析结论以实际证据为准。")}
            for case in DEMO_CASES]


@router.get("/{alert_id}", response_model=schemas.AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="告警未找到")
    return alert


@router.delete("/{alert_id}")
def delete_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="告警未找到")
    db.delete(alert)
    db.commit()
    return {"ok": True}


@router.post("/from-case/{case_id}", response_model=schemas.AlertOut)
def create_from_case(case_id: str, db: Session = Depends(get_db)):
    for case in DEMO_CASES:
        if case["id"] == case_id:
            records = case.get("records", [case["raw_content"]])
            # One transaction imports the complete scenario. Return its last record
            # as the anchor; the existing incident-create API is idempotent.
            for index, raw in enumerate(records):
                alert = models.Alert(
                    title=case["title"] + (f" · 记录 {index + 1}/{len(records)}" if len(records) > 1 else ""),
                    raw_content=raw,
                    source_type="windows_demo",
                    severity=case["severity"],
                    status="pending",
                )
                db.add(alert)
                db.flush()
                db.add(models.Incident(alert_id=alert.id, status="pending"))
            db.commit()
            db.refresh(alert)
            return alert
    raise HTTPException(status_code=404, detail="演示案例未找到")
