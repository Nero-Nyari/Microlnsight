"""事件 API 路由."""
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.agents.pipeline import analyze_incident
from app.db.session import get_db
from app.services.analysis_view import incident_summary, incident_detail

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.post('/{incident_id}/correlate')
def correlate_incident(incident_id: int, payload: schemas.CorrelationRequest, db: Session = Depends(get_db)):
    from app.services.correlation import save_analysis
    incident = db.get(models.Incident, incident_id)
    if not incident or not incident.alert:
        raise HTTPException(status_code=404, detail='事件未找到')
    if incident.status == 'analyzing':
        raise HTTPException(status_code=409, detail='分析进行中，请等待完成后再运行联合分析。')
    save_analysis(db, incident, payload.window_minutes)
    return {'ok': True, 'status': incident.status}


@router.post("", response_model=schemas.IncidentOut)
def create_incident(payload: schemas.IncidentCreate, db: Session = Depends(get_db)):
    if not db.get(models.Alert, payload.alert_id):
        raise HTTPException(status_code=404, detail="告警未找到")
    existing = db.query(models.Incident).filter(models.Incident.alert_id == payload.alert_id).first()
    if existing:
        return existing
    # Importing a record never establishes a security verdict.
    incident = models.Incident(alert_id=payload.alert_id, status="pending")
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


@router.get("", response_model=List[schemas.IncidentOut])
def list_incidents(queue: Optional[Literal["logs", "alerts"]] = None, db: Session = Depends(get_db)):
    items = [incident_summary(i) for i in db.query(models.Incident).order_by(models.Incident.created_at.desc()).all()]
    return [i for i in items if queue is None or i["queue"] == queue]


@router.get("/{incident_id}", response_model=schemas.IncidentDetail)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="事件未找到")
    return incident_detail(incident)


@router.post("/{incident_id}/analyze")
def start_analysis(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="事件未找到")
    if incident.status == "analyzing":
        raise HTTPException(status_code=400, detail="分析正在进行中")
    try:
        analyze_incident(db, incident_id)
    except Exception:
        db.rollback()
        incident.status = "failed"
        db.commit()
        raise HTTPException(status_code=500, detail="分析失败，已有日志与结果已保留，请重试。")
    return {"ok": True, "status": incident.status}
