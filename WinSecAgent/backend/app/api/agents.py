"""智能体执行记录 API 路由."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.db.session import get_db
from app.services.analysis_view import incident_detail

router = APIRouter(prefix="/api/incidents", tags=["agents"])


@router.get("/{incident_id}/agents", response_model=List[schemas.AgentRunOut])
def list_agent_runs(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="事件未找到")
    return incident_detail(incident)["agent_runs"]
