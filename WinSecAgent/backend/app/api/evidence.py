"""Evidence API routes."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.db.session import get_db

router = APIRouter(prefix="/api/incidents", tags=["evidence"])


@router.get("/{incident_id}/evidence", response_model=List[schemas.EvidenceItemOut])
def list_evidence(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="事件未找到")
    from app.services.analysis_view import incident_detail
    return incident_detail(incident)['evidence_items']
