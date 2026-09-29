"""Report API routes."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app import models, schemas
from app.db.session import get_db
from app.services.analysis_view import report_view

router = APIRouter(tags=["reports"])


@router.post("/api/incidents/{incident_id}/report", response_model=schemas.ReportOut)
def generate_report_endpoint(incident_id: int, db: Session = Depends(get_db)):
    from app.agents.report_agent import generate_report
    from app.services.analysis_view import report_inputs
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident or not incident.alert:
        raise HTTPException(status_code=404, detail="事件未找到")
    if incident.status == "analyzing":
        raise HTTPException(status_code=409, detail="分析进行中，请等待本轮结论后生成报告。")
    content = generate_report(**report_inputs(incident))
    report = models.Report(incident_id=incident_id, content=content, format="markdown")
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("/api/incidents/{incident_id}/report", response_model=schemas.ReportOut)
def get_report(incident_id: int, db: Session = Depends(get_db)):
    report = db.query(models.Report).filter(models.Report.incident_id == incident_id).order_by(models.Report.id.desc()).first()
    if not report:
        raise HTTPException(status_code=404, detail="报告未找到")
    return report_view(report)


@router.get("/api/reports/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return PlainTextResponse(content=report_view(report)["content"], media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": f"attachment; filename=report-{report_id}.md"})
