"""Recover only incomplete analysis state when a single backend starts."""
from datetime import datetime
from app import models


def recover_interrupted_analyses(db):
    incidents = db.query(models.Incident).filter(models.Incident.status == "analyzing").all()
    for incident in incidents:
        incident.status = "interrupted"
        for run in incident.agent_runs:
            if run.status == "running":
                run.status = "failed"
                run.error_message = "服务已重启，原分析已中断。请重新开始分析。"
                run.finished_at = datetime.utcnow()
    db.commit()
    return len(incidents)
