"""定时调度 API 路由."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app import schemas
from app.db.session import get_db
from app.services.scheduler import scheduler

router = APIRouter(prefix="/api/scheduler", tags=["scheduler"])


@router.get("/status")
def get_status():
    """获取调度器状态."""
    return scheduler.get_status()


@router.post("/start")
def start_scheduler():
    """启动自动扫描调度器."""
    scheduler.start()
    return {"ok": True, "status": scheduler.get_status()}


@router.post("/stop")
def stop_scheduler():
    """停止自动扫描调度器."""
    scheduler.stop()
    return {"ok": True, "status": scheduler.get_status()}


@router.post("/pause")
def pause_scheduler():
    """暂停调度器."""
    scheduler.pause()
    return {"ok": True, "status": scheduler.get_status()}


@router.post("/resume")
def resume_scheduler():
    """恢复调度器."""
    scheduler.resume()
    return {"ok": True, "status": scheduler.get_status()}


@router.post("/config")
def update_config(payload: schemas.SchedulerConfig):
    """更新调度器配置."""
    if payload.scan_interval is not None:
        scheduler.set_interval(payload.scan_interval)
    if payload.auto_threshold is not None:
        scheduler.set_auto_threshold(payload.auto_threshold)
    return {"ok": True, "status": scheduler.get_status()}
