"""System information API routes - multi-source data collection."""
from fastapi import APIRouter

from app.services.multi_source import (
    collect_all,
    collect_processes,
    collect_network_connections,
    collect_services,
    collect_scheduled_tasks,
    collect_registry_suspicious,
)

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/all")
def get_all_system_info():
    """从所有来源采集数据."""
    return collect_all()


@router.get("/processes")
def get_processes():
    return {"processes": collect_processes()}


@router.get("/network")
def get_network():
    return {"connections": collect_network_connections()}


@router.get("/services")
def get_services():
    return {"services": collect_services()}


@router.get("/tasks")
def get_tasks():
    return {"tasks": collect_scheduled_tasks()}


@router.get("/registry")
def get_registry():
    return {"registry": collect_registry_suspicious()}
