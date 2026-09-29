"""WinSecAgent FastAPI 应用.

结合 SecAgentX 的多智能体流水线与 win10-security-agent 的
Windows 日志读取、RAG 知识库、真实系统操作、记忆、
调度器和多源数据采集功能。
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import APP_NAME, APP_VERSION, CORS_ORIGINS
from app.db.base import Base
from app.db.session import engine, SessionLocal
from app.services.recovery import recover_interrupted_analyses
from app.api import (
    alerts, incidents, agents, evidence, actions, reports,
    logs, knowledge, memory, scheduler, system_info, models,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        recover_interrupted_analyses(db)
    yield


app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SecAgentX original routers
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(agents.router)
app.include_router(evidence.router)
app.include_router(actions.router)
app.include_router(reports.router)

# WinSecAgent new routers
app.include_router(logs.router)
app.include_router(knowledge.router)
app.include_router(memory.router)
app.include_router(scheduler.router)
app.include_router(system_info.router)
app.include_router(models.router)


@app.get("/api/health")
def health():
    return {"ok": True, "app": APP_NAME, "version": APP_VERSION}
