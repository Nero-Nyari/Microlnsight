"""数据库模型 - 从 SecAgentX 扩展，增加 win10-security-agent 功能."""
from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional

from sqlalchemy import String, Text, DateTime, ForeignKey, JSON, Integer, Float, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Severity(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, PyEnum):
    PENDING = "pending"
    ANALYZING = "analyzing"
    REVIEW = "review"
    APPROVED = "approved"
    REJECTED = "rejected"
    CLOSED = "closed"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    raw_content: Mapped[Optional[str]] = mapped_column(Text)
    source_type: Mapped[Optional[str]] = mapped_column(String(50), default="manual")
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    incidents: Mapped[list["Incident"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"))
    event_type: Mapped[Optional[str]] = mapped_column(String(100))
    risk_level: Mapped[Optional[str]] = mapped_column(String(20))
    confidence: Mapped[Optional[float]] = mapped_column(default=0.0)
    summary: Mapped[Optional[str]] = mapped_column(Text)
    attack_stage: Mapped[Optional[str]] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    alert: Mapped["Alert"] = relationship(back_populates="incidents")
    agent_runs: Mapped[list["AgentRun"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="AgentRun.started_at"
    )
    evidence_items: Mapped[list["EvidenceItem"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    response_actions: Mapped[list["ResponseAction"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )


class AgentRun(Base):
    __tablename__ = "agent_runs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    agent_name: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20), default="running")
    input_data: Mapped[Optional[dict]] = mapped_column(JSON)
    output_data: Mapped[Optional[dict]] = mapped_column(JSON)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    incident: Mapped["Incident"] = relationship(back_populates="agent_runs")


class EvidenceItem(Base):
    __tablename__ = "evidence_items"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    type: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(255))
    content: Mapped[Optional[str]] = mapped_column(Text)
    source: Mapped[Optional[str]] = mapped_column(String(100))
    confidence: Mapped[Optional[float]] = mapped_column(default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped["Incident"] = relationship(back_populates="evidence_items")


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    action_type: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text)
    risk: Mapped[str] = mapped_column(String(20), default="medium")
    approval_required: Mapped[bool] = mapped_column(default=False)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    approved_by: Mapped[Optional[str]] = mapped_column(String(100))
    result: Mapped[Optional[dict]] = mapped_column(JSON)  # execution result from ActionExecutor
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    incident: Mapped["Incident"] = relationship(back_populates="response_actions")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    content: Mapped[str] = mapped_column(Text)
    format: Mapped[str] = mapped_column(String(20), default="markdown")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped["Incident"] = relationship(back_populates="reports")


# ---------- New models for Microlnsight features ----------

class ScanResult(Base):
    """Stores results from scheduled log scans."""
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_type: Mapped[str] = mapped_column(String(50))  # "log_scan", "full_scan"
    events_found: Mapped[int] = mapped_column(default=0)
    suspicious_count: Mapped[int] = mapped_column(default=0)
    incidents_created: Mapped[int] = mapped_column(default=0)
    details: Mapped[Optional[dict]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="success")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class MemoryEntry(Base):
    """持久化记忆条目（数据库中的长期记忆）."""
    __tablename__ = "memory_entries"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    event_data: Mapped[dict] = mapped_column(JSON)
    analysis_result: Mapped[dict] = mapped_column(JSON)
    keywords: Mapped[Optional[list]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
