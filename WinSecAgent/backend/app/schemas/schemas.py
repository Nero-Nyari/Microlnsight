"""Pydantic 模式 - 为 WinSecAgent 扩展."""
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


# ---------- Alert schemas ----------
class AlertBase(BaseModel):
    title: str
    raw_content: Optional[str] = None
    source_type: str = "manual"
    severity: str = "medium"
    status: str = "pending"


class WindowsLogContext(BaseModel):
    event_id: Optional[int] = Field(default=None, ge=1, le=65535)
    channel: Optional[str] = Field(default=None, max_length=200)
    computer: Optional[str] = Field(default=None, max_length=255)


class AlertCreate(AlertBase):
    windows_context: Optional[WindowsLogContext] = None


class AlertUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    raw_content: Optional[str] = None


class AlertOut(AlertBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime
    updated_at: datetime


# ---------- Incident schemas ----------
class IncidentBase(BaseModel):
    event_type: Optional[str] = None
    risk_level: Optional[str] = None
    confidence: Optional[float] = 0.0
    summary: Optional[str] = None
    attack_stage: Optional[str] = None
    status: str = "pending"


class IncidentCreate(IncidentBase):
    alert_id: int


class IncidentOut(IncidentBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    alert_id: int
    created_at: datetime
    updated_at: datetime
    queue: str = "logs"
    assessment: Optional[Dict[str, Any]] = None


class IncidentDetail(IncidentOut):
    source_record: Optional[Dict[str, Any]] = None
    correlation: Optional[Dict[str, Any]] = None
    alert: Optional[AlertOut] = None
    agent_runs: List["AgentRunOut"] = []
    evidence_items: List["EvidenceItemOut"] = []
    response_actions: List["ResponseActionOut"] = []
    reports: List["ReportOut"] = []


# ---------- AgentRun schemas ----------
class AgentRunBase(BaseModel):
    agent_name: str
    status: str = "running"
    input_data: Optional[Dict[str, Any]] = None
    output_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class AgentRunOut(AgentRunBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    incident_id: int
    started_at: datetime
    finished_at: Optional[datetime] = None


# ---------- EvidenceItem schemas ----------
class EvidenceItemBase(BaseModel):
    type: str
    title: str
    content: Optional[str] = None
    source: Optional[str] = None
    confidence: Optional[float] = 0.0


class EvidenceItemOut(EvidenceItemBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    incident_id: int
    created_at: datetime


# ---------- ResponseAction schemas ----------
class ResponseActionBase(BaseModel):
    action_type: str
    description: str
    risk: str = "medium"
    approval_required: bool = False
    status: str = "pending"


class ResponseActionOut(ResponseActionBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    incident_id: int
    approved_by: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime


class ActionApproval(BaseModel):
    approved_by: str


# ---------- Report schemas ----------
class ReportBase(BaseModel):
    content: str
    format: str = "markdown"


class ReportOut(ReportBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    incident_id: int
    created_at: datetime


# ---------- Pipeline schemas ----------
class AnalyzeRequest(BaseModel):
    use_demo_case: Optional[str] = None


class CorrelationRequest(BaseModel):
    window_minutes: int = Field(default=15, ge=1, le=60)


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]


# ---------- Log Reader schemas ----------
class LogReadRequest(BaseModel):
    channels: Optional[List[str]] = None
    suspicious_only: bool = True
    max_events: int = Field(default=200, ge=1, le=1000)


class LogChannelResult(BaseModel):
    channel: str
    status: Literal["success", "partial", "failed"]
    events_read: int
    error_kind: Optional[str] = None
    error_code: Optional[int] = None
    message: Optional[str] = None
    detail: Optional[str] = None


class LogReaderContext(BaseModel):
    account: Optional[str] = None
    elevated: Optional[bool] = None


class LogReadResponse(BaseModel):
    warnings: List[str] = Field(default_factory=list)
    read_status: Literal["success", "partial", "failed", "demo"] = "success"
    channel_results: List[LogChannelResult] = Field(default_factory=list)
    reader_context: Optional[LogReaderContext] = None
    events: List[Dict[str, Any]]
    total_raw: int
    total_filtered: int
    event_id_stats: Dict[int, int]
    channel_stats: Dict[str, int]
    timestamp: str
    is_mock: bool
    platform: str


# ---------- Knowledge schemas ----------
class KnowledgeQuery(BaseModel):
    query: str
    top_k: int = 5


class KnowledgeEntry(BaseModel):
    id: str
    title: str
    content: str
    category: str
    score: Optional[float] = None


# ---------- Memory schemas ----------
class MemoryStoreRequest(BaseModel):
    event_data: Dict[str, Any]
    analysis_result: Dict[str, Any]


class MemorySearchRequest(BaseModel):
    query: str
    top_k: int = 5


class MemoryEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    event_data: Dict[str, Any]
    analysis_result: Dict[str, Any]
    keywords: Optional[list] = None
    created_at: datetime


# ---------- Scheduler schemas ----------
class SchedulerConfig(BaseModel):
    scan_interval: Optional[int] = None
    auto_threshold: Optional[float] = None


# ---------- ScanResult schemas ----------
class ScanResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_type: str
    events_found: int
    suspicious_count: int
    incidents_created: int
    details: Optional[Dict[str, Any]] = None
    status: str
    created_at: datetime


# ---------- Action Execute schemas ----------
class ActionExecuteRequest(BaseModel):
    action_type: str
    description: str = ""
    params: Optional[Dict[str, Any]] = None


class ActionExecuteResponse(BaseModel):
    success: bool
    action_type: str
    message: str
    dry_run: bool
    command: Optional[str] = None
    timestamp: Optional[str] = None


# Rebuild forward refs
IncidentDetail.model_rebuild()
