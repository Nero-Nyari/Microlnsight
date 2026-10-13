"""记忆库 API 路由."""
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app import models, schemas
from app.db.session import get_db
from app.services.memory import AgentMemory

router = APIRouter(prefix="/api/memory", tags=["memory"])

_memory = AgentMemory()


@router.post("/store")
def store_memory(payload: schemas.MemoryStoreRequest, db: Session = Depends(get_db)):
    """将事件和分析结果存入记忆库."""
    _memory.store_event(payload.event_data, payload.analysis_result)

    entry = models.MemoryEntry(
        event_data=payload.event_data,
        analysis_result=payload.analysis_result,
        keywords=_memory._extract_keywords(payload.event_data, payload.analysis_result),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    return {"ok": True, "id": entry.id}


@router.post("/search")
def search_memory(payload: schemas.MemorySearchRequest):
    """Search memory for similar events."""
    results = _memory.search_similar(payload.query, top_k=payload.top_k)
    return {"results": results, "count": len(results)}


@router.get("/stats")
def memory_stats():
    """Get memory statistics."""
    return _memory.get_stats()


@router.get("/recent")
def get_recent(count: int = 10):
    """获取最近的短期记忆条目."""
    return {"entries": _memory.get_recent(count)}


@router.delete("/short-term")
def clear_short_term():
    """清除短期记忆."""
    _memory.clear_short_term()
    return {"ok": True, "message": "短期记忆已清除"}


@router.delete("/long-term")
def clear_long_term(db: Session = Depends(get_db)):
    """清除长期记忆."""
    _memory.clear_long_term()
    db.query(models.MemoryEntry).delete()
    db.commit()
    return {"ok": True, "message": "长期记忆已清除"}
