"""安全知识库 API 路由."""
from typing import List

from fastapi import APIRouter

from app import schemas
from app.services.rag_knowledge import RAGKnowledgeBase

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])

_kb = RAGKnowledgeBase()


@router.post("/search", response_model=List[schemas.KnowledgeEntry])
def search_knowledge(payload: schemas.KnowledgeQuery):
    """Search the security knowledge base."""
    results = _kb.search(payload.query, top_k=payload.top_k)
    return results


@router.get("/entries", response_model=List[schemas.KnowledgeEntry])
def list_entries():
    """获取所有内置知识条目."""
    return _kb.get_all_entries()


@router.get("/context/{event_id}")
def get_context(event_id: int):
    """Get knowledge context for a specific Windows event ID."""
    context = _kb.get_context_for_event(event_id)
    return {"event_id": event_id, "context": context}
