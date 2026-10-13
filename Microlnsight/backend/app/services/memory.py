"""智能体记忆系统.

提供短期（内存中）和长期（JSON 文件）记忆，
支持历史事件的相似性搜索。
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class AgentMemory:
    """双层记忆: 短期（当前会话）+ 长期（持久化 JSON）."""

    def __init__(self, long_term_path: str = "./data/long_term_memory.json"):
        self._short_term: List[Dict[str, Any]] = []
        self._long_term_path = Path(long_term_path)
        self._long_term_path.parent.mkdir(parents=True, exist_ok=True)
        self._long_term: List[Dict[str, Any]] = self._load_long_term()

    def _load_long_term(self) -> List[Dict[str, Any]]:
        if self._long_term_path.exists():
            try:
                return json.loads(self._long_term_path.read_text(encoding="utf-8"))
            except Exception:
                return []
        return []

    def _save_long_term(self):
        self._long_term_path.write_text(
            json.dumps(self._long_term, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    # ---------- Store ----------

    def store_event(self, event_data: Dict[str, Any], analysis_result: Dict[str, Any]):
        """Store an event and its analysis result in both memory layers."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event_data": event_data,
            "analysis_result": analysis_result,
            "keywords": self._extract_keywords(event_data, analysis_result),
        }
        self._short_term.append(entry)
        self._long_term.append(entry)
        self._save_long_term()

    def store_step(self, step_data: Dict[str, Any]):
        """Store a single ReAct step in short-term memory."""
        step_data.setdefault("timestamp", datetime.now().isoformat())
        self._short_term.append(step_data)

    # ---------- Retrieve ----------

    def get_recent(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get most recent short-term entries."""
        return self._short_term[-count:]

    def get_all_long_term(self) -> List[Dict[str, Any]]:
        """获取所有长期记忆条目."""
        return self._long_term.copy()

    def search_similar(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Search long-term memory for similar events using keyword matching."""
        query_words = set(query.lower().split())
        scored = []
        for entry in self._long_term:
            entry_words = set(entry.get("keywords", []))
            overlap = len(query_words & entry_words)
            if overlap > 0:
                scored.append((overlap, entry))
        scored.sort(key=lambda x: x[0], reverse=True)
        results = []
        for score, entry in scored[:top_k]:
            results.append({**entry, "relevance_score": score / max(len(query_words), 1)})
        return results

    def search_by_event_id(self, event_id: int) -> List[Dict[str, Any]]:
        """搜索具有特定事件 ID 的记忆条目."""
        results = []
        for entry in self._long_term:
            ed = entry.get("event_data", {})
            if ed.get("EventID") == event_id:
                results.append(entry)
        return results

    def search_by_risk_level(self, risk_level: str) -> List[Dict[str, Any]]:
        """搜索具有特定风险等级的记忆条目."""
        results = []
        for entry in self._long_term:
            ar = entry.get("analysis_result", {})
            if ar.get("risk_level") == risk_level:
                results.append(entry)
        return results

    # ---------- Stats ----------

    def get_stats(self) -> Dict[str, Any]:
        """获取记忆统计信息."""
        risk_counts: Dict[str, int] = {}
        for entry in self._long_term:
            rl = entry.get("analysis_result", {}).get("risk_level", "unknown")
            risk_counts[rl] = risk_counts.get(rl, 0) + 1

        return {
            "short_term_count": len(self._short_term),
            "long_term_count": len(self._long_term),
            "risk_distribution": risk_counts,
            "oldest_entry": self._long_term[0]["timestamp"] if self._long_term else None,
            "newest_entry": self._long_term[-1]["timestamp"] if self._long_term else None,
        }

    # ---------- Clear ----------

    def clear_short_term(self):
        """清除短期记忆（新会话）."""
        self._short_term.clear()

    def clear_long_term(self):
        """Clear long-term memory."""
        self._long_term.clear()
        self._save_long_term()

    # ---------- Helpers ----------

    @staticmethod
    def _extract_keywords(event_data: Dict[str, Any], analysis_result: Dict[str, Any]) -> List[str]:
        """从事件和分析数据中提取可搜索的关键词."""
        keywords = []
        # From event data
        for key in ("EventID", "Channel", "ProviderName"):
            val = event_data.get(key)
            if val is not None:
                keywords.append(str(val).lower())
        msg = event_data.get("Message", "")
        for word in msg.split():
            if len(word) > 3:
                keywords.append(word.lower())

        # From analysis
        rl = analysis_result.get("risk_level", "")
        if rl:
            keywords.append(rl)
        et = analysis_result.get("event_type", "")
        if et:
            keywords.append(et.lower())

        return list(set(keywords))
