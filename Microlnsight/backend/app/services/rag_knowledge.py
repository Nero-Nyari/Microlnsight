"""Windows 安全事件 RAG 知识库.

使用 ChromaDB + sentence-transformers 进行向量搜索，内置
Windows 事件知识库。当向量库不可用时，回退到关键词匹配。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.storage_migration import COLLECTION_NAME, LEGACY_COLLECTION_NAME, MigrationRequired

# ---------- Built-in knowledge entries ----------
KNOWLEDGE_ENTRIES: List[Dict[str, str]] = [
    {
        "id": "evt_4625",
        "title": "事件 ID 4625 - 登录失败",
        "content": (
            "事件 ID 4625 表示登录尝试失败。常见原因: "
            "密码错误、账户锁定、账户已禁用或暴力破解攻击。"
            "ATT&CK: T1110 (暴力破解)。"
            "排查建议: 检查来源 IP、频率、目标账户。"
        ),
        "category": "login",
    },
    {
        "id": "evt_4648",
        "title": "事件 ID 4648 - 使用显式凭据登录",
        "content": (
            "事件 ID 4648 表示使用显式凭据尝试登录"
            "(例如 runas、PsExec)。常见于横向移动。"
            "ATT&CK: T1021 (远程服务), T1550 (使用替代认证材料)。"
            "排查建议: 谁触发的、目标服务器、时间模式。"
        ),
        "category": "login",
    },
    {
        "id": "evt_4740",
        "title": "事件 ID 4740 - 账户被锁定",
        "content": (
            "事件 ID 4740 表示账户被锁定，通常是在"
            "超过错误密码尝试阈值后触发。通常是暴力破解的指标。"
            "ATT&CK: T1110.001 (密码猜测)。"
            "排查建议: 之前的 4625 事件、来源 IP、锁定策略。"
        ),
        "category": "account",
    },
    {
        "id": "evt_7045",
        "title": "事件 ID 7045 - 新服务已安装",
        "content": (
            "系统日志中的事件 ID 7045 表示安装了新服务。"
            "常见的持久化技术。ATT&CK: T1543.003 (Windows 服务)。"
            "排查建议: 服务名、二进制路径、发布者、安装时间。"
        ),
        "category": "persistence",
    },
    {
        "id": "evt_1116",
        "title": "事件 ID 1116 - Defender 检测到恶意软件",
        "content": (
            "Windows Defender 检测到恶意软件 (事件 1116)。"
            "ATT&CK: T1059 (命令和脚本解释器), T1204 (用户执行)。"
            "排查建议: 检测名称、文件路径、采取的操作、用户上下文。"
        ),
        "category": "malware",
    },
    {
        "id": "evt_1117",
        "title": "事件 ID 1117 - Defender 已采取操作",
        "content": (
            "Windows Defender 已对检测到的恶意软件采取操作。"
            "可能的操作: 隔离、删除、允许。"
            "如果操作失败，威胁可能仍然活跃。"
            "验证: 检查文件是否仍然存在，使用替代工具扫描。"
        ),
        "category": "malware",
    },
    {
        "id": "evt_4720",
        "title": "事件 ID 4720 - 用户账户已创建",
        "content": (
            "创建了新用户账户。可能是合法的管理员操作，"
            "也可能是攻击者创建的后门账户。"
            "ATT&CK: T1136.001 (本地账户)。"
            "排查建议: 谁创建的账户、账户名、组成员关系。"
        ),
        "category": "account",
    },
    {
        "id": "evt_4697",
        "title": "事件 ID 4697 - 服务已安装 (安全日志)",
        "content": (
            "在安全日志中安装了服务。与 7045 类似但在"
            "安全通道中。通常表示持久化安装。"
            "ATT&CK: T1543.003。排查建议: 服务名、可执行文件路径。"
        ),
        "category": "persistence",
    },
    {
        "id": "brute_force_response",
        "title": "暴力破解攻击响应手册",
        "content": (
            "暴力破解攻击响应步骤: "
            "1. 从 4625 事件中识别来源 IP 和目标账户。"
            "2. 通过 Windows 防火墙封禁来源 IP: netsh advfirewall firewall add rule。"
            "3. 重置被入侵账户的密码。"
            "4. 如果未设置，启用账户锁定策略。"
            "5. 检查横向移动 (4648 事件)。"
            "6. 审查过去 24 小时的所有登录事件。"
        ),
        "category": "playbook",
    },
    {
        "id": "malware_response",
        "title": "恶意软件检测响应手册",
        "content": (
            "恶意软件检测响应步骤: "
            "1. 将受影响的终端从网络隔离。"
            "2. 识别恶意软件文件和隔离位置。"
            "3. 使用更新的签名运行全系统扫描。"
            "4. 检查持久化机制 (计划任务、服务、注册表)。"
            "5. 审查网络连接以查找 C2 通信。"
            "6. 收集取证工件以供进一步分析。"
        ),
        "category": "playbook",
    },
    {
        "id": "persistence_response",
        "title": "持久化机制响应手册",
        "content": (
            "检测到持久化的响应步骤: "
            "1. 识别持久化机制 (服务、计划任务、注册表键)。"
            "2. 停止并删除恶意服务/任务。"
            "3. 删除相关文件和注册表项。"
            "4. 检查多个持久化位置。"
            "5. 审查系统变更时间线。"
            "6. 在环境中扫描相关 IOC。"
        ),
        "category": "playbook",
    },
    {
        "id": "mitre_t1110",
        "title": "MITRE ATT&CK T1110 - 暴力破解",
        "content": (
            "攻击者可能使用暴力破解技术获取账户访问权限。"
            "技术: 密码猜测、密码喷洒、凭证填充。"
            "检测: 监控 4625 事件，跟踪每个来源/账户的失败登录率。"
            "缓解: 账户锁定策略、多因素认证、速率限制。"
        ),
        "category": "mitre",
    },
    {
        "id": "mitre_t1543",
        "title": "MITRE ATT&CK T1543 - 创建或修改系统进程",
        "content": (
            "攻击者可能创建或修改系统级进程以实现持久化。"
            "子技术: 启动代理、Systemd 服务、Windows 服务。"
            "检测: 监控 7045/4697 事件、服务创建告警。"
            "缓解: 限制服务创建权限。"
        ),
        "category": "mitre",
    },
]


class RAGKnowledgeBase:
    """Knowledge base with optional vector search and keyword fallback."""

    def __init__(self, persist_dir: Optional[str] = None):
        self._persist_dir = persist_dir
        self._collection = None
        self._use_vector = False

        # Try to initialize ChromaDB
        try:
            import chromadb
            from chromadb.config import Settings
            client = chromadb.Client(Settings(
                chroma_db_impl="duckdb+parquet",
                persist_directory=persist_dir or "./data/knowledge_db",
                anonymized_telemetry=False,
            ))
            names = {item if isinstance(item, str) else item.name for item in client.list_collections()}
            if LEGACY_COLLECTION_NAME in names:
                raise MigrationRequired('请先停止旧服务并运行 migrate_branding.py --knowledge-dir 旧知识库目录')
            self._collection = client.get_or_create_collection(
                name=COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
            # Populate if empty
            if self._collection.count() == 0:
                self._populate()
            self._use_vector = True
        except MigrationRequired:
            raise
        except Exception:
            self._use_vector = False

    def _populate(self):
        """Insert built-in knowledge entries into the vector store."""
        if not self._collection:
            return
        ids = [e["id"] for e in KNOWLEDGE_ENTRIES]
        docs = [e["content"] for e in KNOWLEDGE_ENTRIES]
        metas = [{"title": e["title"], "category": e["category"]} for e in KNOWLEDGE_ENTRIES]
        self._collection.add(ids=ids, documents=docs, metadatas=metas)

    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Search knowledge base. Returns list of {id, title, content, category, score}."""
        if self._use_vector and self._collection:
            return self._vector_search(query, top_k)
        return self._keyword_search(query, top_k)

    def _vector_search(self, query: str, top_k: int) -> List[Dict[str, Any]]:
        results = self._collection.query(query_texts=[query], n_results=top_k)
        items = []
        for i in range(len(results["ids"][0])):
            items.append({
                "id": results["ids"][0][i],
                "title": results["metadatas"][0][i].get("title", ""),
                "content": results["documents"][0][i],
                "category": results["metadatas"][0][i].get("category", ""),
                "score": 1 - results["distances"][0][i] if results.get("distances") else 0.0,
            })
        return items

    def _keyword_search(self, query: str, top_k: int) -> List[Dict[str, Any]]:
        """Simple keyword-based fallback search."""
        query_lower = query.lower()
        scored = []
        for entry in KNOWLEDGE_ENTRIES:
            text = (entry["title"] + " " + entry["content"]).lower()
            # Simple scoring: count keyword matches
            words = query_lower.split()
            score = sum(1 for w in words if w in text)
            if score > 0:
                scored.append((score, entry))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [
            {
                "id": e["id"],
                "title": e["title"],
                "content": e["content"],
                "category": e["category"],
                "score": s / max(len(query_lower.split()), 1),
            }
            for s, e in scored[:top_k]
        ]

    def get_context_for_event(self, event_id: int) -> str:
        """Get relevant knowledge context for a specific Windows event ID."""
        results = self.search(f"Event ID {event_id}", top_k=3)
        if not results:
            return ""
        return "\n\n".join(f"[{r['title']}]\n{r['content']}" for r in results)

    def get_all_entries(self) -> List[Dict[str, str]]:
        """Return all built-in knowledge entries."""
        return KNOWLEDGE_ENTRIES.copy()
