"""模型管理 API 路由."""
import json
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/models", tags=["models"])

# 模型配置存储文件
MODELS_FILE = Path(__file__).parent.parent.parent / "data" / "models.json"


class ModelConfig(BaseModel):
    id: Optional[str] = None
    name: str
    provider: str
    model: str
    api_key: str
    base_url: Optional[str] = ""
    is_active: bool = False
    created_at: Optional[str] = None


def _load_models() -> List[dict]:
    """从文件加载模型配置."""
    if not MODELS_FILE.exists():
        return []
    try:
        return json.loads(MODELS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save_models(models: List[dict]) -> None:
    """保存模型配置到文件."""
    MODELS_FILE.parent.mkdir(exist_ok=True)
    MODELS_FILE.write_text(json.dumps(models, indent=2, ensure_ascii=False), encoding="utf-8")


@router.get("", response_model=List[ModelConfig])
def list_models():
    """获取所有模型配置."""
    return _load_models()


@router.get("/active", response_model=Optional[ModelConfig])
def get_active_model():
    """获取当前激活的模型."""
    models = _load_models()
    for m in models:
        if m.get("is_active"):
            return m
    return models[0] if models else None


@router.post("", response_model=ModelConfig)
def create_model(config: ModelConfig):
    """创建新的模型配置."""
    models = _load_models()

    # 生成 ID
    config.id = str(uuid.uuid4())[:8]
    config.created_at = str(Path().cwd())  # 简单的时间戳替代

    # 如果是第一个模型或设为激活，则取消其他激活状态
    if config.is_active or len(models) == 0:
        for m in models:
            m["is_active"] = False
        config.is_active = True

    models.append(config.model_dump())
    _save_models(models)
    return config


@router.delete("/{model_id}")
def delete_model(model_id: str):
    """删除模型配置."""
    models = _load_models()
    original_count = len(models)
    models = [m for m in models if m.get("id") != model_id]

    if len(models) == original_count:
        raise HTTPException(status_code=404, detail="模型不存在")

    # 如果删除的是激活模型，激活第一个
    if not any(m.get("is_active") for m in models) and models:
        models[0]["is_active"] = True

    _save_models(models)
    return {"ok": True}


@router.post("/{model_id}/activate")
def activate_model(model_id: str):
    """设置指定模型为激活状态."""
    models = _load_models()
    found = False

    for m in models:
        if m.get("id") == model_id:
            m["is_active"] = True
            found = True
        else:
            m["is_active"] = False

    if not found:
        raise HTTPException(status_code=404, detail="模型不存在")

    _save_models(models)
    return {"ok": True}


@router.post("/{model_id}/test")
def test_model(model_id: str):
    """测试模型连接."""
    models = _load_models()
    model = next((m for m in models if m.get("id") == model_id), None)

    if not model:
        raise HTTPException(status_code=404, detail="模型不存在")

    try:
        provider = model.get("provider", "").lower()
        api_key = model.get("api_key", "")
        base_url = model.get("base_url", "")
        model_name = model.get("model", "")

        if not api_key:
            return {"ok": False, "message": "API 密钥未配置"}

        if provider in ("openai", "deepseek"):
            from openai import OpenAI
            url = base_url or ("https://api.deepseek.com" if provider == "deepseek" else "https://api.openai.com/v1")
            client = OpenAI(api_key=api_key, base_url=url)
            response = client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": "Hi"}],
                max_tokens=5,
            )
            return {
                "ok": True,
                "message": f"连接成功！模型响应: {response.choices[0].message.content[:50]}",
                "provider": provider,
                "model": model_name,
            }
        elif provider == "anthropic":
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            response = client.messages.create(
                model=model_name,
                max_tokens=5,
                messages=[{"role": "user", "content": "Hi"}],
            )
            return {
                "ok": True,
                "message": f"连接成功！模型响应: {response.content[0].text[:50]}",
                "provider": provider,
                "model": model_name,
            }
        elif provider == "ollama":
            import requests
            url = base_url or "http://localhost:11434"
            resp = requests.post(
                f"{url}/api/chat",
                json={"model": model_name, "messages": [{"role": "user", "content": "Hi"}], "stream": False},
                timeout=30,
            )
            if resp.status_code == 200:
                return {"ok": True, "message": "Ollama 连接成功！", "provider": provider, "model": model_name}
            else:
                return {"ok": False, "message": f"Ollama 连接失败: {resp.status_code}"}
        else:
            return {"ok": False, "message": f"不支持的提供商: {provider}"}

    except Exception as e:
        return {"ok": False, "message": f"连接测试失败: {str(e)}"}


@router.post("/refresh")
def refresh_config():
    """刷新 LLM 配置，使其立即生效."""
    try:
        from app.core.llm_provider import refresh_llm_provider
        refresh_llm_provider()
        return {"ok": True, "message": "配置已刷新"}
    except Exception as e:
        return {"ok": False, "message": f"刷新失败: {str(e)}"}
