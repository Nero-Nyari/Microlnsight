"""应用配置."""
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

PROJECT_ROOT = Path(__file__).parent.parent.parent.resolve()
ENV_FILE = PROJECT_ROOT / ".env"
MODELS_FILE = PROJECT_ROOT / "data" / "models.json"


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _load_active_model_config() -> Optional[Dict[str, Any]]:
    """从 models.json 加载激活的模型配置."""
    if not MODELS_FILE.exists():
        return None
    try:
        models = json.loads(MODELS_FILE.read_text(encoding="utf-8"))
        for m in models:
            if m.get("is_active"):
                return m
        if models:
            return models[0]
    except Exception:
        pass
    return None


_load_env_file(ENV_FILE)

DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DATA_DIR / 'winsecagent.db'}")

# 优先使用 models.json 中的激活模型配置，其次使用环境变量
_active_model = None if os.environ.get("WINSEC_TEST_MODE") == "1" else _load_active_model_config()

if _active_model and _active_model.get("api_key"):
    # 使用 models.json 中的配置
    _llm_type = _active_model.get("provider", "deepseek")
    _api_key = _active_model.get("api_key", "")
    _base_url = _active_model.get("base_url", "")
    _model_name = _active_model.get("model", "deepseek-chat")
    
    # 根据 provider 设置默认 base_url
    if not _base_url:
        if _llm_type == "deepseek":
            _base_url = "https://api.deepseek.com"
        elif _llm_type == "openai":
            _base_url = "https://api.openai.com/v1"
else:
    # 使用环境变量配置
    _llm_type = os.environ.get("LLM_TYPE", "deepseek")
    _api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    _base_url = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    _model_name = os.environ.get("LLM_MODEL", "deepseek-v4-flash")

if not _api_key and _llm_type != "local":
    _llm_type = "local"

if os.environ.get("WINSEC_TEST_MODE") == "1":
    _llm_type, _api_key = "local", ""

DEFAULT_LLM_CONFIG: Dict[str, Any] = {
    "type": _llm_type,
    "api_key": _api_key,
    "base_url": _base_url,
    "model_name": _model_name,
}

CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")

APP_NAME = "WinSecAgent"
APP_VERSION = "1.0.0"
