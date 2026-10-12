"""统一 LLM 提供者 - 改编自 OpenCode ai_service."""
import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional

# 模型配置文件路径
MODELS_FILE = Path(__file__).parent.parent.parent / "data" / "models.json"


class LLMError(Exception):
    pass


class BaseLLMProvider(ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model_name = config.get("model_name", "")
        self.api_key = config.get("api_key", "")
        self.base_url = config.get("base_url", "")

    @abstractmethod
    def generate(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        pass


class LocalLLMProvider(BaseLLMProvider):
    def generate(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        import random
        responses = [
            "这是一个本地模拟的安全分析响应。",
            "当前使用本地模式，请配置真实模型 API 以获得分析结果。",
        ]
        return random.choice(responses)


class OpenAIProvider(BaseLLMProvider):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        try:
            from openai import OpenAI
        except ImportError:
            raise LLMError("未安装 openai 库")
        api_key = os.environ.get("OPENAI_API_KEY") or self.api_key
        base_url = os.environ.get("OPENAI_BASE_URL") or self.base_url or "https://api.openai.com/v1"
        if not api_key:
            raise LLMError("OpenAI API key 未配置")
        self.client = OpenAI(api_key=api_key, base_url=base_url)

    def generate(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        system = system or "你是一个专业的网络安全分析师，用中文回答。"
        model = kwargs.get("model") or self.model_name or "gpt-4o"
        response = self.client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            temperature=kwargs.get("temperature", 0.3),
            max_tokens=kwargs.get("max_tokens", 2048),
            stream=False,
        )
        return response.choices[0].message.content


class AnthropicProvider(BaseLLMProvider):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        try:
            import anthropic
        except ImportError:
            raise LLMError("未安装 anthropic 库")
        api_key = os.environ.get("ANTHROPIC_API_KEY") or self.api_key
        if not api_key:
            raise LLMError("Anthropic API key 未配置")
        self.client = anthropic.Anthropic(api_key=api_key)

    def generate(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        system = system or "你是一个专业的网络安全分析师，用中文回答。"
        model = kwargs.get("model") or self.model_name or "claude-3-haiku-20240307"
        response = self.client.messages.create(
            model=model,
            max_tokens=kwargs.get("max_tokens", 2048),
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text


class DeepSeekProvider(BaseLLMProvider):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        try:
            from openai import OpenAI
        except ImportError:
            raise LLMError("未安装 openai 库")
        # 优先使用配置中的 API Key，其次使用环境变量
        api_key = self.api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        base_url = self.base_url or os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        if not api_key:
            raise LLMError("DeepSeek API key 未配置")
        print(f"[DeepSeek] 初始化: base_url={base_url}, model={self.model_name}")
        self.client = OpenAI(api_key=api_key, base_url=base_url)

    def generate(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        system = system or "你是一个专业的网络安全分析师，用中文回答。"
        model = kwargs.get("model") or self.model_name
        params = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": kwargs.get("temperature", 0.3),
            "max_tokens": kwargs.get("max_tokens", 2048),
            "stream": False,
        }
        if model == "deepseek-v4-pro":
            # Short JSON stages need their token budget for the actual answer.
            # Otherwise reasoning can consume it and leave an empty content field.
            thinking = kwargs.get("max_tokens", 2048) > 2048
            params["extra_body"] = {"thinking": {"type": "enabled" if thinking else "disabled"}}
            if thinking:
                params["reasoning_effort"] = "high"
        try:
            response = self.client.chat.completions.create(**params)
        except TypeError as te:
            if "reasoning_effort" in str(te):
                params.pop("reasoning_effort", None)
                params.setdefault("extra_body", {}).pop("reasoning_effort", None)
                response = self.client.chat.completions.create(**params)
            else:
                raise
        content = response.choices[0].message.content
        if not content or not content.strip():
            raise LLMError("模型未返回正文，请检查模型参数或输出预算")
        return content


class OllamaProvider(BaseLLMProvider):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = os.environ.get("OLLAMA_BASE_URL") or self.base_url or "http://localhost:11434"

    def generate(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        import requests
        system = system or "你是一个专业的网络安全分析师，用中文回答。"
        model = kwargs.get("model") or self.model_name or "llama2"
        response = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
            },
            timeout=120,
        )
        if response.status_code != 200:
            raise LLMError(f"Ollama 请求失败: {response.status_code}")
        return response.json().get("message", {}).get("content", "")


class LLMProviderFactory:
    @staticmethod
    def create(config: Dict[str, Any]) -> BaseLLMProvider:
        model_type = config.get("type", "local").lower()
        if model_type == "local":
            return LocalLLMProvider(config)
        if model_type == "openai":
            return OpenAIProvider(config)
        if model_type == "anthropic":
            return AnthropicProvider(config)
        if model_type == "deepseek":
            return DeepSeekProvider(config)
        if model_type == "ollama":
            return OllamaProvider(config)
        raise LLMError(f"不支持的模型类型: {model_type}")


_provider: Optional[BaseLLMProvider] = None
_last_models_config: Optional[str] = None


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


def _build_config_from_model(model: Dict[str, Any]) -> Dict[str, Any]:
    """从模型配置构建 LLM 配置."""
    provider = model.get("provider", "deepseek").lower()
    api_key = model.get("api_key", "")
    base_url = model.get("base_url", "")
    model_name = model.get("model", "")
    
    # 根据 provider 设置默认 base_url
    if not base_url:
        if provider == "deepseek":
            base_url = "https://api.deepseek.com"
        elif provider == "openai":
            base_url = "https://api.openai.com/v1"
    
    return {
        "type": provider,
        "api_key": api_key,
        "base_url": base_url,
        "model_name": model_name,
    }


def get_llm_provider(config: Optional[Dict[str, Any]] = None) -> BaseLLMProvider:
    global _provider, _last_models_config

    if os.environ.get("WINSEC_TEST_MODE") == "1":
        if not isinstance(_provider, LocalLLMProvider):
            _provider = LocalLLMProvider({"type": "local"})
        return _provider
    
    # 检查 models.json 是否有更新
    try:
        if MODELS_FILE.exists():
            current_config = MODELS_FILE.read_text(encoding="utf-8")
            if current_config != _last_models_config:
                _last_models_config = current_config
                active_model = _load_active_model_config()
                if active_model and active_model.get("api_key"):
                    config = _build_config_from_model(active_model)
                    print(f"[LLM] 从 models.json 加载配置: type={config.get('type')}, model={config.get('model_name')}")
                    _provider = LLMProviderFactory.create(config)
                    return _provider
                else:
                    print("[LLM] models.json 中没有有效的激活模型配置")
    except Exception as e:
        print(f"[LLM] 读取 models.json 失败: {e}")
    
    if config is not None:
        _provider = LLMProviderFactory.create(config)
    if _provider is None:
        from app.core.config import DEFAULT_LLM_CONFIG
        print(f"[LLM] 使用默认配置: type={DEFAULT_LLM_CONFIG.get('type')}")
        _provider = LLMProviderFactory.create(DEFAULT_LLM_CONFIG)
    return _provider


def refresh_llm_provider() -> BaseLLMProvider:
    """强制刷新 LLM 提供者配置."""
    global _provider, _last_models_config
    _provider = None
    _last_models_config = None
    return get_llm_provider()
