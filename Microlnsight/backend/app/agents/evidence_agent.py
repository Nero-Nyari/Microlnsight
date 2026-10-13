"""Only the supplied event is evidence; external integrations are not simulated."""
import json


def gather_evidence(parsed, raw_content):
    demo = parsed.get("is_demo", False)
    return [{
        "type": "log", "title": "演示日志（非真实告警）" if demo else "输入日志原文",
        "content": raw_content, "source": "demo_input" if demo else "provided_log", "confidence": 1.0,
    }, {
        "type": "context", "title": "日志来源与采集范围",
        "content": json.dumps({
            "platform": parsed.get("platform", "Unknown"), "event_id": parsed.get("event_id"),
            "channel": parsed.get("channel"), "computer": parsed.get("computer"),
            "provider_name": parsed.get("provider_name"), "timestamp": parsed.get("timestamp"),
            "说明": "仅依据输入日志；未查询 CMDB、威胁情报或漏洞库。置信度表示原文保留完整，不表示攻击已被证实。",
        }, ensure_ascii=False, indent=2),
        "source": "input_metadata", "confidence": 1.0,
    }]
