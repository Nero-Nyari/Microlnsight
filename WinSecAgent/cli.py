"""Windows terminal interface for local, evidence-based WinSecAgent analysis."""

from __future__ import annotations

import argparse
from calendar import monthrange
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import unicodedata


ROOT = Path(__file__).resolve().parent
DEFAULT_DATABASE = ROOT / "backend" / "data" / "cli-preview.db"
DEFAULT_SERVER_REPORTS = ROOT / "backend" / "data" / "server-reports"
DEMO_CHOICES = ("windows_demo_normal", "windows_demo_single", "windows_demo_sequence")
EVENT_NAMES = {
    "4104": "PowerShell 脚本块记录", "4624": "账户登录成功", "4625": "账户登录失败",
    "4648": "使用显式凭据尝试登录", "4697": "安装服务", "4720": "创建账户",
    "4722": "启用账户", "4724": "尝试重置密码", "4726": "删除账户",
    "4732": "向本地组添加成员", "4740": "账户被锁定", "5156": "筛选平台允许连接",
    "7045": "安装新服务", "1116": "Defender 检测到威胁", "1117": "Defender 执行防护操作",
    "4627": "登录账户的组成员信息", "4672": "新登录会话获授特殊权限",
    "4798": "查询用户的本地组成员身份", "5379": "凭据管理器中的保存凭据被读取",
}
EVENT_CHANNELS = {
    "4104": "microsoft-windows-powershell/operational",
    "7045": "system",
    "1116": "microsoft-windows-windows defender/operational",
    "1117": "microsoft-windows-windows defender/operational",
    **{key: "security" for key in ("4624", "4625", "4627", "4648", "4672", "4697", "4720", "4722", "4724", "4726", "4732", "4740", "4798", "5156", "5379")},
}


def _width() -> int:
    """Keep output readable in both narrow terminals and captured output."""
    return max(32, min(shutil.get_terminal_size(fallback=(88, 24)).columns, 100))


def _cell_width(value: str) -> int:
    return sum(0 if unicodedata.combining(char) else
               2 if unicodedata.east_asian_width(char) in ("F", "W") else 1
               for char in value)


def _style(value: str, color: str) -> str:
    enabled = (sys.stdout.isatty() and "NO_COLOR" not in os.environ
               and (os.name != "nt" or os.environ.get("WT_SESSION")
                    or os.environ.get("TERM_PROGRAM") == "Windows_Terminal"))
    return f"\x1b[{color}m{value}\x1b[0m" if enabled else value


def _wrap(value: object, indent: str = "", continuation: str | None = None) -> None:
    """Wrap mixed Chinese and Latin text by terminal cells, without losing words."""
    continuation = indent if continuation is None else continuation
    text = str(value).replace("\r", " ").replace("\n", " ").replace("\t", "    ")
    text = re.sub(r"[\x00-\x1f\x7f-\x9f]", lambda match: f"\\x{ord(match.group()):02x}", text)
    prefix = indent
    line = prefix
    for token in re.findall(r"[A-Za-z0-9_./:#-]+|\s+|.", text):
        if _cell_width(line + token) > _width() and line != prefix:
            print(line.rstrip())
            prefix = continuation
            line = prefix
            token = token.lstrip()
        if _cell_width(line + token) > _width() and line == prefix:
            for char in token:
                if _cell_width(line + char) > _width() and line != prefix:
                    print(line.rstrip())
                    prefix = continuation
                    line = prefix
                line += char
        else:
            line += token
    print(line.rstrip())


def _heading(title: str, subtitle: str = "") -> None:
    print()
    print(_style("─" * _width(), "36"))
    print(_style(f"  {title}", "1;36"))
    if subtitle:
        _wrap(subtitle, "  ")
    print(_style("─" * _width(), "36"))


def _note(label: str, value: object) -> None:
    _wrap(f"{label}  {value}", "  ", "    ")


def _menu() -> None:
    _heading("WinSecAgent  ·  命令行工作台", "选择数字后按回车")
    print(_style("  Windows 日志", "1"))
    print("    1  演示案例")
    print("    2  导入本机日志")
    print("    3  查找记录")
    print("    4  线索详情与单条分析")
    print("    5  报告预览与导出")
    print("    6  批量分析已导入日志")
    print(_style("  服务器日志", "1"))
    print("    7  分析导出的日志目录")
    print(_style("  工作台", "1"))
    print("    8  首页总览")
    print("    9  后台任务状态")
    print(_style("  模型与防护建议", "1"))
    print("   10  模型配置与选择")
    print("   11  采集分析与防护建议")
    print("   12  防护任务、证据与追问")
    print("    0  退出")


def _short(value, limit: int = 64) -> str:
    clean = re.sub(r"[\x00-\x1f\x7f-\x9f]+", " ", str(value or "")).strip()
    return clean[:limit] + ("…" if len(clean) > limit else "")


def _input_path(value: str | Path) -> Path:
    raw = str(value).strip()
    if raw.startswith(('"', "'")) or raw.endswith(('"', "'")):
        if len(raw) < 2 or raw[0] != raw[-1] or raw[0] not in ('"', "'"):
            raise ValueError("保存路径两端的引号不匹配")
        raw = raw[1:-1].strip()
    if not raw:
        raise ValueError("路径不能为空")
    return Path(raw).expanduser()


def _report_path(value: str | Path) -> Path:
    path = _input_path(value)
    if path.is_dir():
        path = path / "WinSecAgent-report.md"
    elif not path.suffix:
        path = path.with_suffix(".md")
    return path.resolve()


def _server_output_path(source: Path, output: Path | None) -> Path:
    if output is None:
        filename = "server-report-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".md"
        output = DEFAULT_SERVER_REPORTS / filename
    path = _report_path(output)
    if path.is_relative_to(source.resolve()):
        raise ValueError("报告不能保存在原始日志目录内，请选择其他位置")
    return path


def _save_server_analysis(source: Path, output: Path) -> dict:
    from server_logs import analyze_directory, render_report

    result = analyze_directory(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_report(result), encoding="utf-8")
    return result


def _show_server_analysis(result: dict, output: Path) -> None:
    from server_logs import render_console

    _heading("服务器日志 · 离线分析")
    for line in render_console(result).splitlines():
        _wrap(line, "  ", "    ")
    for warning in result["warnings"]:
        _note("范围", warning)
    _note("报告已保存", output)


def analyze_server_directory(source: str | Path, output: Path | None = None) -> dict:
    source = _input_path(source).resolve()
    if not source.is_dir():
        raise ValueError(f"服务器日志目录不存在：{source}")
    output = _server_output_path(source, output)
    result = _save_server_analysis(source, output)
    _show_server_analysis(result, output)
    return result


@dataclass
class ServerJob:
    source: Path
    output: Path
    future: Future
    shown: bool = False


class ServerJobs:
    """One read-only server analysis at a time; the menu stays responsive."""

    def __init__(self) -> None:
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="server-log-analysis")
        self.current: ServerJob | None = None

    def start(self, source: str | Path, output: Path | None = None) -> None:
        if self.current and not self.current.future.done():
            raise ValueError("已有服务器日志任务正在运行，请先查看任务状态")
        if self.current and not self.current.shown:
            self.status()
        directory = _input_path(source).resolve()
        if not directory.is_dir():
            raise ValueError(f"服务器日志目录不存在：{directory}")
        path = _server_output_path(directory, output)
        self.current = ServerJob(directory, path,
                                 self.executor.submit(_save_server_analysis, directory, path))
        _note("任务已开始", f"只读分析 {directory}")

    def status(self, *, full: bool = False) -> None:
        job = self.current
        if not job:
            if full:
                _note("后台任务", "本次运行尚无服务器日志分析任务")
        elif not job.future.done():
            _note("后台任务", f"正在分析 {job.source}")
        elif full or not job.shown:
            job.shown = True
            try:
                _show_server_analysis(job.future.result(), job.output)
            except Exception as exc:
                _note("任务失败", exc)

    def close(self) -> None:
        if self.current and not self.current.future.done():
            _note("退出", "正在等待当前只读分析完成")
        self.executor.shutdown(wait=True)
        self.status()


def _event_name(event_id, channel=None, provider=None, message=None) -> str:
    name = EVENT_NAMES.get(str(event_id)) if str(channel or "").casefold() == EVENT_CHANNELS.get(str(event_id)) else None
    if name:
        return name
    source = _short(provider, 36)
    snippet = _short(message, 50)
    if snippet.startswith(("{", "[")):
        snippet = ""
    details = "；".join(part for part in (f"来源：{source}" if source else "", f"日志摘录：{snippet}" if snippet else "") if part)
    return f"未收录的事件类型（{details}）" if details else "未收录的事件类型"


def _show_event_summary(events: list[dict], *, parsed: bool = False) -> None:
    if not events:
        print("没有可汇总的日志。")
        return
    counts = Counter()
    examples = {}
    for event in events:
        if parsed:
            channel, event_id, provider, message = event.get("channel"), event.get("event_id"), event.get("provider_name"), None
            if event.get("raw_content"):
                try:
                    message = json.loads(event["raw_content"]).get("Message")
                except (ValueError, TypeError, AttributeError):
                    pass
        else:
            channel, event_id, provider, message = event.get("Channel"), event.get("EventID"), event.get("ProviderName"), event.get("Message")
        key = (_short(channel, 36) or "未知通道", str(event_id or "未知"), _short(provider, 36))
        counts[key] += 1
        examples.setdefault(key, message)
    _heading("事件概览", "括号内是 Windows 事件编号；单凭编号不能判断风险")
    for (channel, event_id, provider), count in counts.most_common(15):
        _wrap(f"{_event_name(event_id, channel, provider, examples.get((channel, event_id, provider)))}（{event_id}，{channel}）：{count} 条", "  • ", "    ")
    if len(counts) > 15:
        _note("其余", f"{len(counts) - 15} 种事件类型，{sum(counts.values()) - sum(n for _, n in counts.most_common(15))} 条")


def _prepare_database(path: Path) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    os.environ["DATABASE_URL"] = f"sqlite:///{path.as_posix()}"
    sys.path.insert(0, str(ROOT / "backend"))
    from app import models  # noqa: F401 - registers tables with Base
    from app.db.base import Base
    from app.db.session import engine

    Base.metadata.create_all(bind=engine)


def _session():
    from app.db.session import SessionLocal

    return SessionLocal()


def _incident(db, incident_id: int):
    from app import models

    incident = db.get(models.Incident, incident_id)
    if incident is None:
        raise ValueError(f"找不到记录 #{incident_id}（命令行试用版使用独立数据库）")
    return incident


def _show_result(incident) -> None:
    from app.services.analysis_view import assessment_for, current_runs

    assessment = assessment_for(incident)
    _heading(f"记录 #{incident.id}  ·  {assessment['label']}")
    _wrap(assessment["reasoning"], "  ", "  ")
    correlation = current_runs(incident).get("Correlation")
    if correlation and correlation.output_data:
        result = correlation.output_data
        for finding in result["findings"]:
            _wrap(finding["title"], "  • ", "    ")
            _wrap(finding["reason"], "    ")
            _note("依据日志", "、".join(f"#{ref}" for ref in finding["record_refs"]))
        for warning in result["warnings"]:
            _note("范围", warning)
    _note("提醒", "结论需核对原始证据；本命令行界面不执行系统处置。")


def load_demo(db, case_id: str) -> int:
    from app.api.alerts import create_from_case
    from app import models

    alert = create_from_case(case_id, db)
    incident = db.query(models.Incident).filter_by(alert_id=alert.id).one()
    print(f"已导入演示案例：{case_id}（合成数据）")
    analyze(db, incident.id)
    return incident.id


def analyze(db, incident_id: int, window_minutes: int = 15) -> None:
    from app.services.correlation import save_analysis

    incident = _incident(db, incident_id)
    if incident.status == "analyzing":
        raise ValueError("该记录正在分析中")
    save_analysis(db, incident, window_minutes)
    _show_result(incident)


@dataclass(frozen=True)
class RecordFilters:
    since: str = ""
    until: str = ""
    source: str = ""
    event: str = ""
    conclusion: str = ""


def _record_time(incident, source: dict) -> datetime:
    value = source.get("timestamp")
    if value:
        try:
            stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return stamp.astimezone().replace(tzinfo=None) if stamp.tzinfo else stamp
        except ValueError:
            pass
    return incident.created_at


def _event_message(incident) -> str | None:
    try:
        payload = json.loads(incident.alert.raw_content or "{}")
        return payload.get("Message") if isinstance(payload, dict) else None
    except (ValueError, TypeError):
        return None


def _filter_time(value: str, *, end: bool = False) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    date = re.match(r"(\d{4})-(\d{1,2})-(\d{1,2})(?=$|[ T])", value)
    date_only = bool(date and date.end() == len(value))
    if date:
        year, month, day = map(int, date.groups())
        if not 1 <= year <= 9999:
            raise ValueError("年份必须在 1 至 9999 之间")
        if not 1 <= month <= 12:
            raise ValueError("月份必须在 1 至 12 之间")
        days = monthrange(year, month)[1]
        if not 1 <= day <= days:
            raise ValueError(f"{year} 年 {month} 月只有 {days} 天，请填写 1 至 {days} 日")
        value = f"{year:04d}-{month:02d}-{day:02d}" + value[date.end():]
    try:
        stamp = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("请输入有效日期或时间，例如 2026-06-30 或 2026-06-30 14:30") from exc
    if stamp.tzinfo:
        stamp = stamp.astimezone().replace(tzinfo=None)
    if end and date_only:
        stamp = stamp.replace(hour=23, minute=59, second=59, microsecond=999999)
    return stamp


def _matching_records(db, filters: RecordFilters, max_scan: int = 5000):
    from app import models
    from app.agents.event_context import extract_event_context
    from app.services.analysis_view import assessment_for
    from sqlalchemy.orm import selectinload

    since = _filter_time(filters.since)
    until = _filter_time(filters.until, end=True)
    if since and until and since > until:
        raise ValueError("开始时间不能晚于结束时间")
    incidents = (db.query(models.Incident)
                 .options(selectinload(models.Incident.alert), selectinload(models.Incident.agent_runs))
                 .order_by(models.Incident.id.desc()).limit(max_scan + 1).all())
    truncated = len(incidents) > max_scan
    matches = []
    for incident in incidents[:max_scan]:
        source = extract_event_context(incident.alert.raw_content or "")
        stamp = _record_time(incident, source)
        if since and stamp < since or until and stamp > until:
            continue
        source_text = " ".join(str(item or "") for item in
                               (incident.alert.source_type, source.get("channel"), source.get("provider_name"),
                                source.get("computer"), source.get("source_ip"))).casefold()
        if filters.source and filters.source.casefold() not in source_text:
            continue
        event_id = str(source.get("event_id") or "未知")
        event_name = _event_name(event_id, source.get("channel"), source.get("provider_name"), _event_message(incident))
        if filters.event and filters.event.casefold() not in f"{event_id} {event_name}".casefold():
            continue
        assessment = assessment_for(incident)
        if filters.conclusion and filters.conclusion.casefold() not in assessment["label"].casefold():
            continue
        matches.append((incident, source, stamp, event_name, assessment["label"]))
    return matches, truncated


def list_records(db, limit: int = 10, filters: RecordFilters | None = None) -> None:
    matches, truncated = _matching_records(db, filters or RecordFilters())
    incidents = matches[:limit]
    if not incidents:
        print("没有匹配的记录。可调整筛选条件，或先导入日志。")
        return
    _heading("记录列表", f"匹配 {len(matches)} 条 · 显示前 {len(incidents)} 条；记录 ID 可用于菜单 4/5")
    for incident, source, stamp, event_name, conclusion in incidents:
        event_id = source.get("event_id") or "未知"
        _wrap(f"#{incident.id}  {stamp:%Y-%m-%d %H:%M}  {event_name}（{event_id}）", "  ", "      ")
        _note("来源 / 单条状态", f"{_short(source.get('channel')) or incident.alert.source_type} · {conclusion}")
    if truncated:
        _note("范围", "仅搜索数据库中最新 5000 条记录")


def show_overview(db, jobs: ServerJobs | None = None) -> None:
    from app import models
    from app.agents.event_context import extract_event_context
    from app.services.analysis_view import assessment_for
    from sqlalchemy.orm import selectinload

    incidents = (db.query(models.Incident)
                 .options(selectinload(models.Incident.alert), selectinload(models.Incident.agent_runs))
                 .order_by(models.Incident.id.desc()).limit(1001).all())
    sampled = incidents[:1000]
    counts = Counter(assessment_for(item)["label"] for item in sampled)
    times = [_record_time(item, extract_event_context(item.alert.raw_content or "")) for item in sampled]
    _heading("首页总览", "以下数字只覆盖已导入数据库的记录")
    actual = sum(item.alert.source_type == "windows_log" for item in sampled)
    demo = sum(item.alert.source_type == "windows_demo" for item in sampled)
    _note("Windows 记录", f"真实 {actual} 条 · 演示 {demo} 条")
    if times:
        _note("日志时间", f"{min(times):%Y-%m-%d %H:%M} 至 {max(times):%Y-%m-%d %H:%M}")
    for label, count in counts.most_common():
        _note(label, f"{count} 条")
    if len(incidents) > 1000:
        _note("范围", "总览仅统计最新 1000 条；可在菜单 3 查找更多记录")
    reports = list(DEFAULT_SERVER_REPORTS.glob("server-report-*.md")) if DEFAULT_SERVER_REPORTS.exists() else []
    if reports:
        latest = max(reports, key=lambda item: item.stat().st_mtime)
        _note("服务器报告", f"已有 {len(reports)} 份 · 最近：{latest}")
    if jobs and jobs.current and not jobs.current.future.done():
        _note("后台任务", "服务器日志分析中；菜单 9 可查看状态")
    _note("提醒", "未发现线索不代表整机安全；未导入记录不在统计范围内")


def show_record_detail(db, incident_id: int, *, raw: bool = False) -> None:
    from app.agents.event_context import extract_event_context
    from app.services.analysis_view import assessment_for, current_runs

    incident = _incident(db, incident_id)
    source = extract_event_context(incident.alert.raw_content or "")
    assessment = assessment_for(incident)
    event_id = source.get("event_id") or "未知"
    _heading(f"记录 #{incident.id}  ·  {assessment['label']}")
    _note("发生了什么", f"{_event_name(event_id, source.get('channel'), source.get('provider_name'), _event_message(incident))}（{event_id}）")
    _note("时间 / 通道", f"{_record_time(incident, source):%Y-%m-%d %H:%M} · {source.get('channel') or '未知'}")
    _note("主机 / 来源", f"{source.get('computer') or '未知'} · {source.get('source_ip') or '未知'}")
    _note("判断依据", assessment["reasoning"])
    correlation = current_runs(incident).get("Correlation")
    if correlation and correlation.status == "success" and correlation.output_data:
        for finding in correlation.output_data.get("findings", []):
            _wrap(finding["title"], "  • ", "    ")
            _wrap(finding["reason"], "    ")
            _note("证据记录 ID", "、".join(f"#{ref}" for ref in finding.get("record_refs", [])))
    elif assessment.get("findings"):
        for finding in assessment["findings"]:
            _wrap(finding.get("reason", "原文线索"), "  • ", "    ")
            if finding.get("quote"):
                _wrap(finding["quote"], "    ")
    for missing in assessment.get("missing_evidence", [])[:5]:
        _note("待补证", missing)
    if raw:
        _heading("原始日志", "以下是导入时保存的原文")
        content = incident.alert.raw_content or "（无原文）"
        for line in content[:12000].splitlines():
            _wrap(line, "  ", "  ")
        if len(content) > 12000:
            _note("范围", "终端仅显示前 12000 字；完整原文仍保存在数据库与报告中")


def read_logs(channels: list[str], max_events: int) -> dict:
    from app.services.log_reader import read_windows_logs

    if platform.system() != "Windows":
        raise RuntimeError("本机 Windows 日志读取只支持 Windows；演示案例可在其他系统验证")
    # Include successful logons as context for the failed-then-success rule.
    result = read_windows_logs(channels=channels, suspicious_only=False, max_events=max_events)
    if result["is_mock"]:
        raise RuntimeError("读取器返回了演示数据，已拒绝作为本机日志导入")
    _heading("本机日志读取")
    _note("读取结果", f"{result['total_raw']} 条真实日志 · {result['read_status']}")
    for channel in result["channel_results"]:
        _wrap(f"{channel['channel']}：{channel['status']}，{channel['events_read']} 条"
              + (f"；{channel.get('message')}" if channel.get("message") else ""), "  • ", "    ")
        if channel["events_read"] >= max_events:
            _note("读取上限", f"{channel['channel']} 达到本次 {max_events} 条上限；可能还有更早记录，未读数量未知")
    result["requested_max_events"] = max_events
    _show_event_summary(result["events"])
    if result["read_status"] == "failed":
        raise RuntimeError("所选通道均读取失败，未导入日志。可先尝试 Application 通道或演示案例；Security 权限请由系统管理员核实")
    return result


def import_logs(db, result: dict) -> list[int]:
    from app import models
    from app.agents.event_context import serialize_windows_event
    from app.api.logs import _event_to_severity

    ids = []
    for event in result["events"]:
        alert = models.Alert(
            title=f"EventID {event.get('EventID')} - {event.get('Channel', 'Unknown')}",
            raw_content=serialize_windows_event(event, is_demo=False),
            source_type="windows_log", severity=_event_to_severity(event.get("EventID", 0)),
            status="pending",
        )
        db.add(alert)
        db.flush()
        incident = models.Incident(alert_id=alert.id, status="pending")
        db.add(incident)
        db.flush()
        ids.append(incident.id)
    db.commit()
    _note("导入完成", f"{len(ids)} 条真实日志已存入命令行试用数据库")
    return ids


def batch_analyze(db, incident_ids: list[int] | None = None, output: Path | None = None,
                  collection: dict | None = None) -> dict:
    from app import models
    from app.agents.report_agent import correlation_report
    from app.services.correlation import analyze_records, record, MAX_CANDIDATES

    query = (db.query(models.Incident).join(models.Alert)
             .filter(models.Alert.source_type == "windows_log")
             .order_by(models.Incident.id.desc()))
    if incident_ids is not None:
        query = query.filter(models.Incident.id.in_(incident_ids))
    selected_total = query.count()
    incidents = query.limit(MAX_CANDIDATES).all()
    if not incidents:
        raise ValueError("没有可批量分析的真实日志；请先读取并导入")
    truncated = selected_total > MAX_CANDIDATES
    warnings = ["仅分析本次选取且已导入的真实日志；未读通道和未导入记录不在范围内。"]
    if truncated:
        warnings.append(f"所选范围共 {selected_total} 条，仅分析最新 {MAX_CANDIDATES} 条，超限跳过 {selected_total - len(incidents)} 条。")
    if collection:
        for channel in collection["channel_results"]:
            if channel["status"] != "success":
                warnings.append(f"采集范围：{channel['channel']} {channel['status']}；{channel.get('message') or '读取未完成'}")
            limit = collection.get("requested_max_events")
            if limit and channel["events_read"] >= limit:
                warnings.append(f"{channel['channel']} 达到采集上限 {limit} 条，未读数量未知。")
    else:
        warnings.append("历史采集覆盖信息尚未持久化；本次仅能确认已导入记录，无法核实原通道是否读全。")
    result = analyze_records([record(i.alert, i.id) for i in incidents], warnings=warnings)
    result["scope"] = "batch"
    result["coverage"].update(selected_total=selected_total, skipped_limit=selected_total - len(incidents))
    incident_by_alert = {i.alert_id: i.id for i in incidents}
    _heading("批量分析结果")
    _note("分析范围", f"{len(incidents)} 条真实日志 · 去重后 {len(result['records'])} 条")
    coverage = result["coverage"]
    _note("范围统计", f"所选 {selected_total} 条 · 超限跳过 {coverage['skipped_limit']} 条 · 重复排除 {coverage['duplicates']} 条 · 标识冲突排除 {coverage['conflicts']} 条")
    _note("解析质量", f"结构已识别 {coverage['identified']} 条 · 未识别 {coverage['unparsed']} 条 · 缺带时区时间 {coverage['missing_time']} 条 · 规则未覆盖 {coverage['unsupported']} 条")
    for source in coverage["sources"]:
        _note("来源时间（UTC）", f"{source['host']} / {source['channel']} · {source['retained']} 条 · {source['start'] or '未知'} 至 {source['end'] or '未知'}")
    _show_event_summary(result["records"], parsed=True)
    _heading(f"结论  ·  {result['assessment']['label']}")
    if result["findings"]:
        for finding in result["findings"]:
            _wrap(finding["title"], "  • ", "    ")
            _wrap(finding["reason"], "    ")
            _note("证据记录 ID", "、".join(f"#{incident_by_alert.get(ref, ref)}" for ref in finding["record_refs"]))
    else:
        _wrap(result["assessment"]["reasoning"], "  ")
        _wrap("当前规则主要检查短时间重复登录失败、失败后成功，以及可疑的自动启动服务路径；未命中不代表其余事件均安全。", "  ")
    for warning in result["warnings"]:
        _note("范围", warning)
    _note("提醒", "结论需核对原始证据；本命令行界面不执行系统处置。")
    if output:
        output = _report_path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(correlation_report("所选真实日志", result), encoding="utf-8")
        _note("批量报告已保存", output)
    return result


def _report_content(db, incident_id: int) -> str:
    from app import models
    from app.services.analysis_view import report_view

    _incident(db, incident_id)
    report = db.query(models.Report).filter_by(incident_id=incident_id).order_by(models.Report.id.desc()).first()
    if report is None:
        raise ValueError(f"记录 #{incident_id} 尚无报告，请先运行分析")
    return report_view(report)["content"]


def preview_report(db, incident_id: int, lines: int = 30) -> None:
    content = _report_content(db, incident_id)
    parts = content.splitlines()
    _heading(f"记录 #{incident_id}  ·  报告预览")
    for line in parts[:lines]:
        _wrap(line, "  ", "  ")
    if len(parts) > lines:
        _note("预览", f"还有 {len(parts) - lines} 行；可导出完整 Markdown 报告")


def show_report(db, incident_id: int, output: Path | None = None) -> None:
    content = _report_content(db, incident_id)
    if output:
        output = _report_path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
        _note("报告已保存", output)
    else:
        print(content)


def _ask_id() -> int:
    return int(input("输入记录 ID：").strip())


def _ask_filter_time(label: str, *, end: bool = False, earliest: datetime | None = None) -> str:
    while True:
        value = input(f"  {label} YYYY-MM-DD [可跳过]：").strip()
        try:
            stamp = _filter_time(value, end=end)
            if stamp is not None and earliest is not None and stamp < earliest:
                raise ValueError("结束时间不能早于开始时间，请重新填写结束时间")
            return value
        except ValueError as exc:
            _note("日期有误", exc)


def _ask_filters() -> RecordFilters:
    _heading("查找记录", "直接回车可跳过条件；时间按日志时间筛选")
    since = _ask_filter_time("开始时间")
    until = _ask_filter_time("结束时间", end=True, earliest=_filter_time(since))
    return RecordFilters(
        since=since,
        until=until,
        source=input("  来源（通道、主机或 IP）[可跳过]：").strip(),
        event=input("  事件类型（编号或名称）[可跳过]：").strip(),
        conclusion=input("  结论关键词 [可跳过]：").strip(),
    )


def _windows_import_wizard(db) -> None:
    _heading("导入本机 Windows 日志", "先读取预览，再决定是否导入并分析；每次最多读取 200 条")
    print("  1  Security（默认）\n  2  Application\n  3  System")
    answer = input("  选择通道 [1-3] > ").strip()
    channel = {"": "Security", "1": "Security", "2": "Application", "3": "System",
               "Security": "Security", "Application": "Application", "System": "System"}.get(answer)
    if channel is None:
        raise ValueError("请选择 1、2 或 3")
    result = read_logs([channel], 200)
    if not result["events"]:
        _note("读取结果", "没有可导入的记录；请查看通道状态或调整读取范围")
        return
    if input("  导入并批量分析上述日志？输入 y 确认：").strip().lower() == "y":
        batch_analyze(db, import_logs(db, result), collection=result)


def _server_import_wizard(jobs: ServerJobs) -> None:
    from server_logs import LOG_FILES

    _heading("导入服务器日志目录", "只读分析导出文件；报告保存在本机其他目录")
    source = _input_path(input("  服务器日志目录：")).resolve()
    if not source.is_dir():
        raise ValueError(f"服务器日志目录不存在：{source}")
    found = [name for name in LOG_FILES if (source / name).is_file()]
    missing = [name for name in LOG_FILES if name not in found]
    _note("识别文件", "、".join(found) if found else "无")
    _note("缺失文件", "、".join(missing) if missing else "无")
    _note("校验清单", "已找到" if (source / "SHA256SUMS.txt").is_file() else "未找到；无法校验导出清单")
    if not found:
        raise ValueError("目录中没有可识别的 SSH、Nginx 或应用日志")
    path = input("  报告保存路径（直接回车自动保存到本地）：").strip()
    jobs.start(source, Path(path) if path else None)


def _record_detail_menu(db) -> None:
    incident_id = _ask_id()
    show_record_detail(db, incident_id)
    while True:
        answer = input("  1 查看原文  2 运行单条分析  3 预览报告  0 返回 > ").strip()
        if answer == "0" or not answer:
            return
        if answer == "1":
            show_record_detail(db, incident_id, raw=True)
        elif answer == "2":
            analyze(db, incident_id)
        elif answer == "3":
            preview_report(db, incident_id)
        else:
            print("请选择 0、1、2 或 3。")


def menu(db, database=DEFAULT_DATABASE) -> None:
    from guard_cli import resources, configure, wizard, task_menu
    store, profiles = resources(database)
    jobs = ServerJobs()
    try:
        show_overview(db, jobs)
        while True:
            jobs.status()
            _menu()
            choice = input("  选择 [0-12] > ").strip()
            try:
                if choice == "0":
                    return
                if choice == "1":
                    _heading("演示案例")
                    print("  1  正常运维\n  2  单次登录失败\n  3  连续失败后成功")
                    case = input("  选择 [1-3] > ").strip()
                    if case not in ("1", "2", "3"):
                        print("请选择 1、2 或 3。")
                        continue
                    load_demo(db, DEMO_CHOICES[int(case) - 1])
                elif choice == "2":
                    _windows_import_wizard(db)
                elif choice == "3":
                    list_records(db, filters=_ask_filters())
                elif choice == "4":
                    _record_detail_menu(db)
                elif choice == "5":
                    incident_id = _ask_id()
                    preview_report(db, incident_id)
                    path = input("  保存路径（直接回车不导出）：").strip()
                    if path:
                        show_report(db, incident_id, Path(path))
                elif choice == "6":
                    path = input("批量报告保存路径（直接回车仅显示摘要）：").strip()
                    batch_analyze(db, output=Path(path) if path else None)
                elif choice == "7":
                    _server_import_wizard(jobs)
                elif choice == "8":
                    show_overview(db, jobs)
                elif choice == "9":
                    jobs.status(full=True)
                elif choice == "10":
                    configure(profiles)
                elif choice == "11":
                    wizard(store, profiles)
                elif choice == "12":
                    task_menu(store, profiles)
                else:
                    print("无效选项。")
            except (ValueError, OSError, RuntimeError) as exc:
                db.rollback()
                print(f"操作失败：{exc}")
    finally:
        jobs.close()


def main(argv: list[str] | None = None) -> int:
    from terminal_ui import setup_terminal
    setup_terminal()
    parser = argparse.ArgumentParser(description="WinSecAgent 命令行工作台（Windows / Linux，不启动网页）")
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE, help="试用数据库路径")
    commands = parser.add_subparsers(dest="command")
    from guard_cli import add_commands, dispatch
    add_commands(commands)
    demo = commands.add_parser("demo", help="导入并分析合成演示案例")
    demo.add_argument("case", choices=DEMO_CHOICES)
    scan = commands.add_parser("scan", help="读取本机 Windows 事件日志")
    scan.add_argument("--channel", action="append", dest="channels", default=None, help="日志通道；默认 Security，可重复指定")
    scan.add_argument("--max-events", type=int, default=200, help="每个通道最多读取的事件数")
    scan.add_argument("--import-logs", action="store_true", help="将本次读取的日志导入试用数据库")
    listing = commands.add_parser("list", help="查看最近记录")
    listing.add_argument("--limit", type=int, default=20)
    analysis = commands.add_parser("analyze", help="对一条记录运行本地联合分析")
    analysis.add_argument("id", type=int)
    analysis.add_argument("--window-minutes", type=int, default=15)
    batch = commands.add_parser("batch", help="对已导入的真实日志批量联合分析")
    batch.add_argument("--output", type=Path, help="保存包含原始证据的 Markdown 报告")
    server = commands.add_parser("server", help="只读分析导出的 Linux 服务器日志目录")
    server.add_argument("directory", type=Path)
    server.add_argument("--output", type=Path, help="报告路径；省略时自动保存到本地数据目录")
    report = commands.add_parser("report", help="查看或保存已生成的 Markdown 报告")
    report.add_argument("id", type=int)
    report.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.command == "scan" and not 1 <= args.max_events <= 1000:
        parser.error("--max-events 必须在 1 至 1000 之间")
    if args.command == "list" and not 1 <= args.limit <= 100:
        parser.error("--limit 必须在 1 至 100 之间")
    if args.command == "analyze" and not 1 <= args.window_minutes <= 60:
        parser.error("--window-minutes 必须在 1 至 60 之间")
    try:
        if args.command in ('guard', 'tasks', 'models', 'ask'):
            dispatch(args)
            return 0
        if args.command == "scan" and not args.import_logs:
            sys.path.insert(0, str(ROOT / "backend"))
            read_logs(args.channels or ["Security"], args.max_events)
            return 0
        if args.command == "server":
            analyze_server_directory(args.directory, args.output)
            return 0
        _prepare_database(args.database)
        with _session() as db:
            if args.command is None:
                menu(db, args.database)
            elif args.command == "demo":
                load_demo(db, args.case)
            elif args.command == "scan":
                result = read_logs(args.channels or ["Security"], args.max_events)
                if args.import_logs and result["events"]:
                    batch_analyze(db, import_logs(db, result), collection=result)
            elif args.command == "list":
                list_records(db, args.limit)
            elif args.command == "analyze":
                analyze(db, args.id, args.window_minutes)
            elif args.command == "batch":
                batch_analyze(db, output=args.output)
            elif args.command == "report":
                show_report(db, args.id, args.output)
    except (KeyboardInterrupt, EOFError):
        print("\n已退出。")
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"操作失败：{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
