"""Read-only, local analysis of an exported Linux server log directory.

This is intentionally separate from Windows event correlation and never writes to
the source directory, a database, or a remote service.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re


LOG_FILES = (
    "ssh.journal.log", "nginx-security-access.log", "candidate-api.journal.log",
    "admin-api.journal.log", "nginx-error.log", "system-errors.journal.log",
    "kernel-warnings.journal.log", "mysql-error.log", "nginx-mysql.journal.log",
)
MAX_FILE_BYTES = 100 * 1024 * 1024
RULE_VERSION = 2
HTTP_WINDOW_SECONDS = 120
SSH_FAILURE = re.compile(r"Failed password for (?:invalid user )?(?P<account>.+?) from (?P<ip>\S+) port \d+")
SSH_SUCCESS = re.compile(r"Accepted (?P<method>\S+) for (?P<account>.+?) from (?P<ip>\S+) port \d+")
PROBE_MARKERS = ("/.env", "/.git/", "/wp-admin", "/wp-login", "/phpmyadmin",
                 "/actuator", "/server-status", "/cgi-bin/", "/etc/passwd")


def _time(value: str | None) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else None
    except (ValueError, TypeError):
        return None


def _lines(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        yield from enumerate(stream, 1)


def _json_record(line: str) -> dict | None:
    payload = line.strip()
    if not payload.startswith("{"):
        match = re.search(r"\]:\s*(\{.*)$", line)
        if match is None:
            return None
        payload = match.group(1)
    try:
        value = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _ref(name: str, line: int) -> str:
    return f"{name}:{line}"


def _host(line: str) -> str:
    """Only accept the timestamp/host/process form of exported journal text."""
    match = re.match(r"^\S+\s+(\S+)\s+[^\s:]+(?:\[\d+\])?:\s", line)
    return match[1].casefold() if match else ""


def _ip(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value)
        return None if address.is_unspecified else str(getattr(address, "ipv4_mapped", None) or address)
    except ValueError:
        return None


class SourceCoverage:
    """Account for every physical line; times include recognized timestamps only."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.files = {}
        for name in LOG_FILES:
            path = directory / name
            size = path.stat().st_size if path.is_file() else 0
            status = ("missing" if not path.is_file() else "skipped_large" if size > MAX_FILE_BYTES
                      else "empty" if not size else "read")
            self.files[name] = dict(status=status, bytes=size, lines=0, parsed=0, unparsed=0,
                                    invalid=0, duplicates=0, blank=0, missing_time=0,
                                    start=None, end=None, unparsed_examples=[], invalid_examples=[])
        self.ignored = sorted(path.name for path in directory.iterdir()
                              if path.is_file() and path.name not in (*LOG_FILES, "SHA256SUMS.txt"))

    def lines(self, name: str):
        info = self.files[name]
        if info["status"] != "read":
            return
        seen = set()
        for line_no, line in _lines(self.directory / name):
            info["lines"] += 1
            if not line.strip():
                info["blank"] += 1
                continue
            digest = hashlib.sha256(line.rstrip("\r\n").encode("utf-8")).digest()
            if digest in seen:
                info["duplicates"] += 1
                continue
            seen.add(digest)
            row = _json_record(line)
            when = _time(row.get("occurred_at")) if row else None
            when = when or _time(line.split(" ", 1)[0])
            if when:
                when = when.astimezone(timezone.utc).isoformat()
                info["start"] = min(info["start"], when) if info["start"] else when
                info["end"] = max(info["end"], when) if info["end"] else when
            else:
                info["missing_time"] += 1
            info["unparsed"] += 1
            before = info["unparsed"]
            yield line_no, line
            if info["unparsed"] == before and len(info["unparsed_examples"]) < 3:
                info["unparsed_examples"].append(_ref(name, line_no))

    def mark(self, name: str, kind: str = "parsed", line_no: int | None = None):
        info = self.files[name]
        info["unparsed"] -= 1
        info[kind] += 1
        if kind == "invalid" and len(info["invalid_examples"]) < 3:
            info["invalid_examples"].append(_ref(name, line_no))

    def summary(self):
        totals = {key: sum(info[key] for info in self.files.values())
                  for key in ("lines", "parsed", "unparsed", "invalid", "duplicates", "blank", "missing_time")}
        totals.update(discovered=sum(info["status"] != "missing" for info in self.files.values()) + len(self.ignored),
                      recognized=sum(info["status"] != "missing" for info in self.files.values()),
                      skipped_large=sum(info["status"] == "skipped_large" for info in self.files.values()),
                      ignored_files=self.ignored)
        return totals


def _http_links(request: dict, candidates: list[dict]) -> tuple[list[dict], str, bool]:
    if not request["request_id"]:
        return [], "缺少 request_id", False
    if not request["time"]:
        return [], "缺少带时区的时间", False
    matches = [item for item in candidates if item["time"]
               and abs((item["time"] - request["time"]).total_seconds()) <= HTTP_WINDOW_SECONDS
               and (not request["service"] or request["service"] == item["service"])
               and (not request["host"] or not item["host"] or request["host"] == item["host"])
               and (not request["path"] or not item["route"] or request["path"] == item["route"])
               and (not request["method"] or not item["method"] or request["method"] == item["method"])]
    if not matches:
        return [], "无匹配：需相同 ID、兼容服务/主机/请求及前后 120 秒时间窗", False
    # A reused ID must never select an arbitrary service/exception.
    if len(matches) > 1:
        return matches, "存在多个候选，待核实", False
    if not request["service"]:
        return matches, "唯一候选；网关未提供服务标识，待核实", False
    if not request["host"] or not matches[0]["host"]:
        return matches, "唯一候选；缺少主机标识，待核实", False
    return matches, "同服务、主机、ID 和时间窗匹配（不证明因果）", True


def _md(value, limit: int = 160) -> str:
    clean = re.sub(r"[\x00-\x1f\x7f-\x9f]+", " ", str(value or "")).strip()
    clean = clean.replace("`", "'").replace("|", "\\|")
    return clean[:limit] + ("…" if len(clean) > limit else "")


def _manifest(directory: Path) -> tuple[list[dict], list[str]]:
    manifest = directory / "SHA256SUMS.txt"
    if not manifest.is_file():
        return [], ["没有 SHA256SUMS.txt，无法核验文件内容是否与导出清单一致。"]
    checks, warnings = [], []
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64}) \*(.+)", line.strip())
        if not match:
            warnings.append("校验清单存在无法解析的行。")
            continue
        expected, name = match.groups()
        if Path(name).name != name or name in (".", ".."):
            warnings.append("校验清单存在非文件名路径，已跳过。")
            continue
        path = directory / name
        location = "导出目录"
        if not path.is_file() and name == "server-logs.tar.gz":
            path = directory.parent / name
            location = "上一级目录"
        if not path.is_file():
            checks.append({"file": name, "status": "missing", "location": None})
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            checks.append({"file": name, "status": "skipped_large", "location": location})
            warnings.append(f"{name} 超过单文件大小上限，未执行 SHA-256 校验。")
            continue
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        checks.append({"file": name, "status": "match" if digest.hexdigest().casefold() == expected.casefold() else "mismatch",
                       "location": location})
    if any(check["status"] == "mismatch" for check in checks):
        warnings.append("至少一个文件与 SHA-256 清单不符；分析结论需先核对文件来源。")
    if any(check["status"] == "missing" for check in checks):
        warnings.append("校验清单中有文件未找到；已继续分析当前目录中存在的日志。")
    return checks, warnings


def analyze_directory(source: str | Path) -> dict:
    directory = Path(source).expanduser().resolve()
    if not directory.is_dir():
        raise ValueError(f"找不到服务器日志目录：{directory}")
    if not any((directory / name).is_file() for name in LOG_FILES):
        raise ValueError("目录中没有可识别的 SSH、Nginx 或应用日志")
    coverage = SourceCoverage(directory)
    files = coverage.files
    checks, warnings = _manifest(directory)
    for name, info in files.items():
        if info["status"] == "skipped_large":
            warnings.append(f"{name} 超过单文件 {MAX_FILE_BYTES // (1024 * 1024)} MB 上限，已跳过；跳过行数未知，请分段导出。")

    failed, accepted, nginx_requests, app_requests, exceptions = [], [], [], [], []
    service_events, startup_errors = [], []
    ssh_sources, ssh_accounts, status_counts, app_event_types, app_errors = (Counter() for _ in range(5))
    malformed_json, unstructured_lines, probe_requests, nginx_errors = Counter(), Counter(), [], []
    operation_reasons = Counter()
    system_error_categories = Counter()

    ssh_path = directory / "ssh.journal.log"
    if ssh_path.is_file():
        for line_no, line in coverage.lines(ssh_path.name):
            when = _time(line.split(" ", 1)[0])
            match = SSH_FAILURE.search(line)
            if match:
                coverage.mark(ssh_path.name)
                item = {"time": when, "host": _host(line), "ip": match["ip"], "account": match["account"],
                        "ref": _ref(ssh_path.name, line_no)}
                failed.append(item)
                ssh_sources[item["ip"]] += 1
                ssh_accounts[item["account"]] += 1
                continue
            match = SSH_SUCCESS.search(line)
            if match:
                coverage.mark(ssh_path.name)
                accepted.append({"time": when, "host": _host(line), "ip": match["ip"], "account": match["account"],
                                 "method": match["method"], "ref": _ref(ssh_path.name, line_no)})

    nginx_path = directory / "nginx-security-access.log"
    if nginx_path.is_file():
        for line_no, line in coverage.lines(nginx_path.name):
            row = _json_record(line)
            if row is None:
                malformed_json[nginx_path.name] += 1
                coverage.mark(nginx_path.name, "invalid", line_no)
                continue
            when = _time(row.get("occurred_at")) or _time(line.split(" ", 1)[0])
            try:
                status = int(row.get("status_code"))
                if isinstance(row.get("status_code"), (bool, float)) or not 100 <= status <= 599:
                    raise ValueError("invalid HTTP status")
            except (TypeError, ValueError):
                malformed_json[nginx_path.name] += 1
                coverage.mark(nginx_path.name, "invalid", line_no)
                continue
            coverage.mark(nginx_path.name)
            path = str(row.get("path") or "").split("?", 1)[0]
            item = {"time": when, "ip": str(row.get("client_ip") or ""),
                    "service": str(row.get("service") or ""),
                    "host": str(row.get("server_host") or "").casefold(),
                    "method": str(row.get("method") or ""), "path": path, "status": status,
                    "request_id": str(row.get("request_id") or ""), "ref": _ref(nginx_path.name, line_no),
                    "duration_seconds": row.get("duration_seconds")}
            nginx_requests.append(item)
            status_counts[status] += 1
            if any(marker in path.casefold() for marker in PROBE_MARKERS):
                probe_requests.append(item)

    for name in ("candidate-api.journal.log", "admin-api.journal.log"):
        path = directory / name
        if not path.is_file():
            continue
        for line_no, line in coverage.lines(name):
            row = _json_record(line)
            if row is None:
                if line.lstrip().startswith("{") or re.search(r"\]:\s*\{", line):
                    malformed_json[name] += 1
                    coverage.mark(name, "invalid", line_no)
                else:
                    unstructured_lines[name] += 1
                    recognized = False
                    when = _time(line.split(" ", 1)[0])
                    service_match = re.search(r"\b(Stopping|Started) (ai-interview-[\w-]+\.service)\b", line)
                    if service_match:
                        recognized = True
                        service_events.append({"time": when, "action": service_match[1],
                                               "host": _host(line),
                                               "service": service_match[2], "ref": _ref(name, line_no)})
                    if "Main process exited" in line:
                        recognized = True
                        service_match = re.search(r"(ai-interview-[\w-]+\.service): Main process exited", line)
                        service_events.append({"time": when, "action": "Main process exited",
                                               "host": _host(line),
                                               "service": service_match[1] if service_match else name,
                                               "ref": _ref(name, line_no)})
                    if "Application startup complete" in line:
                        recognized = True
                        service_events.append({"time": when, "action": "Application startup complete",
                                               "host": _host(line),
                                               "service": name, "ref": _ref(name, line_no)})
                    error_match = re.search(r"pymysql\.err\.OperationalError: \((\d+),\s*'([^']+)'", line)
                    if error_match:
                        recognized = True
                        startup_errors.append({"time": when, "code": error_match[1],
                                               "message": error_match[2], "ref": _ref(name, line_no)})
                    if recognized:
                        coverage.mark(name)
                continue
            when = _time(row.get("occurred_at")) or _time(line.split(" ", 1)[0])
            event_type = str(row.get("event_type") or "")
            if event_type in ("http.request", "http.exception", "operation.failed"):
                coverage.mark(name)
            app_event_types[(name, event_type)] += 1
            item = {"time": when, "service": str(row.get("service") or ""),
                    "host": str(row.get("server_host") or _host(line)).casefold(),
                    "method": str(row.get("method") or ""),
                    "ip": str(row.get("client_ip") or ""), "route": str(row.get("route") or "").split("?", 1)[0],
                    "request_id": str(row.get("request_id") or ""), "status": row.get("status_code"),
                    "error_type": str(row.get("error_type") or ""), "ref": _ref(name, line_no)}
            if event_type == "http.request":
                app_requests.append(item)
            elif event_type == "http.exception":
                exceptions.append(item)
                app_errors[item["error_type"] or "未提供"] += 1
            elif event_type == "operation.failed":
                operation_reasons[str(row.get("reason") or "未提供")] += 1

    for name in ("nginx-error.log", "system-errors.journal.log", "kernel-warnings.journal.log",
                 "mysql-error.log", "nginx-mysql.journal.log"):
        path = directory / name
        if not path.is_file():
            continue
        for line_no, line in coverage.lines(name):
            if name == "nginx-error.log":
                category = ("请求体过大" if "client intended to send too large body" in line
                            else "上游连接中断" if "upstream" in line and ("failed" in line or "reset" in line)
                            else "其他")
                nginx_errors.append({"category": category, "ref": _ref(name, line_no)})
                if category != "其他":
                    coverage.mark(name)
            elif name == "system-errors.journal.log":
                category = ("SSH 握手中断" if "kex_exchange_identification" in line
                            else "SSH 协议版本不匹配" if "Protocol major versions differ" in line
                            else "其他系统错误")
                system_error_categories[category] += 1
                if category != "其他系统错误":
                    coverage.mark(name)

    if malformed_json:
        warnings.append("部分 JSON 或必要字段无效：" + "、".join(f"{name} {count} 行" for name, count in malformed_json.items()))
    if unstructured_lines:
        warnings.append("应用 journal 中有非 JSON 文本行，仅识别已支持的服务状态和启动错误，其余计入未识别：" + "、".join(f"{name} {count} 行" for name, count in unstructured_lines.items()))
    if files["ssh.journal.log"]["status"] == "missing" or files["nginx-security-access.log"]["status"] == "missing":
        warnings.append("SSH 或 Nginx 访问日志缺失，相关结论范围不完整。")

    failures_by_identity = defaultdict(list)
    for item in failed:
        if item["host"] and item["account"] and _ip(item["ip"]):
            failures_by_identity[(item["host"], item["account"], _ip(item["ip"]))].append(item)
    success_after_failures = []
    for item in accepted:
        prior = [attempt for attempt in failures_by_identity[(item["host"], item["account"], _ip(item["ip"]))]
                 if attempt["time"] and item["time"] and timedelta(0) < item["time"] - attempt["time"] <= timedelta(minutes=30)]
        if prior:
            prior.sort(key=lambda attempt: attempt["time"])
            success_after_failures.append({"accepted": item, "failure_count": len(prior),
                                          "first_failure": prior[0]["ref"], "failure_refs": [p["ref"] for p in prior]})

    app_by_id = defaultdict(list)
    for item in exceptions:
        if item["request_id"]:
            app_by_id[item["request_id"]].append(item)
    five_xx = [item for item in nginx_requests if 500 <= item["status"] < 600]
    for item in five_xx:
        matches, status, unique_match = _http_links(item, app_by_id[item["request_id"]])
        item["app_candidates"] = matches
        item["correlation_status"] = status
        item["app_exception"] = matches[0] if unique_match else None
    requests_by_exception = Counter(candidate["ref"] for request in five_xx for candidate in request["app_candidates"])
    for item in five_xx:
        if any(requests_by_exception[candidate["ref"]] > 1 for candidate in item["app_candidates"]):
            item["app_exception"] = None
            item["correlation_status"] = "同一异常对应多个网关请求，待核实"
    root_password = [item for item in accepted if item["account"] == "root" and item["method"] == "password"]
    nearby_root_logins = []
    for login in root_password:
        related = [event for event in service_events if event["action"] == "Stopping" and login["time"] and event["time"]
                   and login["host"] and login["host"] == event["host"]
                   and timedelta(0) < event["time"] - login["time"] <= timedelta(minutes=15)]
        if related:
            nearby_root_logins.append({"login": login, "service_events": related})

    quality = coverage.summary()
    if quality["unparsed"] or quality["invalid"]:
        warnings.append(f"未识别 {quality['unparsed']} 行、格式无效 {quality['invalid']} 行；这些内容未纳入对应规则判断。")
    if quality["missing_time"]:
        warnings.append(f"{quality['missing_time']} 条非空去重记录缺少带时区的可识别时间，无法用于时间关联。")
    if quality["duplicates"]:
        warnings.append(f"排除 {quality['duplicates']} 行完全相同的重复文本；此为保守去重，不证明每行代表独立事件。")
    if coverage.ignored:
        warnings.append("存在未支持的文件，未读取其内容：" + "、".join(coverage.ignored))
    starts = [info["start"] for info in files.values() if info["start"]]
    ends = [info["end"] for info in files.values() if info["end"]]
    ssh_excluded = sum(not (item["time"] and item["host"] and item["account"] and _ip(item["ip"]))
                       for item in failed + accepted)
    if ssh_excluded:
        warnings.append(f"{ssh_excluded} 条 SSH 认证记录缺少有效主机、账户、IP 或带时区时间；保留汇总但不参与失败后成功关联。")
    signal_count = (len(success_after_failures) + len(root_password) + len(five_xx)
                    + len(probe_requests) + len(exceptions) + len(startup_errors)
                    + sum(operation_reasons.values())
                    + sum(item["category"] != "其他" for item in nginx_errors)
                    + sum(count for category, count in system_error_categories.items() if category != "其他系统错误"))
    assessment = ("没有足够的已识别记录，无法判断" if not quality["parsed"] else
                  "发现待核查线索" if signal_count else "未发现当前规则覆盖范围内的线索")
    return {
        "rule_version": RULE_VERSION, "quality": quality, "assessment": assessment,
        "source": str(directory), "analyzed_at": datetime.now().astimezone().isoformat(),
        "files": files, "checks": checks, "warnings": warnings,
        "time_range": {"start": min(starts) if starts else None, "end": max(ends) if ends else None},
        "ssh": {"failed": len(failed), "accepted": len(accepted), "distinct_failure_ips": len(ssh_sources),
                "correlation_excluded": ssh_excluded,
                "top_failure_ips": ssh_sources.most_common(10), "top_accounts": ssh_accounts.most_common(10),
                "root_failed": ssh_accounts["root"],
                "accepted_examples": accepted[:10], "success_after_failures": success_after_failures,
                "root_password_success": len(root_password),
                "root_password_sources": sorted({item["ip"] for item in root_password})},
        "nginx": {"requests": len(nginx_requests), "status_counts": dict(status_counts), "five_xx": five_xx,
                  "probe_count": len(probe_requests), "probe_examples": probe_requests[:10],
                  "probe_status_counts": dict(Counter(item["status"] for item in probe_requests)),
                  "error_lines": len(nginx_errors), "error_categories": dict(Counter(e["category"] for e in nginx_errors)),
                  "error_examples": nginx_errors[:10]},
        "application": {"request_count": len(app_requests), "exception_count": len(exceptions),
                        "exception_types": dict(app_errors), "exception_examples": exceptions[:15],
                        "event_types": {f"{name}:{kind}": count for (name, kind), count in app_event_types.items()},
                        "operation_failed_reasons": dict(operation_reasons),
                        "service_events": service_events, "startup_errors": startup_errors,
                        "nearby_root_logins": nearby_root_logins,
                        "system_error_categories": dict(system_error_categories)},
    }


def render_report(result: dict) -> str:
    ssh, nginx, app = result["ssh"], result["nginx"], result["application"]
    lines = ["# 服务器日志离线分析", "", f"分析时间：{result['analyzed_at']}",
             f"来源目录：`{_md(result['source'], 500)}`", "方式：本地只读解析；未连接服务器，未调用模型或外部情报。",
             f"规则版本：{result['rule_version']}；结论：{result['assessment']}",
             "", "## 范围与完整性", "",
             f"可识别时间范围（UTC）：{result['time_range']['start'] or '未知'} 至 {result['time_range']['end'] or '未知'}。",
             "本报告仅覆盖导出目录中的记录，不代表服务器完整取证或已确认入侵。", "",
             *coverage_lines(result), "",
             "行数关系：读取 = 已识别 + 未识别 + 格式无效 + 重复 + 空白。缺少时间是独立统计，不重复相加。",
             "超限文件未读取，跳过行数未知；缺失文件不代表该服务一定存在。", "",
             "| 文件 | 状态 | 读取行 | 已识别 | 未识别 | 无效 | 重复 | 空白 | 缺时间 |",
             "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for name, info in result["files"].items():
        lines.append(f"| `{_md(name)}` | {info['status']} | " + " | ".join(str(info[k]) for k in
                     ("lines", "parsed", "unparsed", "invalid", "duplicates", "blank", "missing_time")) + " |")
    lines.extend(["", "各文件可识别时间范围（UTC；不推断缺失时区）："])
    for name, info in result["files"].items():
        if info["status"] != "missing":
            lines.append(f"- `{_md(name)}`：{info['start'] or '未知'} 至 {info['end'] or '未知'}。")
            examples = info["unparsed_examples"] + info["invalid_examples"]
            if examples:
                lines.append("  未识别/无效原文示例：" + "、".join(f"`{_md(ref)}`" for ref in examples))
    lines.extend(["", "SHA-256 清单校验：" + "、".join(f"`{_md(c['file'])}` {c['status']}" for c in result["checks"]) if result["checks"] else "SHA-256 清单未提供。"])
    lines.extend(f"- 范围说明：{warning}" for warning in result["warnings"])
    lines.extend(["", "## 主要发现", "",
                  f"1. SSH 日志中有 **{ssh['failed']} 条密码验证失败**，来自 {ssh['distinct_failure_ips']} 个来源 IP；"
                  f"同时记录到 {ssh['accepted']} 条成功认证。失败记录不能单独证明登录成功或入侵。",
                  f"   其中 **{ssh['root_password_success']} 条是 root 密码登录成功**，来自 {len(ssh['root_password_sources'])} 个来源 IP；需与运维授权核对。",
                  f"2. Nginx 有 **{nginx['requests']} 条请求**，其中 **{len(nginx['five_xx'])} 条 5xx**；"
                  f"应用记录 **{app['exception_count']} 条 http.exception**，其中"
                  f" **{sum(bool(item['app_exception']) for item in nginx['five_xx'])} 条与 Nginx 5xx 按服务、主机、request_id 和时间窗唯一对应**。",
                  f"3. Nginx 错误日志有 {nginx['error_lines']} 行；识别到 {nginx['probe_count']} 条常见敏感路径探测请求。"
                  "路径特征只是排查线索，不能单独确认攻击；重定向状态也不证明目标内容被读取。"])
    if ssh["success_after_failures"]:
        lines.append(f"4. 有 {len(ssh['success_after_failures'])} 条 SSH 成功认证在同主机、同账户、同来源 IP 的失败尝试后 30 分钟内出现，需优先核对会话和授权。")
    else:
        lines.append("4. 在当前导出范围内，未发现同主机、同账户、同来源 IP 在失败尝试后 30 分钟内成功认证；这不排除范围外或其他方式的访问。")
    if app["exception_types"]:
        lines.append("应用异常类型只能指向排查方向，不能单独确定数据库操作错误的具体根因。")
        if result["files"]["mysql-error.log"]["status"] == "empty":
            lines.append("本次 MySQL 错误日志为空，无法用它交叉核对这些应用异常。")
    gateway_timeouts = [item for item in nginx["five_xx"] if item["status"] == 504]
    if gateway_timeouts:
        lines.append(f"另有 {len(gateway_timeouts)} 条 504 网关超时，需与应用异常分别核查。")
    if app["startup_errors"]:
        lines.append(f"非结构化应用日志记录 {len(app['startup_errors'])} 条启动期数据库操作错误，需与 HTTP 500 分开核查。")
    lines.extend(["", "## SSH 证据", "", "失败次数最高的来源：", "", "| 来源 IP | 失败次数 |", "| --- | ---: |"])
    lines.extend(f"| `{_md(ip)}` | {count} |" for ip, count in ssh["top_failure_ips"])
    lines.append(f"\n其中 root 账户密码失败 {ssh['root_failed']} 次。")
    if ssh["accepted_examples"]:
        lines.extend(["", "成功认证记录（最多 10 条）：", "", "| 时间 | 来源 IP | 账户 | 方式 | 原文位置 |", "| --- | --- | --- | --- | --- |"])
        for item in ssh["accepted_examples"]:
            lines.append(f"| {item['time'].isoformat() if item['time'] else '未知'} | `{_md(item['ip'])}` | `{_md(item['account'])}` | {_md(item['method'])} | `{item['ref']}` |")
    if ssh["success_after_failures"]:
        lines.extend(["", f"失败后成功的同源线索（共 {len(ssh['success_after_failures'])} 条，最多展示 20 条）："])
        for item in ssh["success_after_failures"][:20]:
            success = item["accepted"]
            lines.append(f"- 主机 `{_md(success['host'])}` / 账户 `{_md(success['account'])}` / `{_md(success['ip'])}`：此前 30 分钟 {item['failure_count']} 次失败（最早 `{item['first_failure']}`），成功记录 `{success['ref']}`；仍需核对授权。")
    lines.extend(["", "## HTTP 与应用证据", "",
                  "HTTP 状态：" + "、".join(f"{code}={count}" for code, count in sorted(nginx["status_counts"].items())),
                  "应用异常类型：" + ("、".join(f"{_md(kind)}={count}" for kind, count in app["exception_types"].items()) or "未记录"),
                  "", f"5xx 共 {len(nginx['five_xx'])} 条，最多展示 50 条；HTTP 关联窗口为前后 {HTTP_WINDOW_SECONDS} 秒。",
                  "缺少服务或主机标识、同 ID 多候选仅列为待核实，不计入唯一匹配；匹配也不证明根因。",
                  "", "| 时间 | 状态 | 请求 | request_id | 耗时秒 | 来源 IP | Nginx 原文 | 应用异常对应 |", "| --- | ---: | --- | --- | ---: | --- | --- | --- |"])
    for item in nginx["five_xx"][:50]:
        matched = item["app_exception"]
        refs = "、".join(f"`{candidate['ref']}`" for candidate in item["app_candidates"][:10])
        link = f"{item['correlation_status']}；候选 {len(item['app_candidates'])} 条" + (f"：{refs}（最多列 10 条）" if refs else "")
        if matched:
            link += "；" + _md(matched["error_type"])
        lines.append(f"| {item['time'].isoformat() if item['time'] else '未知'} | {item['status']} | `{_md(item['method'])} {_md(item['path'])}` | `{_md(item['request_id'])}` | {_md(item['duration_seconds'])} | `{_md(item['ip'])}` | `{item['ref']}` | {link} |")
    if nginx["probe_examples"]:
        lines.extend(["", "敏感路径探测的 HTTP 状态：" + "、".join(f"{code}={count}" for code, count in sorted(nginx["probe_status_counts"].items())),
                      "样例（最多 10 条）："])
        lines.extend(f"- `{_md(item['method'])} {_md(item['path'])}` → {item['status']}，`{item['ref']}`" for item in nginx["probe_examples"])
    if nginx["error_categories"]:
        lines.extend(["", "Nginx 错误分类：" + "、".join(f"{kind}={count}" for kind, count in nginx["error_categories"].items())])
        lines.extend(f"- {item['category']}：`{item['ref']}`" for item in nginx["error_examples"])
    lines.extend(["", "## 服务与系统日志", ""])
    if app["startup_errors"]:
        for item in app["startup_errors"][:20]:
            lines.append(f"- {item['time'].isoformat() if item['time'] else '时间未知'}：MySQL 错误 {item['code']}，"
                         f"`{_md(item['message'])}`，原文 `{item['ref']}`。")
    if app["service_events"]:
        lines.extend(["", "服务状态时间线：", "", "| 时间 | 服务 | 状态 | 原文位置 |", "| --- | --- | --- | --- |"])
        for item in sorted(app["service_events"], key=lambda event: event["time"] or datetime.min.replace(tzinfo=timezone.utc))[:30]:
            lines.append(f"| {item['time'].isoformat() if item['time'] else '未知'} | `{_md(item['service'])}` | {_md(item['action'])} | `{item['ref']}` |")
    if app["nearby_root_logins"]:
        lines.extend(["", "时间邻近的 root 登录与服务停止记录（仅时间关联，不能证明由该会话操作）："])
        for item in app["nearby_root_logins"][:10]:
            login = item["login"]
            refs = "、".join(f"`{event['ref']}`" for event in item["service_events"])
            lines.append(f"- root 登录 `{login['ref']}`，来源 `{_md(login['ip'])}`；随后 15 分钟内服务停止 {refs}。")
    if app["system_error_categories"]:
        lines.append("\n系统错误日志分类：" + "、".join(f"{kind}={count}" for kind, count in app["system_error_categories"].items()))
    lines.extend(["", "## 建议核查", "",
                  "- 核对成功 SSH 会话的账户、登录方式、来源 IP、登录后的命令及授权记录；失败次数本身不构成入侵结论。",
                  "- 对照上表的 request_id、应用异常和数据库服务状态，确认 500 的根因；504 另查上游处理耗时。",
                  "- 核对导出时间窗、缺失日志和审计覆盖范围，再决定是否升级为安全事件。",
                  "- 原始日志保持不变；本报告不执行封禁、删除或服务变更。", ""])
    return "\n".join(lines)


def coverage_lines(result: dict) -> list[str]:
    q = result["quality"]
    return [f"文件：发现 {q['discovered']} 个日志/其他文件（不含校验清单），识别 {q['recognized']} 个，"
            f"未支持 {len(q['ignored_files'])} 个，超限跳过 {q['skipped_large']} 个。",
            f"记录：读取 {q['lines']} 行，已识别 {q['parsed']} 行，未识别 {q['unparsed']} 行，"
            f"格式无效 {q['invalid']} 行，重复 {q['duplicates']} 行，空白 {q['blank']} 行。",
            f"时间：{q['missing_time']} 条非空去重记录缺少带时区时间；各来源时间范围见报告。"]


def render_console(result: dict) -> str:
    ssh, nginx, app = result["ssh"], result["nginx"], result["application"]
    matched = sum(bool(item["app_exception"]) for item in nginx["five_xx"])
    return "\n".join([
        f"已只读分析服务器日志：{result['source']}",
        *coverage_lines(result),
        f"结论：{result['assessment']}；未识别、缺失和跳过内容均不在判断范围内。",
        f"SSH：{ssh['failed']} 次密码失败，{ssh['accepted']} 次成功认证，失败来源 {ssh['distinct_failure_ips']} 个 IP。",
        f"其中 root 密码登录成功 {ssh['root_password_success']} 次，来自 {len(ssh['root_password_sources'])} 个 IP，需核对授权。",
        f"Nginx：{nginx['requests']} 条请求，{len(nginx['five_xx'])} 条 5xx，其中 {matched} 条唯一匹配应用异常，"
        f"{sum(bool(item['app_candidates']) and not item['app_exception'] for item in nginx['five_xx'])} 条仅有待核实候选。",
        f"应用：{app['exception_count']} 条 http.exception；Nginx 错误日志 {nginx['error_lines']} 行。",
        f"启动期数据库错误 {len(app['startup_errors'])} 条；服务状态变化 {len(app['service_events'])} 条。",
        "这只是导出范围内的线索，不能单凭次数确认入侵。",
    ])
