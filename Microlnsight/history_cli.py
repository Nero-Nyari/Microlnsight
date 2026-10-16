"""Interactive archived SSH analysis, shared by plain CLI and the workbench."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from types import SimpleNamespace
import uuid

import history_analysis as engine
from terminal_ui import Cancelled, busy, cancellable, choice, field, model_answer, section

ROOT = Path(__file__).resolve().parent


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def archive_path(value):
    path = Path(value.strip().strip('"').strip("'")).expanduser().resolve()
    if not path.is_dir() or not any(path.glob('*.jsonl')):
        raise ValueError('请选择含 .jsonl 采集归档的 raw 目录；不是 ssh.journal.log 导出目录')
    return path


def sources(data_dir, install_root=ROOT):
    """Only read local source labels/paths, never credentials or remote systems."""
    registry = Path(data_dir) / 'history-sources.json'
    entries = read(registry) if registry.exists() else []
    collector = Path(install_root).parent / 'collector'
    if (collector / 'raw').is_dir():
        label = '采集器 SSH 归档'
        if (collector / 'config.json').is_file():
            try:
                label = str(read(collector / 'config.json').get('source_label') or label)
            except (ValueError, OSError):
                pass
        entries = [{'label': label, 'raw': str((collector / 'raw').resolve())}, *entries]
    unique = {}
    for item in entries:
        unique.setdefault(str(Path(item['raw']).resolve()), item)
    return list(unique.values())


def select_source(data_dir):
    from cli import _note
    entries = sources(data_dir)
    for index, item in enumerate(entries, 1):
        _note(str(index), f"{item['label']} · {item['raw']}")
    _note('a', '添加本地已有 SSH 归档目录')
    selected = choice('选择服务器归档（序号；0 返回）', tuple(str(i) for i in range(1, len(entries) + 1)) + ('a',), '1' if entries else 'a')
    if selected != 'a':
        item = entries[int(selected) - 1]
        return item['label'], archive_path(item['raw'])
    raw = field('归档 raw 目录', validate=archive_path)
    label = field('服务器名称或来源标签（仅用于显示）')
    registry = Path(data_dir) / 'history-sources.json'
    registry.parent.mkdir(parents=True, exist_ok=True)
    entries = read(registry) if registry.exists() else []
    engine.save(registry, [e for e in entries if e['raw'] != str(raw)] + [{'label': label, 'raw': str(raw)}])
    return label, raw


def offset(value):
    if not re.fullmatch(r'[+-](?:0\d|1[0-4]):[0-5]\d', value):
        raise ValueError('填写时区偏移，例如 +08:00 或 +00:00')
    if value[1:3] == '14' and value[4:] != '00':
        raise ValueError('时区偏移不能超过 14 小时')
    return datetime.fromisoformat('2000-01-01T00:00:00' + value).tzinfo


def minute(value):
    try:
        return datetime.strptime(value, '%Y-%m-%d %H:%M')
    except ValueError:
        raise ValueError('填写 YYYY-MM-DD HH:MM，例如 2026-10-16 16:35') from None


def interval(start, end, zone):
    first, last = minute(start).replace(tzinfo=offset(zone)), minute(end).replace(tzinfo=offset(zone))
    if last < first:
        raise ValueError('结束时间不能早于开始时间')
    return first.isoformat(), (last + timedelta(minutes=1)).isoformat()


def model_target(profiles, output):
    binding = output / 'destination.json'
    if binding.exists():
        saved = read(binding)
        return saved['url'], saved['model']
    _, profile = profiles.active()
    if profile['kind'] != 'ollama':
        raise ValueError('历史分批分析使用 Ollama；请在 /models 选择本地 Ollama 模型后重试')
    return profile['base_url'], profile['model']


def overview(output):
    from cli import _heading, _note
    manifest = read(output / 'manifest.json')
    _heading('历史报告分析', manifest['source'])
    _note('请求范围', f"{manifest['requested_start_inclusive']} 至 {manifest['requested_end_exclusive']}（结束边界不包含）")
    _note('实际归档范围', f"{manifest['actual_first']} 至 {manifest['actual_last']}")
    _note('待分析日志', f"{manifest['record_count']} 条 · {manifest['batch_count']} 批 · 完整消息分批送入模型")
    _note('归档检查', f"去重 {manifest['audit']['duplicates_removed']} 条；无效记录 {len(manifest['audit']['invalid_records'])} 条")
    _note('范围限制', '仅覆盖已归档的 SSH 消息；最早/最晚时间不能证明中间连续采集，不包含应用、数据库日志')
    status_file = output / 'status.json'
    if status_file.exists():
        state = read(status_file)
        _note('分析进度', f"{state['accepted_records']}/{state['total_records']} 条，{state['accepted_batches']}/{state['total_batches']} 批；" + ('已完成' if state['completed'] else '尚未完成，可续跑'))
    else:
        _note('分析进度', '已准备，尚未完成模型分析')
    if (output / 'destination.json').exists():
        target = read(output / 'destination.json')
        _note('报告绑定模型', f"{target['url']} / {target['model']}")
    _note('保存位置', output)
    return manifest


def execute(output, profiles, checkpoint):
    from cli import _note
    url, model = model_target(profiles, output)
    _note('本次模型目的地', f'{url} / {model}')
    _note('发送范围', '各批完整 SSH 消息、时间、主机、进程和 PID，可能包含账户、IP、密钥指纹。已完成批次跳过，不切换模型。')
    _note('重试与取消', '每批最多两次；覆盖或长度失败时拆为两小批，各最多两次。Ctrl+C 在当前请求结束后停止，已保存结果可续跑。')
    if choice('1 开始 / 续跑分析  2 仅保留准备结果  0 返回', ('1', '2'), '2') != '1':
        return

    def progress(index, total, state):
        if state is None:
            _note('处理中', f'批次 {index}/{total} · 等待模型或读取已保存回答')
        else:
            _note('已保存', f"{state['accepted_records']}/{state['total_records']} 条；成功 {state['accepted_batches']}/{total} 批")
    try:
        result = engine.run(SimpleNamespace(output=output, model_url=url, model=model, allow_model_send=True),
                            checkpoint=checkpoint, progress=progress)
        _note('分析完成' if result == 0 else '部分批次未完成', '回答已保存；可查看报告，或重新选择续跑重试失败批次')
    finally:
        _note('报告目录', output)


def new_report(data_dir, profiles, checkpoint):
    from cli import _note
    label, raw = select_source(data_dir)
    local = datetime.now().astimezone()
    default_zone = local.strftime('%z')
    zone = field('日志时间的时区偏移', default_zone[:3] + ':' + default_zone[3:], validate=lambda v: (offset(v), v)[1])
    now = datetime.now(offset(zone))
    start = field('开始时间 YYYY-MM-DD HH:MM', (now - timedelta(days=1)).strftime('%Y-%m-%d 00:00'), validate=lambda v: (minute(v), v)[1])
    def check_end(value):
        interval(start, value, zone)
        return value
    end = field('结束时间 YYYY-MM-DD HH:MM（包含这一整分钟）', now.strftime('%Y-%m-%d %H:%M'), validate=check_end)
    first, last = interval(start, end, zone)
    checkpoint()
    parent = Path(data_dir) / 'history-analysis'
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = parent / (now.strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:8])
    with busy('筛选归档并保存证据快照'):
        engine.prepare(SimpleNamespace(raw=raw, output=output, source=label, start=first, end=last))
    overview(output)
    _note('说明', '准备阶段没有调用模型；日期范围外的日志不会发送')
    execute(output, profiles, checkpoint)
    return output


def reports(data_dir, install_root=ROOT):
    found = {}
    for parent in (Path(data_dir) / 'history-analysis', Path(install_root).parent / 'history-analysis'):
        for path in parent.glob('*/manifest.json'):
            try:
                manifest = read(path)
                if manifest.get('schema') != 1 or not manifest.get('batch_count'):
                    continue
                found[str(path.parent.resolve())] = (path.parent, manifest)
            except (ValueError, OSError):
                continue
    return sorted(found.values(), key=lambda item: item[0].name, reverse=True)


def select_report(data_dir):
    from cli import _note
    items = reports(data_dir)
    if not items:
        _note('暂无报告', '选择“新建历史分析”准备归档')
        return None
    page = 0
    while True:
        chunk = items[page * 10:page * 10 + 10]
        for i, (path, manifest) in enumerate(chunk, 1):
            _note(str(i), f"{manifest['source']} · {manifest['actual_first']} → {manifest['actual_last']} · {manifest['record_count']} 条 · {path.name}")
        selected = choice(f'报告序号（第 {page + 1}/{(len(items) + 9) // 10} 页；n 下一页，p 上一页）', tuple(str(i) for i in range(1, len(chunk) + 1)) + ('n', 'p'))
        if selected == 'n':
            page = min((len(items) - 1) // 10, page + 1)
        elif selected == 'p':
            page = max(0, page - 1)
        else:
            return chunk[int(selected) - 1][0]


def show_answer(answer, title, rows):
    lines = [answer['summary'], '']
    for key, label in (('observations', '观察'), ('concerns', '待核实线索')):
        for item in answer[key]:
            lines += [f"- {label}：{item['text']}（{', '.join(item['refs'])}）",
                      '  引用日志时间：' + engine.evidence_times(item['refs'], rows)]
    lines += ['', '限制：' + answer['limitations']]
    model_answer('\n'.join(lines), title)


def batch_detail(output, checkpoint):
    from cli import _note
    manifest = read(output / 'manifest.json')
    def batch_number(value):
        if not value.isdigit() or not 1 <= int(value) <= manifest['batch_count']:
            raise ValueError(f"输入 1–{manifest['batch_count']} 的批次序号")
        return int(value)
    index = field('查看批次序号', '1', validate=batch_number)
    while True:
        rows = read(output / 'inputs' / f'{index:04}.json')
        result_file = output / 'results' / f'{index:04}.json'
        result = read(result_file) if result_file.exists() else {}
        section(f"批次 {index}/{manifest['batch_count']} · {rows[0]['time']} → {rows[-1]['time']} · {len(rows)} 条")
        if result.get('status') == 'accepted':
            engine.validate_saved(result, rows)
            show_answer(result['answer'], '本地模型分析（需核实）', rows)
        else:
            _note('尚未完成', '本批没有通过检查的完整回答，请返回报告菜单开始或续跑')
        action = choice('n 下一批  p 上一批  e 本批原文  a 问本地模型  h 查看本批追问  0 返回', ('n', 'p', 'e', 'a', 'h'))
        if action == 'n':
            index = min(manifest['batch_count'], index + 1)
        elif action == 'p':
            index = max(1, index - 1)
        elif action == 'e':
            for row in rows:
                _note(row['ref'] + ' · ' + row['time'], row['message'])
        elif action == 'a':
            question = field('关于本批证据的问题', validate=check_question)
            if not (output / 'destination.json').exists():
                raise ValueError('请先返回报告菜单开始分析，绑定本地模型')
            target = read(output / 'destination.json')
            _note('发送范围', f"仅发送本批 {len(rows)} 条完整证据和本次问题；不发送其他批次或历史对话。")
            _note('模型目的地', f"{target['url']} / {target['model']}")
            if choice('1 发送本次问题  2 取消', ('1', '2'), '2') != '1':
                continue
            checkpoint()
            # Reject changed evidence before sending it.
            all_rows = read(output / 'evidence.json')
            if engine.digest(all_rows) != manifest['evidence_sha256'] or rows != engine.batches(all_rows)[index - 1]:
                raise ValueError('证据快照发生变化，请重新准备报告')
            with busy('等待本地模型回答'):
                answer, metadata = engine.request_model(target['url'], target['model'], rows, question=question)
                engine.validate_reply(answer, rows)
            folder = output / 'questions'
            folder.mkdir(exist_ok=True, mode=0o700)
            engine.save(folder / (uuid.uuid4().hex + '.json'), dict(batch=index, question=question, answer=answer,
                        metadata=metadata, destination=target, created=datetime.now(timezone.utc).isoformat()))
            show_answer(answer, '本地模型回答（仅针对本批，需核实）', rows)
        elif action == 'h':
            saved = [read(path) for path in (output / 'questions').glob('*.json')]
            selected = sorted((item for item in saved if item['batch'] == index), key=lambda item: item['created'])
            if not selected:
                _note('暂无追问', '本批还没有保存的模型追问')
            for item in selected:
                _note('问题 · ' + item['created'], item['question'])
                show_answer(item['answer'], '已保存的本地模型回答（需核实）', rows)


def check_question(value):
    if len(value) > 1500:
        raise ValueError('问题请控制在 1500 字以内')
    return value


@cancellable
def report_menu(output, profiles, checkpoint):
    from cli import _note
    while True:
        manifest = overview(output)
        action = choice('1 查看分批报告与追问  2 开始 / 续跑  3 导出完整报告  4 日志统计  0 返回', ('1', '2', '3', '4'))
        try:
            if action == '1':
                batch_detail(output, checkpoint)
            elif action == '2':
                execute(output, profiles, checkpoint)
            elif action == '3':
                report = output / 'report.md'
                if not report.exists():
                    _note('暂无模型报告', '请先开始分析；证据快照已经保存在报告目录')
                    continue
                destination = Path(field('导出 .md 文件完整路径（目标必须不存在）')).expanduser()
                text = engine.saved_report(output)
                with destination.open('x', encoding='utf-8') as stream:
                    stream.write(text)
                _note('已导出', destination)
            else:
                model_answer('```json\n' + json.dumps(manifest['statistics'], ensure_ascii=False, indent=2) + '\n```', '本地程序统计（不是模型推测）')
        except Cancelled:
            checkpoint()
            _note('已返回', '返回报告菜单')


@cancellable
def menu(data_dir, profiles, *, checkpoint=lambda: None):
    from cli import _heading
    while True:
        checkpoint()
        _heading('历史报告分析', '读取本机保存的公网服务器 SSH 归档 · 本地模型分批分析')
        action = choice('1 新建历史分析  2 查看报告 / 续跑  0 返回', ('1', '2'))
        output = new_report(data_dir, profiles, checkpoint) if action == '1' else select_report(data_dir)
        if output:
            report_menu(output, profiles, checkpoint)
