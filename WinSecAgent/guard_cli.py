"""CLI integration for persisted monitoring tasks and evidence conversations."""
from __future__ import annotations

import getpass
import json
from pathlib import Path
import time

from guard import TaskStore, collect_export, collect_linux, collect_windows, demo_events, run_task
from guard_models import Profiles, ask, context, is_loopback, validate


def resources(database):
    base = Path(database).with_suffix('.guard')
    return TaskStore(base / 'tasks.db'), Profiles(base / 'models.json')


def show(task):
    from cli import _heading, _note, _wrap
    _heading(f"防护任务 {task['id']}", '合成演示数据 · 模拟处置' if task['demo'] else '真实日志 · 模拟处置')
    _note('来源', task['source'])
    _note('状态', task['status'])
    if task.get('error'):
        _note('失败原因', task['error'])
    coverage = task.get('coverage', {})
    if coverage:
        _note('数据范围', f"输入 {coverage['input']}，有效登录记录 {coverage['retained']}，"
              f"排除/不支持 {coverage['excluded']}，重复 {coverage['duplicates']}，冲突 {coverage['conflicts']}")
        _note('日志时间 UTC', f"{task['time_range']['start']} → {task['time_range']['end']}")
    for stage in task['stages']:
        _note('阶段', f"{stage['stage']} → {stage['status']}")
    for warning in task.get('warnings', []):
        _note('范围说明', warning)
    if not task['findings']:
        _note('规则结果', '未发现规则覆盖范围内的异常线索；不能据此确认安全')
    for finding in task['findings']:
        _note('线索', finding['title'])
        _note('依据', f"{finding['host']} / {finding['account']} / {finding['ip']}，5 分钟内 {finding['failure_count']} 次失败")
        _note('证据', ', '.join(finding['refs'][:12]) + (' …' if len(finding['refs']) > 12 else ''))
    if task.get('model_answer'):
        _note('模型解释（需核实）', task['model_answer'])
    if task.get('model_error'):
        _note('模型失败', task['model_error'])
    for action in task['actions']:
        _note('模拟方案', f"{action['platform']} / {action['target']} / IP {action['ip']} / {action['ttl_seconds']} 秒")
        _note('处置状态', f"{action['status']}；{action['reason']}")
        if action.get('previous_task'):
            _note('相同证据已处理', action['previous_task'])
        _note('验证状态', '未执行真实封禁，也未验证防护效果')
        if action.get('simulation_checks'):
            _note('模拟器自检', '规则创建、到期失效和撤销验证通过' if action['simulation_verified'] else '模拟器自检失败')
        for step in action['verification_plan']:
            _wrap(step, '    · ')
        _note('恢复计划', action['rollback_plan'])


def configure(profiles):
    from cli import _heading, _note
    _heading('模型配置', 'API Key 仅存于当前进程；持久配置保存环境变量名，不保存密钥')
    data = profiles.load()
    for name, profile in data['profiles'].items():
        _note('*' if name == data['active'] else ' ', f"{name} / {profile['kind']} / {profile['model']} / {profile['base_url']}")
    choice = input('  1 新增/更新并启用  2 切换现有配置  0 返回 > ').strip()
    if choice == '2':
        profiles.activate(input('  配置名称：').strip())
        return
    if choice != '1':
        return
    name = input('  配置名称（例如 local 或 api）：').strip()
    kind = {'1': 'ollama', '2': 'openai'}.get(input('  1 Ollama  2 OpenAI 兼容接口（本地或 API）> ').strip())
    if not kind:
        raise ValueError('请选择 1 或 2')
    default = 'http://127.0.0.1:11434' if kind == 'ollama' else 'http://127.0.0.1:8000/v1'
    base = input(f'  服务地址 [{default}]：').strip() or default
    model = input('  模型名称（与服务端一致）：').strip()
    env = input('  API Key 环境变量名（无密钥可回车）：').strip()
    profile = validate(dict(kind=kind, base_url=base, model=model, key_env=env))
    key = getpass.getpass('  本次会话 API Key（隐藏输入；无/已设环境变量可回车）：') if kind == 'openai' else ''
    profiles.put(name, profile, key)
    _note('已启用', f'{name}；实际连接将在提问时验证')
    if key:
        _note('密钥', '本次进程退出后清除；下次可重新输入，或设置所选环境变量')


def consent_for(profiles, task=None):
    from cli import _note
    _, profile = profiles.active()
    if is_loopback(profile):
        return True
    _note('发送目的地', f"{profile['base_url']} / {profile['model']}")
    _note('发送内容', '任务摘要、最多 30 条证据片段和最近对话；可能含账户、主机名、IP 和业务数据')
    if task:
        preview = context(task)
        _note('本次证据条数', len(preview['evidence']))
        if input('  先查看发送的证据 JSON？输入 y 查看：').strip().lower() == 'y':
            _note('发送证据预览', json.dumps(preview, ensure_ascii=False))
    return input('  允许本次提问发送到此地址？输入 y 确认：').strip().lower() == 'y'


def chat(store, profiles, task_id):
    from cli import _heading, _note
    task = store.get(task_id)
    _heading(f'围绕任务 {task_id} 追问', '回答单独保存；不会改写规则结论或执行命令。输入 /back 返回')
    for item in store.history(task_id, 4):
        _note('你' if item['role'] == 'user' else '模型', item['content'])
    while True:
        question = input('  你 > ').strip()
        if question in ('/back', '退出', ''):
            return
        if not consent_for(profiles, task):
            _note('已取消', '未发送请求')
            continue
        _note('模型', ask(store, profiles, task_id, question, consent=True))


def task_menu(store, profiles):
    from cli import _heading, _note
    _heading('防护任务历史', '退出程序后仍可查看；采集失败也会留档')
    for task in store.recent():
        _note(task['id'], f"{task['created']} | {task['source']} | {task['status']} | 线索 {len(task['findings'])}")
    task_id = input('  输入任务 ID 查看详情（回车返回）：').strip()
    if not task_id:
        return
    task = store.get(task_id)
    show(task)
    choice = input('  1 向模型提问  2 查看证据  3 导出完整 JSON  0 返回 > ').strip()
    if choice == '1':
        chat(store, profiles, task_id)
    elif choice == '2':
        for row in task.get('events', [])[:100]:
            _note(row['ref'], row['raw'])
            if row.get('raw_truncated'):
                _note('原文截断', f"仅保存前 4096 字符；完整记录 SHA256：{row['raw_sha256']}")
        _note('证据展示范围', '最多显示 100 条；完整快照可导出')
    elif choice == '3':
        raw = input('  导出文件路径：').strip().strip('"').strip("'")
        if not raw:
            return
        output = Path(raw).expanduser()
        if output.exists():
            raise ValueError('目标已存在；请换一个文件名以避免覆盖')
        # No implicit parent creation: a wrong directory should be visible.
        with output.open('x', encoding='utf-8') as stream:
            json.dump(dict(task=task, conversation=store.history(task_id, 1000)), stream, ensure_ascii=False, indent=2)
        _note('已导出', output)


def wizard(store, profiles):
    import platform
    from cli import _heading, _note
    system = platform.system().lower()
    if system not in ('windows', 'linux'):
        raise ValueError('本机版本只支持 Windows 或 Linux')
    _heading(f'{system.title()} 本机采集与模拟防护', '日志在当前主机读取和分析；所有处置仅模拟')
    print(f'  1 读取本机 {system.title()} 日志（默认）\n  2 本机导出目录\n  3 本平台合成演示')
    choice = input('  来源 [1-3] > ').strip() or '1'
    if choice == '1':
        source = f'{system}-local'
        collector, demo = (collect_windows if system == 'windows' else collect_linux), False
    elif choice == '2':
        directory = Path(input('  导出目录：').strip().strip('"').strip("'")).resolve()
        source, collector, demo = f'export:{directory}', lambda: collect_export(directory), False
    elif choice == '3':
        source, collector, demo = f'demo:{system}', lambda: demo_events(system), True
    else:
        raise ValueError('请选择 1–3')
    protected = input('  管理 IP / CIDR 保护名单（逗号分隔；可回车）：').strip()
    protected = [value.strip() for value in protected.split(',') if value.strip()]
    from guard import plan
    plan([], protected)  # Validate before collection.
    use_model = input('  本轮调用已配置模型解释证据？输入 y 启用：').strip().lower() == 'y'
    analyst = None
    if use_model:
        profiles.active()  # Fail before collecting if not configured.
        def analyst(task_id):
            if not consent_for(profiles, store.get(task_id)):
                raise ValueError('用户未同意发送证据，模型步骤已取消')
            return ask(store, profiles, task_id, '解释异常线索并引用证据，给出下一步核查方法。', consent=True)
    task = run_task(store, source, collector, protected=protected, demo=demo, analyst=analyst)
    show(task)
    _note('查看或追问', f"进入防护任务历史 → {task['id']}")


def add_commands(commands):
    guard = commands.add_parser('guard', help='真实采集或合成演示，所有防护动作仅模拟')
    guard.add_argument('source', choices=['windows', 'linux', 'export', 'demo-linux', 'demo-windows'])
    guard.add_argument('--ssh', help='已有 SSH 别名或 user@主机；省略则读本机 Linux')
    guard.add_argument('--directory', type=Path, help='导出目录，包含 ssh.journal.log')
    guard.add_argument('--minutes', type=int, default=15)
    guard.add_argument('--limit', type=int, default=1000)
    guard.add_argument('--protect', action='append', default=[], help='受保护管理 IP/CIDR，可重复')
    guard.add_argument('--ttl', type=int, default=600, help='模拟封禁秒数 60–3600')
    guard.add_argument('--cycles', type=int, default=1, help='轮数；0 持续运行，Ctrl+C 停止')
    guard.add_argument('--interval', type=int, default=60, help='轮询间隔秒数，至少 10 秒')
    guard.add_argument('--with-model', action='store_true', help='每轮调用所选模型解释证据')
    guard.add_argument('--allow-remote-model', action='store_true', help='明确允许本次运行将证据和对话发送到配置的非本机模型')
    tasks = commands.add_parser('tasks', help='查看防护任务历史或详情')
    tasks.add_argument('id', nargs='?')
    commands.add_parser('models', help='交互配置/选择本地或 API 模型')
    chat_command = commands.add_parser('ask', help='围绕防护任务连续追问')
    chat_command.add_argument('id')


def dispatch(args):
    from cli import _note
    store, profiles = resources(args.database)
    if args.command == 'models':
        configure(profiles)
    elif args.command == 'ask':
        chat(store, profiles, args.id)
    elif args.command == 'tasks':
        if args.id:
            show(store.get(args.id))
        else:
            for task in store.recent():
                _note(task['id'], f"{task['source']} | {task['status']} | {task['created']}")
    elif args.command == 'guard':
        from guard import plan, ssh_target
        if not (0 <= args.cycles <= 10000 and 10 <= args.interval <= 3600
                and 1 <= args.minutes <= 1440 and 1 <= args.limit <= 5000):
            raise ValueError('轮数 0–10000，间隔 10–3600 秒，时间 1–1440 分钟，条数 1–5000')
        plan([], args.protect, args.ttl)
        if args.ssh and args.source != 'linux':
            raise ValueError('--ssh 仅适用于 linux')
        if args.directory and args.source != 'export':
            raise ValueError('--directory 仅适用于 export')
        source = args.source
        if source.startswith('demo-'):
            collector = lambda: demo_events(source.removeprefix('demo-'))
        elif source == 'windows':
            collector = lambda: collect_windows(args.limit)
        elif source == 'linux':
            if args.ssh:
                ssh_target(args.ssh)
            collector = lambda: collect_linux(args.ssh, args.minutes, args.limit)
        else:
            if not args.directory:
                raise ValueError('export 需要 --directory')
            collector = lambda: collect_export(args.directory)
        analyst = None
        if args.with_model:
            _, profile = profiles.active()
            if not is_loopback(profile) and not args.allow_remote_model:
                raise ValueError('非本机模型需要 --allow-remote-model；证据和对话将发送到所选地址')
            _note('模型目的地', f"{profile['base_url']} / {profile['model']}")
            analyst = lambda task_id: ask(store, profiles, task_id, '解释异常线索并引用证据，给出下一步核查方法。', consent=True)
        count = 0
        source_name = source + ':' + (args.ssh or str(args.directory.resolve() if args.directory else 'local'))
        while args.cycles == 0 or count < args.cycles:
            task = run_task(store, source_name, collector, args.protect, args.ttl,
                            source.startswith('demo-'), analyst)
            show(task)
            count += 1
            if args.cycles == 0 or count < args.cycles:
                _note('等待下一轮', f'{args.interval} 秒；Ctrl+C 停止。任务已保存')
                time.sleep(args.interval)
