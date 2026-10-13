"""CLI integration for persisted monitoring tasks and evidence conversations."""
from __future__ import annotations

import json
import re
from pathlib import Path
import time

from guard import TaskStore, collect_export, collect_linux, collect_windows, demo_events, run_task
from guard_models import Profiles, ask, context, deepseek, discover, is_loopback, validate
from terminal_ui import Cancelled, cancellable, choice, field, read_line

STATES = {'completed_simulation': '模拟分析完成', 'collecting': '采集中', 'analyzing': '分析中',
          'failed': '失败', 'interrupted': '已中断', 'complete': '完成', 'not_requested': '未启用',
          'simulated': '已模拟', 'simulation_only': '仅模拟验证', 'protected_skipped': '保护名单内，已跳过',
          'duplicate_skipped': '相同证据已处理，已跳过'}


def resources(database):
    base = Path(database).with_suffix('.guard')
    return TaskStore(base / 'tasks.db'), Profiles(base / 'models.json')


def show(task):
    from cli import _heading, _note, _wrap
    _heading(f"防护任务 {task['id']}", '合成演示数据 · 模拟处置' if task['demo'] else '真实日志 · 模拟处置')
    _note('来源', task['source'])
    _note('状态', STATES.get(task['status'], task['status']))
    if task.get('error'):
        _note('失败原因', task['error'])
    coverage = task.get('coverage', {})
    if coverage:
        _note('数据范围', f"输入 {coverage['input']}，有效登录记录 {coverage['retained']}，"
              f"排除/不支持 {coverage['excluded']}，重复 {coverage['duplicates']}，冲突 {coverage['conflicts']}")
        _note('日志时间 UTC', f"{task['time_range']['start']} → {task['time_range']['end']}")
    for stage in task['stages']:
        label = {'collect': '日志采集', 'rules': '规则分析', 'model': '模型解释',
                 'policy': '防护策略', 'execute': '模拟执行', 'verify': '模拟验证'}.get(stage['stage'], stage['stage'])
        _note(label, STATES.get(stage['status'], stage['status']))
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
    show_diagnostic(task)
    for action in task['actions']:
        _note('模拟方案', f"{action['platform']} / {action['target']} / IP {action['ip']} / {action['ttl_seconds']} 秒")
        _note('处置状态', f"{STATES.get(action['status'], action['status'])}；{action['reason']}")
        if action.get('previous_task'):
            _note('相同证据已处理', action['previous_task'])
        _note('验证状态', '未执行真实封禁，也未验证防护效果')
        if action.get('simulation_checks'):
            _note('模拟器自检', '规则创建、到期失效和撤销验证通过' if action['simulation_verified'] else '模拟器自检失败')
        for step in action['verification_plan']:
            _wrap(step, '    · ')
        _note('恢复计划', action['rollback_plan'])


@cancellable
def model_parameters(profiles):
    from cli import _heading, _note
    name, current = profiles.active()
    profile = dict(current)
    _heading('模型参数', '0 取消 · 修改后用于下一次请求 · 提高额度可能增加耗时与费用')
    if deepseek(profile):
        selection = choice('1 普通回答（关闭思考）  2 深度思考', ('1', '2'),
                           '2' if profile['thinking'] == 'enabled' else '1')
        profile['thinking'] = 'enabled' if selection == '2' else 'disabled'
    def integer(name):
        def check(value):
            try:
                number = int(value)
            except ValueError:
                raise ValueError('请填写整数') from None
            return validate({**profile, name: number})[name]
        return check
    default_tokens = current['max_tokens']
    if profile['thinking'] == 'enabled' and current['thinking'] != 'enabled':
        default_tokens = max(default_tokens, 16384)
    profile['max_tokens'] = field('输出额度 tokens（256–65536）', str(default_tokens), validate=integer('max_tokens'))
    profile['timeout_seconds'] = field('连接后读取等待上限，秒（10–600）', str(current['timeout_seconds']), validate=integer('timeout_seconds'))
    _note('待保存', f"{name} / 思考 {profile['thinking']} / 输出额度 {profile['max_tokens']} / 等待 {profile['timeout_seconds']} 秒")
    choice('1 保存参数  0 取消', ('1',), '1')
    profiles.put(name, profile, profiles.session_keys.get(name, ''))
    _note('参数已保存', '下一次提问生效；未发送模型请求')


def show_diagnostic(task):
    from cli import _note
    diagnostic = task.get('last_model_diagnostic') or task.get('model_diagnostic')
    if not diagnostic:
        return
    labels = {'code': '错误类别', 'http_status': 'HTTP 状态', 'finish_reason': '结束原因',
              'has_reasoning': '包含思考内容', 'answer_chars': '答案字符数', 'prompt_tokens': '输入 tokens',
              'completion_tokens': '输出 tokens', 'reasoning_tokens': '思考 tokens', 'total_tokens': '总 tokens'}
    for name, label in labels.items():
        if name in diagnostic:
            _note(label, diagnostic[name])


@cancellable
def configure(profiles):
    from cli import _heading, _note
    _heading('模型配置', '回车采用默认值 · 任意一步输入 0 或 Ctrl+C 返回 · 密钥不会写入配置文件')
    data = profiles.load()
    names = list(data['profiles'])
    for index, name in enumerate(names, 1):
        profile = data['profiles'][name]
        _note(str(index), f"{name} / {profile['model']}" + ('（使用中）' if name == data['active'] else ''))
    operation = choice('1 添加配置  2 切换已有配置  3 调整当前模型参数  0 返回', ('1', '2', '3'), '1') if names else '1'
    if operation == '3':
        model_parameters(profiles)
        return
    if operation == '2':
        selected = choice('选择配置序号', tuple(str(i) for i in range(1, len(names) + 1)))
        name = names[int(selected) - 1]
        profiles.activate(name)
        _note('已切换', name)
        return
    _note('第 1 步 / 3', '选择模型服务')
    print('  1 本地 Ollama\n  2 DeepSeek API\n  3 其他 OpenAI 兼容服务（本地或云端）\n  0 返回')
    service = choice('服务序号', ('1', '2', '3'))
    kind, default_base, default_name = {
        '1': ('ollama', 'http://127.0.0.1:11434', 'ollama'),
        '2': ('openai', 'https://api.deepseek.com', 'deepseek'),
        '3': ('openai', 'http://127.0.0.1:8000/v1', 'custom'),
    }[service]
    def check_base(value):
        return validate(dict(kind=kind, base_url=value, model='pending'))['base_url']
    base = field('服务地址（回车使用默认地址）', default_base, validate=check_base)
    profile = dict(kind=kind, base_url=base, model='', key_env='')
    key = ''
    if kind == 'openai':
        mode = choice('密钥：1 隐藏输入（仅本次）  2 环境变量  3 无密钥', ('1', '2', '3'), '1')
        if mode == '1':
            key = field('粘贴 API Key（输入不显示，0 返回）', secret=True)
        elif mode == '2':
            def check_env(value):
                return validate({**profile, 'model': 'pending', 'key_env': value})['key_env']
            profile['key_env'] = field('已设置的环境变量名', validate=check_env)
            key = profiles.key('', profile)
            if not key:
                _note('提示', '此环境变量当前为空；提问前会提示补充密钥')
    _note('第 2 步 / 3', '选择服务中的模型；获取列表只发送认证信息，不发送日志')
    while True:
        mode = choice('1 获取模型列表并选择  2 手动填写模型名称', ('1', '2'), '1')
        if mode == '2':
            profile['model'] = field('模型名称（与服务端一致）')
            break
        try:
            _note('正在连接', base)
            models = discover(profile, key)
        except RuntimeError as exc:
            _note('未取得模型列表', exc)
            continue
        for index, model in enumerate(models, 1):
            _note(str(index), model)
        selected = choice('模型序号', tuple(str(i) for i in range(1, len(models) + 1)))
        profile['model'] = models[int(selected) - 1]
        _note('连接结果', '模型列表读取成功；实际回答将在提问时验证')
        break
    _note('第 3 步 / 3', '检查并保存配置')
    def check_name(value):
        if not re.fullmatch(r'[\w-]{1,40}', value):
            raise ValueError('这是显示名称，请使用 1–40 个字母、数字、中文或下划线/短横线；不要填网址')
        return value
    name = field('显示名称（不是服务地址）', default_name, validate=check_name)
    _note('服务', f"{kind} / {base}")
    _note('模型', profile['model'])
    settings = validate(profile)
    _note('回答设置', f"输出上限 {settings['max_tokens']} tokens；" + ('DeepSeek 思考关闭，可在参数菜单开启' if deepseek(profile) else '使用服务默认思考行为'))
    _note('密钥', f"环境变量 {profile['key_env']}" if profile['key_env'] else '本次会话已输入' if key else '未设置')
    if name in data['profiles']:
        _note('已有同名配置', f'保存将替换 {name}，输入 0 取消可保留原配置')
    choice('1 保存并启用  0 取消', ('1',), '1')
    profiles.put(name, profile, '' if profile['key_env'] else key)
    _note('已启用', name)
    if key and not profile['key_env']:
        _note('密钥', '本次进程退出后清除；下次可重新输入，或设置所选环境变量')


def consent_for(profiles, task=None, session=False):
    from cli import _note
    _, profile = profiles.active()
    if is_loopback(profile):
        return True
    _note('发送目的地', f"{profile['base_url']} / {profile['model']}")
    _note('发送内容', '任务摘要、最多 30 条证据片段和最近对话；可能含账户、主机名、IP 和业务数据')
    if task:
        preview = context(task)
        _note('本次证据条数', len(preview['evidence']))
        if read_line('  先查看发送的证据 JSON？输入 y 查看：').lower() == 'y':
            _note('发送证据预览', json.dumps(preview, ensure_ascii=False))
    if session:
        answer = read_line('  发送授权：y 仅本次，s 本任务本次对话（含后续问题），其他取消：').lower()
        return 'session' if answer == 's' else answer == 'y'
    return read_line('  允许本次提问发送到此地址？输入 y 确认：').lower() == 'y'


def prepare_key(profiles):
    name, profile = profiles.active()
    if profile['kind'] == 'openai' and not profiles.key(name, profile):
        from cli import _note
        _note('当前没有 API Key', '可隐藏输入本次会话密钥；无密钥的本地服务直接回车')
        key = field('API Key（隐藏输入，0 返回）', allow_empty=True, secret=True)
        if key:
            profiles.session_keys[name] = key


@cancellable
def chat(store, profiles, task_id):
    from cli import _heading, _note
    task = store.get(task_id)
    _heading('围绕当前任务追问', '0 或 /back 返回 · /status 查看本地模型诊断，不发送请求')
    if not task.get('events'):
        _note('没有可用登录证据', '可咨询排查方法，但无法判断本机是否被入侵；可重新采集更长时间的日志')
    show_diagnostic(task)
    try:
        prepare_key(profiles)
    except ValueError as exc:
        _note('需要配置模型', exc)
        return
    for item in store.history(task_id, 4):
        _note('你' if item['role'] == 'user' else '模型', item['content'])
    session_destination = None
    while True:
        question = read_line('  你 > ')
        if question in ('0', '/back', '退出', ''):
            return
        if question == '/status':
            show_diagnostic(store.get(task_id))
            continue
        try:
            current = profiles.active()
            destination = json.dumps(current, sort_keys=True)
            if session_destination != destination:
                consent = consent_for(profiles, store.get(task_id), session=True)
                if not consent:
                    _note('已取消', '未发送请求')
                    continue
                if consent == 'session':
                    session_destination = destination
            _note('正在分析', '等待模型回答…')
            _note('模型', ask(store, profiles, task_id, question, consent=True))
        except (ValueError, RuntimeError, OSError) as exc:
            _note('本次提问失败', exc)
            task = store.get(task_id)
            show_diagnostic(task)
            _note('继续操作', '可重新提问，或输入 0 返回；任务证据仍在本机')


@cancellable
def task_detail(store, profiles, task):
    from cli import _note
    task_id = task['id']
    show(task)
    while True:
        action = choice('1 向模型提问  2 查看证据  3 导出完整 JSON  0 返回', ('1', '2', '3'))
        if action == '1':
            chat(store, profiles, task_id)
        elif action == '2':
            for row in task.get('events', [])[:100]:
                _note(row['ref'], row['raw'])
                if row.get('raw_truncated'):
                    _note('原文截断', f"仅保存前 4096 字符；完整记录 SHA256：{row['raw_sha256']}")
            _note('证据展示范围', '最多显示 100 条；完整快照可导出')
        else:
            try:
                def export_path(value):
                    output = Path(value.strip('"').strip("'")).expanduser()
                    if output.exists():
                        raise ValueError('目标已存在；请换一个文件名以避免覆盖')
                    if not output.parent.is_dir():
                        raise ValueError('父目录不存在，请填写已有目录中的文件路径')
                    return output
                output = field('导出文件路径（包含 .json 文件名）', validate=export_path)
                with output.open('x', encoding='utf-8') as stream:
                    json.dump(dict(task=task, conversation=store.history(task_id, 1000)), stream, ensure_ascii=False, indent=2)
                _note('已导出', output)
            except Cancelled:
                _note('已取消', '返回任务详情')
            except OSError as exc:
                _note('导出失败', exc)


@cancellable
def task_menu(store, profiles):
    from cli import _heading, _note
    while True:
        _heading('防护任务历史', '输入列表序号打开任务 · 0 返回主菜单')
        tasks = store.recent()
        if not tasks:
            _note('暂无任务', '从主菜单选择 1 分析本机日志，或选择 4 体验合成演示')
            return
        for index, task in enumerate(tasks, 1):
            status = STATES.get(task['status'], task['status'])
            _note(str(index), f"{task['created']} | {task['source']} | {status} | 线索 {len(task['findings'])}")
        selected = choice('任务序号', tuple(str(i) for i in range(1, len(tasks) + 1)))
        task_detail(store, profiles, store.get(tasks[int(selected) - 1]['id']))


@cancellable
def wizard(store, profiles):
    import platform
    from cli import _heading, _note
    from guard import plan
    system = platform.system().lower()
    if system not in ('windows', 'linux'):
        raise ValueError('本机版本只支持 Windows 或 Linux')
    _heading(f'{system.title()} 本机采集与模拟防护', '回车采用默认值 · 0 返回 · 所有处置仅模拟')
    print(f'  1 读取本机 {system.title()} 日志（默认）\n  2 本机导出目录\n  3 本平台合成演示')
    source_choice = choice('来源', ('1', '2', '3'), '1')
    if source_choice == '1':
        source = f'{system}-local'
        collector, demo = (collect_windows if system == 'windows' else collect_linux), False
        if system == 'linux':
            def check_minutes(value):
                try:
                    minutes = int(value)
                except ValueError:
                    raise ValueError('请填写 1–1440 的整数') from None
                if not 1 <= minutes <= 1440:
                    raise ValueError('时间范围应为 1–1440 分钟')
                return minutes
            minutes = field('读取最近多少分钟的 SSH 日志', '15', validate=check_minutes)
            collector = lambda: collect_linux(minutes=minutes)
    elif source_choice == '2':
        def check_directory(value):
            directory = Path(value.strip('"').strip("'")).expanduser().resolve()
            if not directory.is_dir():
                raise ValueError('目录不存在，请检查路径')
            return directory
        directory = field('导出目录', validate=check_directory)
        source, collector, demo = f'export:{directory}', lambda: collect_export(directory), False
    else:
        source, collector, demo = f'demo:{system}', lambda: demo_events(system), True
    def check_protected(value):
        protected = [item.strip() for item in value.split(',') if item.strip()]
        plan([], protected)
        return protected
    protected = field('管理 IP / CIDR 保护名单（逗号分隔；可回车）', allow_empty=True, validate=check_protected)
    analyst = None
    if profiles.load()['active']:
        use_model = choice('分析方式：1 规则分析  2 规则 + 模型解释', ('1', '2'), '1') == '2'
        if use_model:
            prepare_key(profiles)
            def analyst(task_id):
                if not consent_for(profiles, store.get(task_id)):
                    raise ValueError('用户未同意发送证据，模型步骤已取消')
                return ask(store, profiles, task_id, '解释异常线索并引用证据，给出下一步核查方法。', consent=True)
    else:
        _note('分析方式', '规则分析；尚未配置模型，可稍后在主菜单 3 配置并追问')
    _note('正在分析', '读取日志、匹配规则并生成模拟处置方案…')
    task = run_task(store, source, collector, protected=protected, demo=demo, analyst=analyst)
    task_detail(store, profiles, task)


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
