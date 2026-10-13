"""Full-screen native workbench; existing workflows run in one input-aware worker."""
from __future__ import annotations

import asyncio
from contextlib import redirect_stdout
from datetime import datetime
import os
from pathlib import Path
import re
import sys
import threading
import time

from prompt_toolkit import Application
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.document import Document
from prompt_toolkit.filters import Condition
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import (
    ConditionalContainer, Float, FloatContainer, HSplit, Layout, VSplit, Window,
)
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.layout.menus import CompletionsMenu
from prompt_toolkit.lexers import Lexer
from prompt_toolkit.output import ColorDepth
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import TextArea
from prompt_toolkit.utils import get_cwidth

import guard_cli
from guard import demo_events, run_task, task_assessment
from terminal_ui import Cancelled, input_handler, model_answer, output_width


COMMANDS = {
    '/scan': '分析本机日志', '/tasks': '打开任务与证据',
    '/models': '配置或切换模型', '/demo': '运行合成演示',
    '/details': '当前任务详情与导出', '/status': '查看模型诊断',
    '/parameters': '模型参数', '/check-update': '检查更新',
    '/update': '更新并退出', '/clear': '清空当前屏幕',
    '/home': '返回首页，保留当前任务', '/workspace': '查看工作区与数据目录',
    '/sidebar': '显示 / 隐藏侧栏', '/help': '查看全部命令', '/exit': '退出',
}
ALIASES = dict(zip('1234560', ('/scan', '/tasks', '/models', '/demo', '/check-update', '/update', '/exit')))

STYLE = Style.from_dict({
    '': '#dce2ec',
    'surface': 'bg:#161b22 #dce2ec',
    'header': 'bg:#222b38 #bac8dc', 'brand': '#e6efff bold',
    'accent': '#87c7ff', 'muted': '#a9b5c6', 'title': '#eef4ff bold',
    'sidebar': 'bg:#1e2633 #dce2ec', 'input': 'bg:#273448 #f0f5ff',
    'input-label': 'bg:#273448 #aedaff bold',
    'footer': '#a9b5c6', 'ok': '#a2d9b1', 'warning': '#f0cd91', 'error': '#ffacb8',
    'user': '#a8c1ff bold', 'completion-menu': 'bg:#2b303c #cbd3e3',
    'completion-menu.completion.current': 'bg:#465570 #ffffff',
    'completion-menu.meta.completion': 'bg:#242832 #aab3c5',
    'completion-menu.meta.completion.current': 'bg:#465570 #ffffff',
    'scrollbar.background': 'bg:#20232c', 'scrollbar.button': 'bg:#505b71',
})


def safe_text(value):
    """External text remains literal; never interpret terminal escape sequences."""
    return re.sub(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]',
                  lambda m: f'\\x{ord(m.group()):02x}', str(value))


def fit_line(value, width):
    """Bound labels by terminal cells, including CJK and literal control text."""
    text = safe_text(value).replace('\n', ' ').replace('\t', ' ')
    if get_cwidth(text) <= width:
        return text
    result, used = '', 0
    for char in text:
        cells = get_cwidth(char)
        if used + cells > max(0, width - 1):
            break
        result += char
        used += cells
    return result + '…'


def task_source(task):
    source = str(task.get('source', ''))
    if task.get('demo') or source.startswith('demo:'):
        return '合成演示'
    return {'windows-local': 'Windows 日志', 'linux-local': 'Linux SSH'}.get(
        source, '导入日志' if source.startswith('export:') else '日志任务')


def task_time(task):
    try:
        return datetime.fromisoformat(task['created'].replace('Z', '+00:00')).astimezone().strftime('%m-%d %H:%M')
    except (KeyError, TypeError, ValueError):
        return '时间未知'


def task_result(task):
    assessment = task_assessment(task)
    label = {
        'failed': '未完成 · 失败', 'interrupted': '未完成 · 中断',
        'pending': '采集中', 'findings': f"待核查线索 {len(task.get('findings', []))} 条",
        'insufficient_data': '数据不足', 'no_findings': '已分析范围内无线索',
    }[assessment['status']]
    if assessment['scope_incomplete']:
        label += ' · 范围不完整'
    return label


class MessageLexer(Lexer):
    def lex_document(self, document):
        def line(index):
            text = document.lines[index]
            stripped = text.strip()
            style = ''
            if stripped.startswith(('! 范围说明', '! 分析范围不完整', '! 没有可用登录证据')):
                style = 'class:warning'
            elif stripped.startswith(('! ', '[失败]', '未完成', '操作失败')):
                style = 'class:error'
            elif stripped.startswith('[完成]'):
                style = 'class:ok'
            elif stripped.startswith(('你 ›', '› /')):
                style = 'class:user'
            elif stripped.startswith(('─', '[未启用]')):
                style = 'class:muted'
            elif stripped.startswith(('【', '模型回答', '防护任务')):
                style = 'class:title'
            return [(style, text)]
        return line


class WorkerOutput:
    """Route worker prints only; unrelated threads retain their original stdout."""
    def __init__(self, owner, original):
        self.owner, self.original = owner, original
        self.thread = threading.get_ident()

    def write(self, value):
        if threading.get_ident() == self.thread:
            self.owner.loop.call_soon_threadsafe(self.owner.append, value)
            return len(value)
        return self.original.write(value)

    def flush(self):
        if threading.get_ident() != self.thread:
            self.original.flush()

    def isatty(self):
        return False if threading.get_ident() == self.thread else self.original.isatty()

    def __getattr__(self, name):
        return getattr(self.original, name)


class Workbench:
    def __init__(self, store, profiles, system, data_dir, *, input=None, output=None):
        self.store, self.profiles, self.system = store, profiles, system
        self.data_dir = Path(data_dir)
        self.task_id = None
        self.running = False
        self.started = 0
        self.pending = False
        self.secret = False
        self.prompt = ''
        self.response = None
        self.response_ready = threading.Event()
        self.cancel_requested = threading.Event()
        self.exit_after = False
        self.sidebar = True
        self.loop = None
        self.model = '规则分析 · 未配置模型'
        self.has_model = False
        self.selected_task = None
        self.recent = []
        self.refresh_context()

        self.messages = TextArea(read_only=True, scrollbar=True, wrap_lines=True,
                                 style='class:surface', lexer=MessageLexer())
        self.editor = TextArea(
            height=Dimension(min=1, preferred=2, max=2), multiline=True,
            prompt=' › ', style='class:input',
            password=Condition(lambda: self.secret),
            read_only=Condition(lambda: self.running and not self.pending),
            completer=WordCompleter(list(COMMANDS), meta_dict=COMMANDS, sentence=True),
            complete_while_typing=Condition(lambda: not self.pending and self.editor.text.startswith('/')),
        )
        # One painted surface: empty cells and text inherit the same background.
        welcome = Window(FormattedTextControl(self.home_text), style='class:surface')
        content = HSplit([
            ConditionalContainer(welcome, Condition(lambda: not self.messages.text)),
            ConditionalContainer(self.messages, Condition(lambda: bool(self.messages.text))),
        ])
        sidebar = ConditionalContainer(
            Window(FormattedTextControl(self.sidebar_text), width=34, style='class:sidebar'),
            Condition(self.show_sidebar),
        )
        body = VSplit([Window(width=2), content, Window(width=2), sidebar])
        root = HSplit([
            Window(FormattedTextControl(self.header), height=1, style='class:header'),
            body,
            Window(FormattedTextControl(self.status), height=1, style='class:muted'),
            Window(FormattedTextControl(self.input_title), height=Dimension(min=1, max=4), dont_extend_height=True, wrap_lines=True, style='class:input-label'),
            self.editor,
            Window(FormattedTextControl(self.footer), height=1, style='class:footer'),
        ], style='class:surface')
        keys = KeyBindings()

        @keys.add('enter')
        def submit(event):
            self.submit()

        @keys.add('escape', 'enter')
        def newline(event):
            if not self.running or self.pending:
                self.editor.buffer.insert_text('\n')

        @keys.add('c-c')
        def cancel(event):
            self.cancel()

        @keys.add('c-q')
        def quit_(event):
            self.request_exit()

        @keys.add('c-l')
        def clear(event):
            if not self.running:
                self.messages.text = ''

        @keys.add('f1')
        def help_(event):
            self.help()

        @keys.add('pageup')
        def page_up(event):
            self.messages.buffer.cursor_up(count=max(1, self.app.output.get_size().rows - 10))

        @keys.add('pagedown')
        def page_down(event):
            self.messages.buffer.cursor_down(count=max(1, self.app.output.get_size().rows - 10))

        self.app = Application(
            layout=Layout(FloatContainer(root, [Float(xcursor=True, ycursor=True, content=ConditionalContainer(
                CompletionsMenu(max_height=8, scroll_offset=1),
                Condition(lambda: not self.running and self.editor.text.startswith('/')),
            ))]), self.editor),
            key_bindings=keys, style=STYLE, full_screen=True, mouse_support=True,
            refresh_interval=0.2, input=input, output=output,
            color_depth=ColorDepth.DEPTH_1_BIT if 'NO_COLOR' in os.environ else None,
        )

    def refresh_context(self):
        data = self.profiles.load()
        self.has_model = bool(data['active'])
        self.model = '未配置 · 可先使用规则分析'
        if data['active']:
            self.model = safe_text(data['active'] + ' / ' + data['profiles'][data['active']]['model'])
        self.recent = self.store.recent(5)
        self.selected_task = self.store.get(self.task_id) if self.task_id else None

    def show_sidebar(self):
        size = self.app.output.get_size()
        return self.sidebar and size.columns >= 120 and size.rows >= 26

    def content_width(self):
        return max(1, self.app.output.get_size().columns - 4 - (34 if self.show_sidebar() else 0))

    def home_text(self):
        size = self.app.output.get_size()
        compact = size.rows < 26
        width = self.content_width()
        rows = []

        def line(text='', style=''):
            rows.append((style, fit_line(text, width) + '\n'))

        if not compact:
            line()
        line('Microlnsight  /  日志研判', 'class:brand')
        if not compact:
            line('从本机日志开始，核对证据，再继续追问。', 'class:muted')
        line()
        line('开始工作', 'class:title')
        line('/scan    分析本机日志', 'class:accent')
        line('/demo    体验合成演示', 'class:accent')
        line('/tasks   打开历史任务', 'class:accent')
        line('/models  配置或切换模型', 'class:accent')
        if size.rows < 22:
            return rows
        line()
        if self.selected_task:
            line('继续当前任务  ·  ' + task_source(self.selected_task), 'class:title')
            line(task_result(self.selected_task), 'class:warning')
            line('/details 查看证据与导出；在下方继续提问。', 'class:muted')
        else:
            line('最近任务  ·  /tasks 选择打开', 'class:title')
            if not self.recent:
                line('暂无任务。输入 /scan 开始，或用 /demo 体验。', 'class:muted')
            for task in self.recent[:1 if compact else min(3, max(1, (size.rows - 22) // 3))]:
                line(f'{task_time(task)}  ·  {task_source(task)}')
                line('  ' + task_result(task), 'class:muted')
        if not compact:
            line()
            line('仅读取与分析日志，防护建议尚未执行。', 'class:muted')
        return rows

    def header(self):
        return [('class:brand', '  Microlnsight'), ('', f'  /  {self.system.title()} 本机版'),
                ('class:muted', '     日志 · 证据 · 研判' if self.app.output.get_size().columns >= 85 else '')]

    def sidebar_text(self):
        rows = []

        def line(text='', style=''):
            rows.append((style, '  ' + fit_line(text, 30) + '\n'))

        line()
        line('工作区', 'class:title')
        line(self.system.title() + ' · 本机分析')
        line('日志权限将在采集时检查', 'class:muted')
        line()
        line('当前模型', 'class:muted')
        # Split profile and model instead of wrapping a long identifier arbitrarily.
        for part in self.model.split(' / ', 1):
            line(part)
        line('/models 管理模型', 'class:accent')
        line()
        line('当前任务', 'class:title')
        task = self.selected_task
        if task:
            line(task_source(task) + ' · ' + task_time(task))
            line(task_result(task).split(' · ')[0], 'class:warning')
            if task_assessment(task)['scope_incomplete']:
                line('分析范围不完整', 'class:warning')
            line('/details 证据与导出', 'class:accent')
        else:
            line('尚未选择任务', 'class:muted')
            line('/scan 开始本机分析', 'class:accent')
            line('/tasks 打开历史任务', 'class:accent')
        line()
        line('防护建议尚未执行', 'class:warning')
        line('/workspace 工作区详情', 'class:muted')
        return rows

    def status(self):
        if self.running:
            elapsed = int(time.monotonic() - self.started)
            label = '等待输入' if self.pending else '处理中'
            return f'  {"⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[int(time.monotonic() * 5) % 10]} {label} · {elapsed} 秒' + (' · 完成当前操作后退出' if self.exit_after else '')
        label = '任务已选择' if self.task_id else '等待开始'
        return '  ' + fit_line(f'● {label}   ·   {self.model}', self.app.output.get_size().columns - 2)

    def input_title(self):
        if self.pending:
            return '  ' + self.prompt
        if self.running:
            return '  正在处理 · Ctrl+C 取消当前操作'
        if not self.task_id:
            return '  输入 /scan 开始，或 /tasks 打开任务'
        if not self.has_model:
            return '  /details 查看证据 · /models 配置模型后提问'
        return '  围绕当前任务提问，或输入 /命令'

    def footer(self):
        if self.pending:
            return '  Enter 确认   Ctrl+C 取消   ' + ('密钥已隐藏，不记录输入' if self.secret else '回车采用提示中的默认值')
        if self.app.output.get_size().columns < 90:
            return '  Enter 提交 · F1 帮助 · Ctrl+Q 退出'
        return '  Enter 提交   Tab 补全   Alt+Enter 换行   PgUp/PgDn 滚动   F1 帮助   Ctrl+Q 退出'

    def append(self, value):
        if re.fullmatch('─+', value):
            return  # The full-screen layout already separates sections.
        text = (self.messages.text + safe_text(value))[-160000:]
        self.messages.buffer.set_document(Document(text, len(text)), bypass_readonly=True)
        self.app.invalidate()

    def help(self):
        self.append('\n命令面板\n' + '\n'.join(f'  {key:<15} {value}' for key, value in COMMANDS.items()) + '\n\n')

    def request_exit(self):
        if self.running:
            self.exit_after = True
            self.cancel()
        else:
            self.app.exit()

    def cancel(self):
        if self.running:
            self.cancel_requested.set()
            if self.pending:
                self.response = None
                self.editor.text = ''
                self.pending = self.secret = False
                self.response_ready.set()
            else:
                self.append('\n正在等待当前读写或网络请求结束，随后返回；已保存的任务会保留。\n')
        else:
            self.editor.text = ''

    def read_input(self, prompt, secret=False):
        if self.cancel_requested.is_set():
            raise Cancelled()
        self.response_ready.clear()
        self.loop.call_soon_threadsafe(self.present_prompt, prompt, secret)
        self.response_ready.wait()
        if self.response is None or self.cancel_requested.is_set():
            raise Cancelled()
        return self.response

    def present_prompt(self, prompt, secret):
        if self.cancel_requested.is_set():
            self.response = None
            self.response_ready.set()
            return
        self.prompt, self.secret, self.pending = safe_text(prompt.strip()), secret, True
        self.editor.text = ''
        self.app.invalidate()

    def submit(self):
        value = self.editor.text.strip()
        if self.pending:
            if not self.secret:
                self.append(f'\n  {self.prompt}\n  › {value or "（默认）"}\n')
            self.response = value
            self.editor.text = ''
            self.pending = self.secret = False
            self.response_ready.set()
            return
        if self.running or not value:
            return
        self.editor.text = ''
        command = ALIASES.get(value, value)
        if command == '/exit':
            self.request_exit()
        elif command in ('/clear', '/home'):
            self.messages.text = ''
        elif command == '/workspace':
            self.append(f'\n工作区详情\n  平台：{self.system.title()}\n  模型：{self.model}\n'
                        f'  数据目录：{self.data_dir}\n  当前任务：{self.task_id or "尚未选择"}\n'
                        '  日志权限：采集时检查\n  防护建议尚未执行\n\n')
        elif command == '/sidebar':
            self.sidebar = not self.sidebar
        elif command == '/help':
            self.help()
        elif command.startswith('/') and command not in COMMANDS:
            self.append('\n! 未知命令；输入 /help 查看可用命令。\n')
        else:
            self.append('\n' + ('› ' if command.startswith('/') else '你 › ') + command + '\n\n')
            self.running, self.started = True, time.monotonic()
            self.cancel_requested.clear()
            self.loop = asyncio.get_running_loop()
            self.app.create_background_task(self.execute(command))

    async def execute(self, command):
        try:
            await asyncio.to_thread(self.worker, command)
        finally:
            self.running = self.pending = self.secret = False
            self.refresh_context()
            self.app.invalidate()
            if self.exit_after:
                self.app.exit()

    def worker(self, command):
        token = input_handler.set(self.read_input)
        width_token = output_width.set(lambda: max(1, self.content_width() - 1))
        try:
            with redirect_stdout(WorkerOutput(self, sys.stdout)):
                try:
                    self.dispatch(command)
                except (Cancelled, KeyboardInterrupt):
                    print('\n已取消当前操作。')
                except Exception as exc:
                    print(f'\n! 操作失败：{exc}\n可重试，或使用 /models 检查模型配置。')
        finally:
            output_width.reset(width_token)
            input_handler.reset(token)

    def dispatch(self, command):
        if command == '/demo':
            task = run_task(self.store, f'demo:{self.system}', lambda: demo_events(self.system), demo=True)
            self.task_id = task['id']
            guard_cli.show(task)
        elif command == '/scan':
            guard_cli.wizard(self.store, self.profiles)
            latest = self.store.recent(1)
            if latest:
                self.task_id = latest[0]['id']
        elif command == '/models':
            guard_cli.configure(self.profiles)
        elif command == '/parameters':
            guard_cli.model_parameters(self.profiles)
        elif command == '/tasks':
            tasks = self.store.recent()
            if not tasks:
                print('暂无任务；使用 /scan 或 /demo 创建任务。')
                return
            for i, task in enumerate(tasks, 1):
                print(f"  {i}  {task_time(task)} · {task_source(task)}")
                print(f"     {task_result(task)} · {task['id']}")
            selected = guard_cli.choice('选择任务序号（0 返回）', tuple(str(i) for i in range(1, len(tasks) + 1)))
            self.task_id = tasks[int(selected) - 1]['id']
            guard_cli.show(self.store.get(self.task_id))
        elif command in ('/details', '/status'):
            task = self.current_task()
            if command == '/details':
                guard_cli.task_detail(self.store, self.profiles, task)
            else:
                guard_cli.show_diagnostic(task)
        elif command in ('/check-update', '/update'):
            from cli_update import command as update
            if update(Path(__file__).resolve().parent, execute=command == '/update'):
                self.exit_after = True
        else:
            task = self.current_task()
            guard_cli.prepare_key(self.profiles)
            if not guard_cli.consent_for(self.profiles, task):
                print('已取消，未发送模型请求。')
                return
            model_answer(guard_cli.ask(self.store, self.profiles, task['id'], command, consent=True), '模型回答（需核实）')

    def current_task(self):
        if not self.task_id:
            raise ValueError('请先使用 /scan、/demo 或 /tasks 选择一个任务，再提问或查看详情')
        return self.store.get(self.task_id)

    def run(self):
        self.app.run()
