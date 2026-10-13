"""Full-screen native workbench; existing workflows run in one input-aware worker."""
from __future__ import annotations

import asyncio
from contextlib import redirect_stdout
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
from prompt_toolkit.layout.containers import WindowAlign
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.layout.menus import CompletionsMenu
from prompt_toolkit.lexers import Lexer
from prompt_toolkit.output import ColorDepth
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import TextArea

import guard_cli
from guard import demo_events, run_task
from terminal_ui import Cancelled, input_handler, model_answer, output_width


COMMANDS = {
    '/scan': '分析本机日志', '/tasks': '打开任务与证据',
    '/models': '配置或切换模型', '/demo': '运行合成演示',
    '/details': '当前任务详情与导出', '/status': '查看模型诊断',
    '/parameters': '模型参数', '/check-update': '检查更新',
    '/update': '更新并退出', '/clear': '清空当前屏幕',
    '/sidebar': '显示 / 隐藏侧栏', '/help': '查看全部命令', '/exit': '退出',
}
ALIASES = dict(zip('1234560', ('/scan', '/tasks', '/models', '/demo', '/check-update', '/update', '/exit')))

STYLE = Style.from_dict({
    '': 'bg:#17191f #d6dae4',
    'header': 'bg:#20232c #9da6b8', 'brand': '#cad7ff bold',
    'accent': '#96b5ff', 'muted': '#8d95a7', 'title': '#e1e7f5 bold',
    'sidebar': 'bg:#1d2028 #a5aec0', 'input': 'bg:#252a35 #eef1f7',
    'input-label': 'bg:#252a35 #a8c1ff bold',
    'footer': '#8d95a7', 'ok': '#9bcda6', 'warning': '#ebc68e', 'error': '#ee9eaa',
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
        self.recent = []
        self.refresh_context()

        self.messages = TextArea(read_only=True, scrollbar=True, wrap_lines=True, lexer=MessageLexer())
        self.editor = TextArea(
            height=Dimension(min=1, preferred=3, max=3), multiline=True,
            prompt=' › ', style='class:input',
            password=Condition(lambda: self.secret),
            read_only=Condition(lambda: self.running and not self.pending),
            completer=WordCompleter(list(COMMANDS), meta_dict=COMMANDS, sentence=True),
            complete_while_typing=Condition(lambda: not self.pending and self.editor.text.startswith('/')),
        )
        welcome = HSplit([
            Window(height=Dimension(min=0, weight=1)),
            Window(FormattedTextControl([('class:brand', 'W I N S E C'), ('class:accent', '  /  AGENT')]), height=2, align=WindowAlign.CENTER),
            Window(FormattedTextControl('本机日志研判工作台'), height=2, align=WindowAlign.CENTER, style='class:title'),
            Window(FormattedTextControl('从一份日志开始，找到可以核查的证据。'), height=2, align=WindowAlign.CENTER, style='class:muted'),
            Window(FormattedTextControl([('class:accent', '/scan'), ('', '  本机分析     '), ('class:accent', '/demo'), ('', '  体验演示')]), height=2, align=WindowAlign.CENTER),
            Window(FormattedTextControl([('class:accent', '/tasks'), ('', '  历史任务     '), ('class:accent', '/models'), ('', '  选择模型')]), height=2, align=WindowAlign.CENTER),
            Window(FormattedTextControl('先运行分析，再围绕当前任务直接提问。'), height=2, align=WindowAlign.CENTER, style='class:muted'),
            Window(height=Dimension(min=0, weight=1)),
        ], padding=0)
        content = HSplit([
            ConditionalContainer(welcome, Condition(lambda: not self.messages.text and self.app.output.get_size().rows >= 24)),
            ConditionalContainer(Window(FormattedTextControl(
                '\nMicrolnsight\n\n/scan 分析    /demo 演示\n/tasks 任务   /models 模型\n'),
                align=WindowAlign.CENTER, wrap_lines=True, style='class:brand'),
                Condition(lambda: not self.messages.text and self.app.output.get_size().rows < 24)),
            ConditionalContainer(self.messages, Condition(lambda: bool(self.messages.text))),
        ])
        sidebar = ConditionalContainer(
            Window(FormattedTextControl(self.sidebar_text), width=29, style='class:sidebar', wrap_lines=True),
            Condition(lambda: self.sidebar and self.app.output.get_size().columns >= 105),
        )
        body = VSplit([Window(width=2), content, Window(width=2), sidebar])
        root = HSplit([
            Window(FormattedTextControl(self.header), height=1, style='class:header'),
            body,
            Window(FormattedTextControl(self.status), height=1, style='class:muted'),
            Window(FormattedTextControl(self.input_title), height=Dimension(min=1, max=4), dont_extend_height=True, wrap_lines=True, style='class:input-label'),
            self.editor,
            Window(FormattedTextControl(self.footer), height=1, style='class:footer'),
        ])
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
        if data['active']:
            self.model = safe_text(data['active'] + ' / ' + data['profiles'][data['active']]['model'])
        self.recent = self.store.recent(5)

    def header(self):
        return [('class:brand', '  Microlnsight'), ('', f'  /  {self.system.title()} 本机版'),
                ('class:muted', '     LOCAL WORKSPACE' if self.app.output.get_size().columns >= 85 else '')]

    def sidebar_text(self):
        rows = [('class:title', '\n  工作区\n\n'), ('', f'  {self.system.title()} · 本机分析\n'),
                ('class:muted', '\n  当前模型\n'), ('', '  ' + self.model + '\n'),
                ('class:muted', '\n  当前任务\n'), ('', '  ' + (self.task_id or '尚未选择') + '\n'),
                ('class:muted', '\n  最近任务\n')]
        for task in self.recent:
            rows.append(('', f"  {safe_text(task['id'])}\n"))
        if not self.recent:
            rows.append(('', '  尚无任务，试试 /demo\n'))
        rows.extend([('class:muted', '\n  数据目录\n'), ('', '  ' + safe_text(self.data_dir) + '\n'),
                     ('class:warning', '\n  防护建议尚未执行\n'), ('class:muted', '  结论请结合原文核查\n')])
        return rows

    def status(self):
        if self.running:
            elapsed = int(time.monotonic() - self.started)
            label = '等待输入' if self.pending else '处理中'
            return f'  {"⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[int(time.monotonic() * 5) % 10]} {label} · {elapsed} 秒' + (' · 完成当前操作后退出' if self.exit_after else '')
        return f'  ● 就绪   {self.model}' + (f'   · 任务 {self.task_id}' if self.task_id else '')

    def input_title(self):
        return '  ' + (self.prompt if self.pending else '提问或输入 /命令')

    def footer(self):
        if self.pending:
            return '  Enter 确认   Ctrl+C 取消   ' + ('密钥已隐藏，不记录输入' if self.secret else '回车采用提示中的默认值')
        if self.app.output.get_size().columns < 90:
            return '  Enter 发送 · F1 帮助 · Ctrl+Q 退出'
        return '  Enter 发送   Alt+Enter 换行   Tab 补全   PgUp/PgDn 滚动   F1 帮助   Ctrl+Q 退出'

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
        elif command == '/clear':
            self.messages.text = ''
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
        width_token = output_width.set(lambda: self.app.output.get_size().columns - 5 -
                                       (29 if self.sidebar and self.app.output.get_size().columns >= 105 else 0))
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
                print(f"  {i}  {task['id']}  {task['source']}  {guard_cli.STATES.get(task['status'], task['status'])}")
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
