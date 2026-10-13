"""Small, dependency-free helpers for ordinary SSH/Windows terminals."""
from functools import wraps
import getpass
import re
import sys
import warnings


class Cancelled(Exception):
    pass


def setup_terminal():
    if not sys.stdin.isatty():
        return
    try:
        import readline
        readline.parse_and_bind('"\\C-h": backward-delete-char')
        readline.parse_and_bind('"\\C-?": backward-delete-char')
        readline.set_auto_history(False)
    except (ImportError, AttributeError):
        pass  # Windows' console input already handles editing.


def clean_input(value):
    output = []
    for char in value:
        if char in ('\b', '\x7f'):
            if output:
                output.pop()
        else:
            output.append(char)
    return ''.join(output).strip()


def read_line(prompt, secret=False):
    try:
        if secret:
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                value = getpass.getpass(prompt)
        else:
            value = input(prompt)
        return clean_input(value)
    except getpass.GetPassWarning as exc:
        raise ValueError('当前终端无法隐藏密钥输入；请使用交互终端，或选择环境变量方式') from exc
    except KeyboardInterrupt as exc:
        print()
        raise Cancelled() from exc


def field(label, default='', validate=None, allow_empty=False, secret=False):
    from cli import _note
    while True:
        hint = f' [{default}]' if default else ''
        value = read_line(f'  {label}{hint}：', secret=secret)
        if value.casefold() in ('0', 'q', '/back', '/cancel', '返回'):
            raise Cancelled()
        value = value or default
        if not value and not allow_empty:
            _note('请补充', '这一项不能为空；输入 0 可返回')
            continue
        try:
            return validate(value) if validate else value
        except ValueError as exc:
            _note('请修改这一项', exc)


def choice(label, options, default=''):
    def validate(value):
        if value not in options:
            raise ValueError('请输入 ' + ' / '.join(options) + '；0 返回')
        return value
    return field(label, default=default, validate=validate)


def cancellable(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (Cancelled, KeyboardInterrupt):
            from cli import _note
            _note('已返回', '取消当前操作')
    return wrapped


def _inline(value):
    """Readable Markdown text; keep punctuation inside inline code intact."""
    parts = re.split(r'(`+[^`]+`+)', value)
    for index, part in enumerate(parts):
        if part.startswith('`') and part.endswith('`'):
            parts[index] = part.strip('`')
        else:
            part = re.sub(r'\*\*(.+?)\*\*', r'\1', part)
            part = re.sub(r'__(.+?)__', r'\1', part)
            part = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'\1 (\2)', part)
            parts[index] = part
    return ''.join(parts)


def _table_cells(line):
    # Pipes escaped or inside inline code are part of the cell, not separators.
    cells, cell, code = [], [], False
    escaped = False
    for char in line.strip().strip('|'):
        if escaped:
            cell.append(char)
            escaped = False
        elif char == '\\':
            cell.append(char)
            escaped = True
        elif char == '`':
            code = not code
            cell.append(char)
        elif char == '|' and not code:
            cells.append(''.join(cell).strip())
            cell = []
        else:
            cell.append(char)
    cells.append(''.join(cell).strip())
    return cells


def model_answer(value, title='模型解释（需核实）'):
    """Render model prose as terminal blocks; never interpret code or ANSI escapes.

    The original answer remains untouched in storage and JSON exports.
    Code wraps with a visible continuation marker, never a fabricated shell '\\'.
    """
    from cli import _heading, _wrap
    _heading(title)
    last_blank = False
    def emit(value, indent='', continuation=None):
        nonlocal last_blank
        _wrap(value, indent, continuation)
        last_blank = False
    def gap():
        nonlocal last_blank
        if not last_blank:
            print()
            last_blank = True
    lines = str(value).replace('\r\n', '\n').replace('\r', '\n').split('\n')
    fence = None
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})(.*)$', line)
        if fence:
            if match and match[1][0] == fence[0] and len(match[1]) >= len(fence) and not match[2].strip():
                gap()
                fence = None
            else:
                # Preserve code indentation, Markdown-looking operators and comments.
                emit(line, '    │ ', '    ↪ ')
            index += 1
            continue
        if match:
            fence = match[1]
            gap()
            emit('代码 / 命令（仅展示；↪ 表示显示续行，复制请使用导出原文）', '  ')
            if match[2].strip():
                emit('语言：' + match[2].strip(), '  ')
            index += 1
            continue
        # Display Markdown table rows vertically, so long Chinese cells stay readable.
        if '|' in line and index + 1 < len(lines):
            separators = _table_cells(lines[index + 1])
            headers = _table_cells(line)
            if len(headers) >= 2 and len(headers) == len(separators) and all(re.fullmatch(r':?-{3,}:?', cell) for cell in separators):
                index += 2
                while index < len(lines) and '|' in lines[index] and lines[index].strip():
                    row = _table_cells(lines[index])
                    if len(row) != len(headers):
                        break
                    gap()
                    for header, cell in zip(headers, row):
                        emit(f'{_inline(header)}：{_inline(cell)}', '  ', '    ')
                    index += 1
                gap()
                continue
        heading = re.match(r'^\s{0,3}#{1,6}\s+(.+?)\s*#*$', line)
        bullet = re.match(r'^(\s*)([-+*]|\d+[.)])\s+(.+)$', line)
        if not line.strip():
            gap()
        elif heading:
            gap()
            emit('【' + _inline(heading[1]) + '】', '  ')
        elif re.fullmatch(r'\s*(?:-{3,}|\*{3,}|_{3,})\s*', line):
            gap()
        elif bullet:
            indent = '  ' + ' ' * min(len(bullet[1]), 8)
            marker = '•' if bullet[2] in ('-', '+', '*') else bullet[2]
            emit(_inline(bullet[3]), indent + marker + ' ', indent + '  ')
        else:
            emit(_inline(line), '  ', '    ')
        index += 1
    gap()
