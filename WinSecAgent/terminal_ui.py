"""Small, dependency-free helpers for ordinary SSH/Windows terminals."""
from functools import wraps
import getpass
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
