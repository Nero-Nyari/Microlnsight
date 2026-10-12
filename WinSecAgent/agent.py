"""Native Windows/Linux CLI editions. All collection stays on this host."""
import argparse
import json
import os
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parent


def native_platform():
    system = platform.system().lower()
    if system not in ('windows', 'linux'):
        raise ValueError('当前版本仅支持 Windows 和 Linux')
    manifest = ROOT / 'edition.json'
    if manifest.exists() and json.loads(manifest.read_text(encoding='utf-8'))['platform'] != system:
        raise ValueError('安装包与当前操作系统不符，请下载对应平台版本')
    return system


def _main(argv=None):
    from terminal_ui import Cancelled, read_line, setup_terminal
    setup_terminal()
    from guard_cli import dispatch, resources, configure, wizard, task_menu, show
    from guard import demo_events, run_task
    from cli import _heading, _note
    args_list = list(sys.argv[1:] if argv is None else argv)
    try:
        system = native_platform()
        # Dedicated native command surface: no remote source options.
        native = argparse.ArgumentParser(description='WinSecAgent 本机版：本机采集、本机分析、本机保存')
        native.add_argument('--data-dir', type=Path, default=Path(os.environ.get('WINSEC_DATA_DIR', str(ROOT / 'data'))))
        subs = native.add_subparsers(dest='operation')
        for name in ('scan', 'watch'):
            command = subs.add_parser(name, help='读取本机日志' if name == 'scan' else '持续读取本机日志，Ctrl+C 停止')
            command.add_argument('--limit', type=int, default=1000)
            command.add_argument('--minutes', type=int, default=15, help='Linux journal 时间范围；Windows 按最近条数读取')
            command.add_argument('--protect', action='append', default=[])
            command.add_argument('--ttl', type=int, default=600)
            command.add_argument('--interval', type=int, default=60)
            command.add_argument('--with-model', action='store_true')
            command.add_argument('--allow-remote-model', action='store_true', help='允许将证据摘要发送到所选非本机模型')
        subs.add_parser('demo', help='本平台合成演示')
        subs.add_parser('models', help='配置本机模型或 API 接口')
        subs.add_parser('check-update', help='检查 GitHub 仓库已发布的 CLI 版本')
        update = subs.add_parser('update', help='校验并安装新版，保留本机数据与配置')
        update.add_argument('--yes', action='store_true', help='确认安装可用的已发布版本')
        subs.add_parser('version', help='显示当前版本')
        task_command = subs.add_parser('tasks', help='查看本机任务')
        task_command.add_argument('id', nargs='?')
        chat_command = subs.add_parser('ask', help='围绕本机任务追问')
        chat_command.add_argument('id')
        args = native.parse_args(args_list)
        if args.operation in ('check-update', 'update', 'version'):
            from cli_update import command, installed
            if args.operation == 'version':
                _note('版本', installed(ROOT)['version'])
            else:
                command(ROOT, execute=args.operation == 'update', yes=getattr(args, 'yes', False))
            return 0
        database = args.data_dir.expanduser().resolve() / 'agent.db'
        if args.operation in ('scan', 'watch'):
            args.command, args.source = 'guard', system
            args.ssh, args.directory, args.database = None, None, database
            args.cycles = 0 if args.operation == 'watch' else 1
            dispatch(args)
        elif args.operation in ('models', 'tasks', 'ask'):
            args.command, args.database = args.operation, database
            dispatch(args)
        else:
            store, profiles = resources(database)
            if args.operation == 'demo':
                show(run_task(store, f'demo:{system}', lambda: demo_events(system), demo=True))
                return 0
            while True:
                _heading(f'WinSecAgent · {system.title()} 本机版', '当前主机采集与分析 · 防护处置为模拟')
                _note('本机数据目录', database.parent)
                active = profiles.load()
                _note('当前模型', (active['active'] + ' / ' + active['profiles'][active['active']]['model']) if active['active'] else '尚未配置，可先运行规则分析')
                print('  1 本机日志分析与模拟防护\n  2 任务、证据与模型追问\n  3 模型配置与选择\n  4 本平台合成演示\n  5 检查更新\n  6 更新并退出\n  0 退出')
                choice = read_line('  选择 [0-6] > ')
                try:
                    if choice == '0':
                        return 0
                    if choice == '1':
                        wizard(store, profiles)
                    elif choice == '2':
                        task_menu(store, profiles)
                    elif choice == '3':
                        configure(profiles)
                    elif choice == '4':
                        show(run_task(store, f'demo:{system}', lambda: demo_events(system), demo=True))
                    elif choice in ('5', '6'):
                        from cli_update import command
                        if command(ROOT, execute=choice == '6'):
                            return 0
                    else:
                        _note('输入有误', '请选择 0–6')
                except (ValueError, OSError, RuntimeError) as exc:
                    _note('操作失败', exc)
    except (Cancelled, KeyboardInterrupt, EOFError):
        print('\n已退出，已完成的任务保存在本机。')
    except (ValueError, OSError, RuntimeError) as exc:
        _note('操作失败', exc)
        return 1
    return 0


def main(argv=None):
    from cli_update import runtime_lock, recover
    try:
        with runtime_lock(ROOT):
            if recover(ROOT):
                print('上次更新中断，已恢复旧版。')
            return _main(argv)
    except (ValueError, OSError, RuntimeError) as exc:
        print(f'启动失败：{exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
