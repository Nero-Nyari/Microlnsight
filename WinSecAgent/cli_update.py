"""Native CLI release updates. Only managed program files are replaced.

Downloads never include local logs or model settings. Transactions retain a
backup and recover before the next launch if interrupted during replacement.
"""
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import uuid
import zipfile

REPOSITORY = 'Nero-Nyari/Microlnsight'
VERSION = '0.2.1'
MAX_DOWNLOAD = 32 * 1024 * 1024


def version(value):
    if not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', value):
        raise ValueError('版本号必须是 major.minor.patch')
    return tuple(int(part) for part in value.split('.'))


def atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.update-tmp')
    with temp.open('wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)


@contextmanager
def runtime_lock(root):
    """OS releases the lock on crash; an existing empty lock file is harmless."""
    path = Path(root) / '.cli-runtime.lock'
    with path.open('a+b') as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b'0')
            stream.flush()
        stream.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError('此安装目录还有 CLI/监控进程运行，请先退出该进程再操作') from exc
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == 'nt':
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def installed(root):
    path = Path(root) / 'edition.json'
    if not path.exists():
        return dict(version=VERSION, platform=sys.platform, development=True)
    data = read_json(path)
    data.setdefault('version', '0.1.0')
    return data


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != 'https':
            raise ValueError('更新服务跳转到非 HTTPS 地址，已拒绝')
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected and urlsplit(newurl).netloc != 'api.github.com':
            redirected.remove_header('Authorization')
        return redirected


def download(url, maximum=MAX_DOWNLOAD):
    headers = {'User-Agent': 'WinSecAgent-CLI-Updater', 'Accept': 'application/vnd.github+json'}
    if urlsplit(url).netloc == 'api.github.com':
        token = os.environ.get('WINSEC_UPDATE_TOKEN')
        if token:
            headers['Authorization'] = 'Bearer ' + token
        if '/releases/assets/' in urlsplit(url).path:
            headers['Accept'] = 'application/octet-stream'
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.build_opener(SafeRedirect()).open(request, timeout=30) as response:
            data = response.read(maximum + 1)
        if len(data) > maximum:
            raise RuntimeError('更新下载超过允许大小，未修改现有版本')
        return data
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise RuntimeError('仓库或版本不可访问；私有仓库请设置具有仓库 Contents 只读权限的 WINSEC_UPDATE_TOKEN') from exc
        raise RuntimeError(f'更新服务返回 HTTP {exc.code}，请稍后重试') from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError('无法连接更新仓库；请检查网络或代理。当前版本保持不变') from exc


def check(root):
    current = installed(root)
    releases = json.loads(download(f'https://api.github.com/repos/{REPOSITORY}/releases?per_page=30', 2 * 1024 * 1024))
    candidates = []
    for release in releases:
        if release.get('draft') or release.get('prerelease'):
            continue
        tag = release.get('tag_name', '')
        if not re.fullmatch(r'cli-v\d+\.\d+\.\d+', tag):
            continue
        candidates.append((version(tag[5:]), release))
    result = dict(current=current['version'], available=False, repository=REPOSITORY)
    if not candidates:
        return {**result, 'message': '仓库尚无已发布的 CLI 版本（不是检测到最新版）'}
    _, release = max(candidates, key=lambda item: item[0])
    latest = release['tag_name'][5:]
    assets = {asset['name']: asset for asset in release.get('assets', [])}
    system = current['platform']
    filename = f"winsecagent-{system}-cli" + ('.zip' if system == 'windows' else '.tar.gz')
    if current.get('development'):
        return {**result, 'latest': latest, 'message': '当前为开发源码目录，请通过 Git 更新；安装包支持原地更新'}
    if filename not in assets or 'SHA256SUMS.txt' not in assets:
        raise ValueError('已发布版本缺少本平台安装包或校验清单，未认定为可更新版本')
    prefix = f"https://github.com/{REPOSITORY}/releases/download/{release['tag_name']}/"
    urls = {}
    for name in (filename, 'SHA256SUMS.txt'):
        if assets[name]['browser_download_url'] != prefix + name:
            raise ValueError('更新下载地址与固定仓库不符')
        urls[name] = assets[name]['browser_download_url']
        if os.environ.get('WINSEC_UPDATE_TOKEN'):
            asset_url = assets[name].get('url', '')
            if not re.fullmatch(r'https://api\.github\.com/repos/' + re.escape(REPOSITORY) + r'/releases/assets/\d+', asset_url):
                raise ValueError('私有仓库资产地址无效')
            urls[name] = asset_url
    return {**result, 'latest': latest, 'available': version(latest) > version(current['version']),
            'filename': filename, 'asset_url': urls[filename], 'checksums_url': urls['SHA256SUMS.txt'],
            'message': '发现可用更新' if version(latest) > version(current['version']) else '当前已是最新发布版本或版本更高'}


def safe_name(name):
    path = PurePosixPath(name)
    if (not name or '\\' in name or ':' in name or path.is_absolute() or str(path) != name
            or any(part.startswith('.') for part in path.parts)):
        raise ValueError('更新包含不安全路径')
    allowed = (len(path.parts) == 1 and (path.suffix in ('.py', '.md', '.bat', '.sh')
               or name in ('requirements-windows.txt', 'requirements-linux.txt', 'edition.json', 'SHA256SUMS.txt')))
    allowed = allowed or (len(path.parts) >= 3 and path.parts[:2] == ('backend', 'app') and path.suffix == '.py')
    if not allowed:
        raise ValueError(f'更新文件不属于程序文件：{name}')
    return name


def destination(root, name):
    safe_name(name)
    root = Path(root).resolve()
    path = root / name
    if not path.resolve().is_relative_to(root):
        raise ValueError('程序文件指向安装目录之外')
    for item in (path, *path.parents):
        if item == root:
            break
        if item.is_symlink():
            raise ValueError('程序路径存在符号链接，拒绝覆盖')
    return path


def checksums(data):
    hashes = {}
    for line in data.decode('utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match or match[2] in hashes:
            raise ValueError('校验清单格式错误或文件重复')
        hashes[match[2]] = match[1]
    return hashes


def unpack(data, system, expected_version):
    prefix = f'winsecagent-{system}-cli/'
    files, folded, total = {}, set(), 0

    def add(name, content):
        nonlocal total
        if not name.startswith(prefix):
            raise ValueError('更新包目录或平台不符')
        name = safe_name(name[len(prefix):])
        if name.casefold() in folded:
            raise ValueError('更新包存在重复或大小写冲突文件')
        total += len(content)
        if len(files) >= 1000 or len(content) > 4 * 1024 * 1024 or total > MAX_DOWNLOAD:
            raise ValueError('解包内容超过允许大小')
        folded.add(name.casefold())
        files[name] = content

    if system == 'windows':
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.is_dir() or (info.external_attr >> 16) & 0o170000 == 0o120000 or info.file_size > 4 * 1024 * 1024:
                    raise ValueError('ZIP 更新包含非普通文件或超大文件')
                add(info.filename, archive.read(info))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            for member in archive:
                if not member.isfile() or member.size > 4 * 1024 * 1024:
                    raise ValueError('tar 更新包含链接或非普通文件')
                add(member.name, archive.extractfile(member).read())
    expected = checksums(files['SHA256SUMS.txt'])
    if set(expected) != set(files) - {'SHA256SUMS.txt'}:
        raise ValueError('更新包文件与校验清单不一致')
    for name, checksum in expected.items():
        if hashlib.sha256(files[name]).hexdigest() != checksum:
            raise ValueError('更新包文件校验失败')
    manifest = json.loads(files['edition.json'])
    if manifest.get('platform') != system or manifest.get('version') != expected_version or manifest.get('update_schema') != 1:
        raise ValueError('更新版本、平台或更新协议不符')
    required = {'agent.py', 'launch_cli.py', 'cli_update.py', f'requirements-{system}.txt'}
    if not required.issubset(files):
        raise ValueError('更新包缺少必需入口')
    return files


def runtime_python(root):
    root = Path(root).resolve()
    marker = root / 'runtime.json'
    relative = read_json(marker)['environment'] if marker.exists() else '.venv-cli'
    if relative != '.venv-cli' and not re.fullmatch(r'\.updates/env-[0-9a-f]{32}', relative):
        raise ValueError('运行环境路径无效')
    environment = root / relative
    if not environment.resolve().is_relative_to(root):
        raise ValueError('运行环境不在安装目录内')
    return environment / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')


def smoke(python, staged, data_dir):
    try:
        subprocess.run([str(python), '-B', '-X', 'utf8', str(staged / 'agent.py'),
                        '--data-dir', str(data_dir), 'demo'], cwd=staged, capture_output=True, timeout=45, check=True)
    except (subprocess.SubprocessError, OSError) as exc:
        raise RuntimeError('新版本启动自检失败，未启用新版本') from exc


def recover(root):
    root = Path(root).resolve()
    journal = root / '.update-transaction.json'
    if not journal.exists():
        return False
    state = read_json(journal)
    if not re.fullmatch(r'[0-9a-f]{32}', state['id']):
        raise ValueError('更新恢复记录无效')
    backup = root / '.updates' / state['id'] / 'backup'
    if not backup.resolve().is_relative_to(root) or backup.is_symlink():
        raise ValueError('更新备份路径无效')
    for name, existed in state['files'].items():
        path = destination(root, name) if name != 'runtime.json' else root / name
        if existed:
            atomic(path, (backup / name).read_bytes())
        elif path.exists():
            path.unlink()
    journal.unlink()
    return True


def apply(root, info, progress=print):
    root = Path(root).resolve()
    current = installed(root)
    if current.get('development'):
        raise ValueError('开发目录请使用 Git 更新；不会覆盖工作区改动')
    if not info['available']:
        return False
    system = current['platform']
    progress('下载本平台版本及 SHA256 清单…')
    checksum = checksums(download(info['checksums_url'], 65536)).get(info['filename'])
    archive = download(info['asset_url'])
    if not checksum or hashlib.sha256(archive).hexdigest() != checksum:
        raise ValueError('安装包 SHA256 校验失败，当前版本保持不变')
    files = unpack(archive, system, info['latest'])
    previous = checksums((root / 'SHA256SUMS.txt').read_bytes())
    previous['SHA256SUMS.txt'] = hashlib.sha256((root / 'SHA256SUMS.txt').read_bytes()).hexdigest()
    for name, checksum in previous.items():
        path = destination(root, name)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
            raise ValueError(f'本机程序文件被修改或缺失：{name}；为保留修改，已停止更新')
    for name in files.keys() - previous.keys():
        if destination(root, name).exists():
            raise ValueError(f'新版本文件与本机额外文件冲突：{name}')
    transaction = uuid.uuid4().hex
    work = root / '.updates' / transaction
    if not work.resolve().is_relative_to(root):
        raise ValueError('更新工作目录不在安装目录中')
    staged, backup = work / 'stage', work / 'backup'
    for name, content in files.items():
        path = destination(staged, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    python = runtime_python(root)
    runtime = (root / 'runtime.json').read_bytes() if (root / 'runtime.json').exists() else b'{"environment":".venv-cli"}'
    requirement = f'requirements-{system}.txt'
    if not python.is_file() or files[requirement] != (root / requirement).read_bytes():
        progress('在独立环境准备新版依赖；原环境保留…')
        relative = '.updates/env-' + transaction
        environment = root / relative
        try:
            subprocess.run([sys.executable, '-m', 'venv', str(environment)], capture_output=True, timeout=120, check=True)
            python = environment / ('Scripts/python.exe' if system == 'windows' else 'bin/python')
            subprocess.run([str(python), '-m', 'pip', 'install', '-r', str(staged / requirement)],
                           capture_output=True, timeout=300, check=True)
        except (subprocess.SubprocessError, OSError) as exc:
            raise RuntimeError('新版依赖准备失败，原环境与程序保持不变') from exc
        runtime = json.dumps(dict(environment=relative)).encode()
    progress('运行隔离演示自检（不读取真实日志、不调用模型）…')
    smoke(python, staged, work / 'smoke-before')
    replacements = {**files, 'runtime.json': runtime}
    names = set(previous) | set(replacements)
    state = dict(id=transaction, files={})
    for name in sorted(names):
        path = destination(root, name) if name != 'runtime.json' else root / name
        state['files'][name] = path.exists()
        if path.exists():
            target = backup / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
    journal = root / '.update-transaction.json'
    atomic(journal, json.dumps(state).encode())
    try:
        for name in sorted(names):
            path = destination(root, name) if name != 'runtime.json' else root / name
            if name in replacements:
                atomic(path, replacements[name])
            elif path.exists():
                path.unlink()
        # Agent normally acquires the runtime lock, so validation uses a staged
        # tree rather than trying to start another live instance while locked.
        for name, content in replacements.items():
            if (root / name).read_bytes() != content:
                raise RuntimeError('安装后文件校验失败')
        journal.unlink()  # Commit: until this point a crash restores the backup.
    except BaseException:
        recover(root)
        raise
    progress(f"已更新到 {info['latest']}。旧版备份保存在 .updates/{transaction}/backup；请重新启动。")
    return True


def command(root, execute=False, yes=False):
    try:
        info = check(root)
        print(f"本机版本 {info['current']} · 仓库 {info['repository']}")
        if info.get('latest'):
            print(f"最新发布版本 {info['latest']}")
        print(info['message'])
        if execute and info['available']:
            if not yes and input('更新程序并退出？本机数据和配置保留。输入 y 确认：').strip().lower() != 'y':
                return False
            return apply(root, info)
        return False
    except (KeyError, TypeError, zipfile.BadZipFile, tarfile.TarError) as exc:
        raise ValueError('更新元数据或压缩包格式无效，未完成更新') from exc
