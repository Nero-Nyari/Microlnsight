"""Build source distributions from an allowlist, excluding runtime data/secrets."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile
from cli_update import VERSION, version as parse_version

ROOT = Path(__file__).resolve().parent
COMMON = ('agent.py', 'cli.py', 'guard.py', 'guard_cli.py', 'guard_models.py',
          'server_logs.py', 'install_cli.py', 'NATIVE_CLI.md', 'cli_update.py', 'launch_cli.py')
WINDOWS = ('backend/app/__init__.py', 'backend/app/agents/__init__.py',
           'backend/app/agents/event_context.py', 'backend/app/services/__init__.py',
           'backend/app/services/log_reader.py')


def build(output, version=VERSION):
    parse_version(version)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    artifacts = []
    for system in ('windows', 'linux'):
        extension = 'bat' if system == 'windows' else 'sh'
        names = [*COMMON, f'requirements-{system}.txt', f'install-{system}.{extension}', f'start-{system}.{extension}']
        if system == 'windows':
            names.extend(WINDOWS)
        files = {name: (ROOT / name).read_bytes() for name in names}
        for name in files:
            if name.endswith('.sh'):
                files[name] = files[name].replace(b'\r\n', b'\n')
        files['edition.json'] = json.dumps(dict(platform=system, distribution='native-cli-source',
                                                python='>=3.10', response_mode='simulation',
                                                version=version, update_schema=1), indent=2).encode()
        files['SHA256SUMS.txt'] = ''.join(f'{hashlib.sha256(data).hexdigest()}  {name}\n'
                                          for name, data in sorted(files.items())).encode()
        prefix = f'winsecagent-{system}-cli'
        artifact = output / (prefix + ('.zip' if system == 'windows' else '.tar.gz'))
        if system == 'windows':
            with zipfile.ZipFile(artifact, 'w', zipfile.ZIP_DEFLATED) as archive:
                for name, data in files.items():
                    archive.writestr(prefix + '/' + name, data)
        else:
            with tarfile.open(artifact, 'w:gz') as archive:
                for name, data in files.items():
                    info = tarfile.TarInfo(prefix + '/' + name)
                    info.size = len(data)
                    info.mode = 0o755 if name.endswith('.sh') else 0o644
                    archive.addfile(info, io.BytesIO(data))
        artifacts.append(artifact)
    (output / 'SHA256SUMS.txt').write_text(''.join(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n'
                                                  for path in artifacts), encoding='utf-8')
    return artifacts


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT.parent / 'outputs' / 'cli-releases')
    parser.add_argument('--version', default=VERSION, help='CLI 发布版本 major.minor.patch')
    args = parser.parse_args()
    for path in build(args.output, args.version):
        print(path)
