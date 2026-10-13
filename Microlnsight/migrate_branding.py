"""Migrate legacy web-workbench data after stopping all old services."""
import argparse
import sqlite3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'backend'))
from app.core.storage_migration import migrate_collection, migrate_database


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database-dir', type=Path, default=ROOT / 'backend' / 'data')
    parser.add_argument('--knowledge-dir', type=Path,
                        help='只迁移指定 Chroma 知识库；不迁移 SQLite')
    args = parser.parse_args()
    if args.knowledge_dir:
        directory = args.knowledge_dir.resolve()
        if not directory.is_dir():
            raise ValueError('知识库目录不存在')
        import chromadb
        from chromadb.config import Settings
        client = chromadb.Client(Settings(chroma_db_impl='duckdb+parquet',
            persist_directory=str(directory), anonymized_telemetry=False))
        changed = migrate_collection(client)
        if changed and hasattr(client, 'persist'):
            client.persist()
        print('知识库集合已更名。' if changed else '未发现需要迁移的旧集合。')
    else:
        path = migrate_database(args.database_dir)
        print(f'数据库迁移完成：{path}。旧库保留作备份；请勿再启动旧服务。')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, ImportError, sqlite3.Error) as exc:
        print(f'迁移未完成：{exc}', file=sys.stderr)
        raise SystemExit(1)
