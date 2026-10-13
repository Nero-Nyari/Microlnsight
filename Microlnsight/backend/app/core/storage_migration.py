"""Offline brand migration. Never overwrite a destination or delete old data."""
from contextlib import closing
from pathlib import Path
import os
import sqlite3
import tempfile

DATABASE_NAME = 'microlnsight.db'
LEGACY_DATABASE_NAME = 'winsecagent.db'
COLLECTION_NAME = 'microlnsight_knowledge'
LEGACY_COLLECTION_NAME = 'winsec_knowledge'


class MigrationRequired(RuntimeError):
    pass


def default_database(directory):
    directory = Path(directory)
    current = directory / DATABASE_NAME
    if not current.exists() and (directory / LEGACY_DATABASE_NAME).exists():
        raise MigrationRequired('发现旧数据库。请停止旧服务后执行 python migrate_branding.py；'
                           '迁移会保留原库，不会创建空库替代历史数据。')
    return current


def migrate_database(directory):
    """Copy a consistent SQLite snapshot including WAL; retain source as backup.

    Operator must stop old services first. BEGIN IMMEDIATE excludes writers
    during the snapshot, but cannot prevent an old service restarting later.
    """
    directory = Path(directory).resolve()
    source = directory / LEGACY_DATABASE_NAME
    target = directory / DATABASE_NAME
    if target.exists():
        raise FileExistsError('新数据库已存在，拒绝覆盖；请核对迁移状态')
    if not source.is_file() or source.is_symlink():
        raise ValueError('未找到普通旧数据库文件，未执行迁移')
    descriptor, name = tempfile.mkstemp(prefix='.microlnsight-migration-', suffix='.db', dir=directory)
    os.close(descriptor)
    temporary = Path(name)
    try:
        with closing(sqlite3.connect(source.as_uri() + '?mode=rw', uri=True, timeout=1)) as lock:
            lock.execute('BEGIN IMMEDIATE')
            try:
                # A second read connection sees committed WAL data while the
                # first connection prevents new writes for the whole snapshot.
                with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as reader:
                    with closing(sqlite3.connect(temporary)) as copy:
                        reader.backup(copy)
                        if copy.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                            raise ValueError('数据库完整性检查失败，未启用新数据库')
                # Publish atomically without overwriting a concurrent target.
                # Windows rename refuses existing destinations; POSIX rename
                # overwrites, so use a same-filesystem hard link there instead.
                if os.name == 'nt':
                    os.rename(temporary, target)
                else:
                    os.link(temporary, target)
            finally:
                lock.rollback()
    finally:
        temporary.unlink(missing_ok=True)
    return target


def migrate_collection(client):
    """Rename the existing collection in place, preserving documents/embeddings."""
    names = {item if isinstance(item, str) else item.name for item in client.list_collections()}
    if LEGACY_COLLECTION_NAME in names:
        if COLLECTION_NAME in names:
            raise ValueError('新旧知识库集合同时存在，拒绝覆盖或自动合并')
        client.get_collection(name=LEGACY_COLLECTION_NAME).modify(name=COLLECTION_NAME)
        return True
    return False
