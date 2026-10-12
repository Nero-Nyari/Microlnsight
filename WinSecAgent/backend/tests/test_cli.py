"""Exercise the terminal workflow against a disposable database."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CLI = Path(__file__).resolve().parents[2] / "cli.py"
TEST_DATA = CLI.parent / "backend" / "data"


class CliTests(unittest.TestCase):
    def test_batch_limit_duplicates_and_collection_gaps_are_visible(self):
        with tempfile.TemporaryDirectory(dir=TEST_DATA) as directory:
            run = subprocess.run([sys.executable, '-X', 'utf8', '-c', '''
import cli, json, sys
from unittest.mock import patch
cli._prepare_database(cli.Path(sys.argv[1]))
from app.cases.demo_cases import get_demo_case
from app.agents.report_agent import correlation_report
events = [json.loads(raw) for raw in get_demo_case('windows_demo_sequence')['records']]
with cli._session() as db:
    ids = cli.import_logs(db, {'events': events})
    collection = {'requested_max_events': 6, 'channel_results': [
        {'channel': 'Security', 'status': 'success', 'events_read': 6},
        {'channel': 'System', 'status': 'failed', 'events_read': 0, 'message': '权限不足'}]}
    with patch('app.services.correlation.MAX_CANDIDATES', 3):
        result = cli.batch_analyze(db, ids, collection=collection)
    assert result['coverage']['selected_total'] == 6
    assert result['coverage']['skipped_limit'] == 3
    assert result['coverage']['input_records'] == 3
    report = correlation_report('sample', result)
    assert '超限跳过 3 条' in report
    assert '权限不足' in report
    assert '未读数量未知' in report
    cli.import_logs(db, {'events': events})
    result = cli.batch_analyze(db)
    assert result['coverage']['duplicates'] == 6
    assert result['findings'][0]['failure_count'] == 5
''', str(Path(directory) / 'isolated.db')], cwd=CLI.parent, capture_output=True,
                                 text=True, encoding='utf-8', timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn('来源时间（UTC）', run.stdout)
            self.assertIn('重复排除 6 条', run.stdout)

    def run_cli(self, database: Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-X", "utf8", str(CLI), "--database", str(database), *args],
            capture_output=True, text=True, encoding="utf-8", timeout=30,
        )

    def test_demo_analysis_and_report_without_web_server(self):
        with tempfile.TemporaryDirectory(dir=TEST_DATA) as directory:
            database = Path(directory) / "preview.db"
            demo = self.run_cli(database, "demo", "windows_demo_sequence")
            self.assertEqual(demo.returncode, 0, demo.stderr)
            self.assertIn("发现异常线索", demo.stdout)
            self.assertIn("5 条去重后的 4625", demo.stdout)
            listing = self.run_cli(database, "list")
            self.assertEqual(listing.returncode, 0, listing.stderr)
            self.assertIn("#6", listing.stdout)
            output = Path(directory) / "report.md"
            report = self.run_cli(database, "report", "6", "--output", str(output))
            self.assertEqual(report.returncode, 0, report.stderr)
            content = output.read_text(encoding="utf-8")
            self.assertIn("本地联合分析", content)
            self.assertIn("4625", content)
            self.assertIn("4624", content)
            quoted_base = Path(directory) / "quoted-report"
            menu = subprocess.run(
                [sys.executable, "-X", "utf8", str(CLI), "--database", str(database)],
                input=f'5\n6\n"{quoted_base}"\n0\n', capture_output=True, text=True,
                encoding="utf-8", timeout=30,
            )
            self.assertEqual(menu.returncode, 0, menu.stderr)
            self.assertNotIn("操作失败", menu.stdout)
            self.assertTrue(quoted_base.with_suffix(".md").is_file())

    def test_single_failure_remains_unconfirmed(self):
        with tempfile.TemporaryDirectory(dir=TEST_DATA) as directory:
            demo = self.run_cli(Path(directory) / "preview.db", "demo", "windows_demo_single")
            self.assertEqual(demo.returncode, 0, demo.stderr)
            self.assertIn("证据不足", demo.stdout)
            self.assertNotIn("发现异常线索", demo.stdout)

    def test_batch_analysis_explains_event_ids_without_selecting_each_record(self):
        with tempfile.TemporaryDirectory(dir=TEST_DATA) as directory:
            database = Path(directory) / "preview.db"
            # Use isolated synthetic rows; no Windows log or real user data is read.
            seed = subprocess.run(
                [sys.executable, "-X", "utf8", "-c", """
import json, sys
import cli
cli._prepare_database(cli.Path(sys.argv[1]))
from app.cases.demo_cases import get_demo_case
events = [json.loads(raw) for raw in get_demo_case('windows_demo_sequence')['records']]
for event in events:
    event['IsDemo'] = False
with cli._session() as db:
    ids = cli.import_logs(db, {'events': events})
    cli.batch_analyze(db, ids)
""", str(database)],
                cwd=CLI.parent, capture_output=True, text=True, encoding="utf-8", timeout=30,
            )
            self.assertEqual(seed.returncode, 0, seed.stderr)
            self.assertIn("账户登录失败（4625，Security）：5 条", seed.stdout)
            self.assertIn("账户登录成功（4624，Security）：1 条", seed.stdout)
            self.assertIn("发现异常线索", seed.stdout)
            listing = self.run_cli(database, "list")
            self.assertIn("记录列表", listing.stdout)
            self.assertIn("账户登录失败（4625）", listing.stdout)
            output = Path(directory) / "batch.md"
            batch = self.run_cli(database, "batch", "--output", str(output))
            self.assertEqual(batch.returncode, 0, batch.stderr)
            self.assertIn("发现异常线索", batch.stdout)
            report = output.read_text(encoding="utf-8")
            self.assertIn("范围：本次选取的已导入日志", report)
            self.assertIn("原始证据快照", report)

    def test_unknown_event_preview_uses_source_and_message(self):
        preview = subprocess.run(
            [sys.executable, "-X", "utf8", "-c", """
import cli
cli._show_event_summary([{'Channel': 'Application', 'EventID': 9001,
                          'ProviderName': 'SampleProvider', 'Message': 'Service restarted successfully'},
                         {'Channel': 'Security', 'EventID': 5379,
                          'ProviderName': 'Microsoft-Windows-Security-Auditing'}])
"""], cwd=CLI.parent, capture_output=True, text=True, encoding="utf-8", timeout=30,
        )
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertIn("未收录的事件类型", preview.stdout)
        self.assertIn("来源：SampleProvider", preview.stdout)
        self.assertIn("日志摘录：Service restarted successfully", preview.stdout)
        self.assertIn("凭据管理器中的保存凭据被读取（5379，Security）", preview.stdout)

    def test_overview_filters_detail_and_report_preview(self):
        with tempfile.TemporaryDirectory(dir=TEST_DATA) as directory:
            database = Path(directory) / "preview.db"
            view = subprocess.run(
                [sys.executable, "-X", "utf8", "-c", """
import cli, sys
cli._prepare_database(cli.Path(sys.argv[1]))
with cli._session() as db:
    cli.load_demo(db, 'windows_demo_sequence')
    cli.show_overview(db)
    cli.list_records(db, filters=cli.RecordFilters(since='2026-10-02', until='2026-10-02', source='Security', event='4625', conclusion='待分析'))
    cli.show_record_detail(db, 6, raw=True)
    cli.preview_report(db, 6, lines=8)
""", str(database)], cwd=CLI.parent, capture_output=True, text=True,
                encoding="utf-8", timeout=30,
            )
            self.assertEqual(view.returncode, 0, view.stderr)
            self.assertIn("首页总览", view.stdout)
            self.assertIn("匹配 5 条", view.stdout)
            self.assertIn("线索", view.stdout)
            self.assertIn("原始日志", view.stdout)
            self.assertIn("报告预览", view.stdout)
            self.assertIn("还有", view.stdout)

    def test_server_task_keeps_menu_thread_free_and_raw_text_is_safe(self):
        with tempfile.TemporaryDirectory(dir=TEST_DATA) as directory:
            run = subprocess.run(
                [sys.executable, "-X", "utf8", "-c", """
import cli, sys, threading
from unittest.mock import patch
root = cli.Path(sys.argv[1]); source = root / 'source'; source.mkdir()
(source / 'ssh.journal.log').write_text('2026-10-12T10:00:00+08:00 host sshd[1]: Failed password for root from 192.0.2.10 port 5000 ssh2\\n', encoding='utf-8')
output = root / 'report.md'; entered = threading.Event(); release = threading.Event()
original = cli._save_server_analysis
def delayed(src, dest):
    entered.set(); release.wait(5)
    return original(src, dest)
with patch('cli._save_server_analysis', delayed):
    jobs = cli.ServerJobs()
    try:
        jobs.start(source, output)
        assert entered.wait(2)
        assert not jobs.current.future.done()
        jobs.status()
    finally:
        release.set(); jobs.close()
assert output.is_file()
cli._wrap('raw: \\x1b[31mred')
""", directory], cwd=CLI.parent, capture_output=True, text=True,
                encoding="utf-8", timeout=30,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("正在分析", run.stdout)
            self.assertIn("报告已保存", run.stdout)
            self.assertIn(r"\x1b", run.stdout)
            self.assertNotIn("\x1b", run.stdout)


if __name__ == "__main__":
    unittest.main()
