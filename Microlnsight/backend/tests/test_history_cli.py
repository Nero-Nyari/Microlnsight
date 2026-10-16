"""Exercise the report workflow against synthetic archives, without network."""
from contextlib import redirect_stdout
from datetime import datetime
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import history_cli as ui
import history_analysis as engine
from guard_models import Profiles
from terminal_ui import Cancelled


def answer(rows):
    return dict(reviewed_refs=[r['ref'] for r in rows], summary='观察到会话消息。',
                observations=[dict(text='保留的会话记录。', refs=[rows[0]['ref']])],
                concerns=[], limitations='账户授权尚未确认。')


class ReportWorkflowTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT.parent / 'outputs'
        parent.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=parent, prefix='report-test-')
        assert Path(self.temp.name).resolve().is_relative_to(parent.resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / 'data'
        self.raw = self.root / 'collector' / 'raw'
        self.raw.mkdir(parents=True)
        stamp = engine.micros('2026-10-16T16:35:00+08:00')
        records = [dict(__CURSOR=str(i), __REALTIME_TIMESTAMP=str(stamp + i * 1000),
                        MESSAGE='session message ' + str(i)) for i in range(41)]
        records += [dict(__CURSOR='outside', __REALTIME_TIMESTAMP=str(stamp + 60_000_000), MESSAGE='excluded boundary')]
        (self.raw / 'one.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in records), encoding='utf-8')
        self.profiles = Profiles(self.data / 'agent.guard' / 'models.json')
        self.profiles.put('local', dict(kind='ollama', base_url='http://127.0.0.1:11434', model='synthetic'))
        self.entries = [{'label': 'remote-ssh:test', 'raw': str(self.raw)}]

    def start_inputs(self, decision):
        return ['1', '1', '+08:00', '2026-10-16 16:35', '2026-10-16 16:35', decision]

    def test_full_workflow_and_scoped_followup(self):
        replies = self.start_inputs('1') + ['1', '1', 'e', 'a', '解释本批会话', '1', 'h', '0', '0', '0']
        output = io.StringIO()
        with patch.object(ui, 'sources', return_value=self.entries), patch('terminal_ui.read_line', side_effect=replies), \
                patch.object(engine, 'request_model', side_effect=lambda u, m, r, **kw: (answer(r), {})) as model, redirect_stdout(output):
            ui.menu(self.data, self.profiles)
        calls = model.call_args_list
        self.assertEqual([len(c.args[2]) for c in calls], [40, 1, 40])
        self.assertEqual(calls[-1].kwargs['question'], '解释本批会话')
        self.assertNotIn('excluded boundary', str(calls))
        report = next((self.data / 'history-analysis').iterdir())
        self.assertTrue(ui.read(report / 'status.json')['completed'])
        self.assertEqual(ui.read(report / 'manifest.json')['record_count'], 41)
        self.assertEqual(len(list((report / 'questions').glob('*.json'))), 1)
        self.assertIn('仅发送本批 40 条', output.getvalue())
        self.assertIn('已保存的本地模型回答', output.getvalue())

    def test_prepare_without_send_and_reopen(self):
        with patch.object(ui, 'sources', return_value=self.entries), \
                patch('terminal_ui.read_line', side_effect=self.start_inputs('2') + ['0', '0']), \
                patch.object(engine, 'request_model') as model, redirect_stdout(io.StringIO()):
            ui.menu(self.data, self.profiles)
        model.assert_not_called()
        found = ui.reports(self.data, self.root / 'cli')
        self.assertEqual(len(found), 1)
        self.assertFalse((found[0][0] / 'destination.json').exists())
        with patch('terminal_ui.read_line', side_effect=['2', '1', '4', '0', '0']), \
                patch.object(engine, 'request_model') as model, redirect_stdout(io.StringIO()):
            ui.menu(self.data, self.profiles)
        model.assert_not_called()

    def test_collector_discovery_and_legacy_reports(self):
        (self.raw.parent / 'config.json').write_text(json.dumps(dict(source_label='remote-ssh:test', private_key='must-not-display')))
        items = ui.sources(self.data, self.root / 'cli')
        self.assertEqual(items, self.entries)
        self.assertNotIn('private_key', str(items))
        legacy = self.root / 'history-analysis' / 'old-report'
        with redirect_stdout(io.StringIO()):
            engine.prepare(SimpleNamespace(raw=self.raw, output=legacy, source='legacy',
                start='2026-10-16T16:35:00+08:00', end='2026-10-16T16:36:00+08:00'))
        self.assertEqual(ui.reports(self.data, self.root / 'cli')[0][0], legacy)

    def test_timezone_and_inclusive_minute(self):
        first, end = ui.interval('2026-10-15 23:59', '2026-10-16 16:35', '+08:00')
        self.assertEqual(end, '2026-10-16T16:36:00+08:00')
        self.assertEqual(datetime.fromisoformat(first).hour, 23)
        with self.assertRaises(ValueError):
            ui.interval('2026-10-16 16:35', '2026-10-15 00:00', '+08:00')
        with self.assertRaises(ValueError):
            ui.offset('+14:30')

    def prepare(self):
        out = self.root / 'report'
        with redirect_stdout(io.StringIO()):
            engine.prepare(SimpleNamespace(raw=self.raw, output=out, source='test',
                start='2026-10-16T16:35:00+08:00', end='2026-10-16T16:36:00+08:00'))
        return SimpleNamespace(output=out, model_url='http://127.0.0.1:11434', model='synthetic', allow_model_send=True)

    def test_cancel_after_request_retains_completed_batch_and_resume(self):
        args = self.prepare()
        stop = threading.Event()
        def checkpoint():
            if stop.is_set():
                raise Cancelled()
        def infer(u, m, rows, **kw):
            stop.set()
            return answer(rows), {}
        with patch.object(engine, 'request_model', side_effect=infer) as model, redirect_stdout(io.StringIO()):
            with self.assertRaises(Cancelled):
                engine.run(args, checkpoint=checkpoint)
        self.assertEqual(model.call_count, 1)
        self.assertEqual(ui.read(args.output / 'status.json')['accepted_records'], 40)
        with patch.object(engine, 'request_model', side_effect=lambda u, m, r, **kw: (answer(r), {})) as model, redirect_stdout(io.StringIO()):
            self.assertEqual(engine.run(args), 0)
        self.assertEqual(model.call_count, 1)
        self.assertEqual(len(model.call_args.args[2]), 1)

    def test_changed_later_batch_stops_before_any_send(self):
        args = self.prepare()
        engine.save(args.output / 'inputs' / '0002.json', [])
        with patch.object(engine, 'request_model') as model:
            with self.assertRaisesRegex(ValueError, 'Batch input changed'):
                engine.run(args)
        model.assert_not_called()

    def test_resuming_uses_bound_destination_and_rejects_cloud_profile(self):
        args = self.prepare()
        self.profiles.put('cloud', dict(kind='openai', base_url='https://example.com', model='cloud'))
        with self.assertRaisesRegex(ValueError, 'Ollama'):
            ui.model_target(self.profiles, args.output)
        engine.save(args.output / 'destination.json', dict(url=args.model_url, model=args.model))
        self.assertEqual(ui.model_target(self.profiles, args.output), (args.model_url, args.model))

    def test_lock_excludes_concurrent_analysis(self):
        with engine.run_lock(self.root / '.lock'):
            with self.assertRaises(OSError):
                with engine.run_lock(self.root / '.lock'):
                    self.fail('second writer acquired lock')


if __name__ == '__main__':
    unittest.main()
