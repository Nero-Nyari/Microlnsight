"""History coverage and resumability, using synthetic logs and mocked inference."""
from contextlib import nullcontext, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('history_analysis', REPO / 'Microlnsight/history_analysis.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def record(cursor, stamp, message='unrecognized message retained'):
    return {'__CURSOR': cursor, '__REALTIME_TIMESTAMP': str(stamp), 'MESSAGE': message}


def answer(rows):
    return {'reviewed_refs': [r['ref'] for r in rows], 'summary': '观察到会话记录。',
            'observations': [{'text': '会话消息。', 'refs': [rows[0]['ref']]}],
            'concerns': [], 'limitations': '账户授权尚未确认。'}


class HistoryTests(unittest.TestCase):
    def setUp(self):
        output = REPO / 'outputs'
        output.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=output, prefix='history-test-')
        self.root = Path(self.temp.name).resolve()
        assert self.root.is_relative_to(output.resolve())
        self.addCleanup(self.temp.cleanup)
        self.raw = self.root / 'raw'
        self.raw.mkdir()

    def write(self, name, rows):
        (self.raw / name).write_text(''.join(json.dumps(r) + '\n' for r in rows), encoding='utf-8')

    def test_time_boundaries_dedup_unknown_and_invalid(self):
        self.write('one.jsonl', [record('early', 9), record('a', 10), record('b', 19), record('end', 20)])
        self.write('two.jsonl', [record('a', 10), {'MESSAGE': 'missing timestamp'}])
        rows, audit = h.collect(self.raw, 10, 20)
        self.assertEqual([r['raw']['__CURSOR'] for r in rows], ['a', 'b'])
        self.assertEqual(audit['duplicates_removed'], 1)
        self.assertEqual(len(audit['invalid_records']), 1)

    def test_conflicting_cursor_stops(self):
        self.write('one.jsonl', [record('same', 10), record('same', 11)])
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            h.collect(self.raw, 0, 20)

    def test_timezone_required(self):
        with self.assertRaises(ValueError):
            h.micros('2026-10-16T16:35:00')
        self.assertEqual(h.micros('2026-10-16T16:35:00+08:00'), h.micros('2026-10-16T08:35:00+00:00'))

    def test_partition_no_drop_or_truncation(self):
        rows = [{'ref': f'ssh:{i}', 'message': '消息' * 12} for i in range(100)]
        groups = h.batches(rows, max_records=7, max_bytes=700)
        self.assertEqual([r for group in groups for r in group], rows)
        self.assertTrue(all(len(group) <= 7 and len(h.encoded(group)) <= 700 for group in groups))
        with self.assertRaisesRegex(ValueError, 'no message was truncated'):
            h.batches([{'ref': 'ssh:1', 'message': 'x' * 1000}], max_bytes=100)

    def test_reply_coverage_and_claim_guard(self):
        rows = [{'ref': 'ssh:1'}, {'ref': 'ssh:2'}]
        valid = answer(rows)
        h.validate_reply(valid, rows)
        bad = {**valid, 'reviewed_refs': ['ssh:1']}
        with self.assertRaisesRegex(ValueError, 'reviewed_refs'):
            h.validate_reply(bad, rows)
        bad = {**valid, 'observations': [{'text': '虚构', 'refs': ['ssh:999']}]}
        with self.assertRaisesRegex(ValueError, 'reference'):
            h.validate_reply(bad, rows)
        with self.assertRaisesRegex(ValueError, 'safety'):
            h.validate_reply({**valid, 'summary': '其余活动正常。'}, rows)
        h.validate_reply({**valid, 'summary': '不能推断其余活动正常。'}, rows)
        h.validate_reply({**valid, 'limitations': '未提供主机整体安全状态信息。'}, rows)
        h.validate_reply({**valid, 'limitations': '未掌握主机整体安全策略及用户权限配置。'}, rows)
        with self.assertRaisesRegex(ValueError, 'safety'):
            h.validate_reply({**valid, 'summary': '未提供主机整体安全状态信息但其余活动正常。'}, rows)
        with self.assertRaisesRegex(ValueError, 'safety'):
            h.validate_reply({**valid, 'summary': '未掌握主机整体安全策略但其余活动正常。'}, rows)

    def prepared(self):
        start = '2026-10-15T00:00:00+08:00'
        self.write('one.jsonl', [record(str(i), h.micros(start) + i) for i in range(41)])
        args = SimpleNamespace(raw=self.raw, output=self.root / 'report', start=start,
                               end='2026-10-16T16:36:00+08:00', source='synthetic')
        with redirect_stdout(io.StringIO()):
            h.prepare(args)
        return SimpleNamespace(output=args.output, model_url='http://127.0.0.1:11434', model='test', allow_model_send=True)

    def test_success_and_resume_never_resend(self):
        args = self.prepared()
        with patch.object(h, 'run_lock', return_value=nullcontext()), patch.object(h, 'request_model', side_effect=lambda u, m, r, **kw: (answer(r), {})) as model, redirect_stdout(io.StringIO()):
            self.assertEqual(h.run(args), 0)
            self.assertEqual(model.call_count, 2)
            self.assertEqual(h.run(args), 0)
            self.assertEqual(model.call_count, 2)
        status = json.loads((args.output / 'status.json').read_bytes())
        self.assertEqual(status['accepted_records'], 41)
        self.assertTrue(status['completed'])

    def test_failed_batches_counted_and_retries_bounded(self):
        args = self.prepared()
        with patch.object(h, 'run_lock', return_value=nullcontext()), patch.object(h, 'request_model', side_effect=TimeoutError('timeout')) as model, redirect_stdout(io.StringIO()):
            self.assertEqual(h.run(args), 2)
            self.assertEqual(model.call_count, 4)
        status = json.loads((args.output / 'status.json').read_bytes())
        self.assertEqual(status['accepted_records'], 0)
        self.assertFalse(status['completed'])
        with patch.object(h, 'run_lock', return_value=nullcontext()), patch.object(h, 'request_model', side_effect=lambda u, m, r, **kw: (answer(r), {})) as model, redirect_stdout(io.StringIO()):
            self.assertEqual(h.run(args), 0)
            self.assertTrue(all(call.kwargs['feedback'] for call in model.call_args_list))
        result = json.loads((args.output / 'results/0001.json').read_bytes())
        self.assertEqual(len(result['attempts']), 3)

    def test_no_authorization_no_request(self):
        args = self.prepared()
        args.allow_model_send = False
        with patch.object(h, 'request_model') as model, self.assertRaises(ValueError):
            h.run(args)
        model.assert_not_called()

    def test_missing_information_revalidation_preserves_attempt(self):
        args = self.prepared()
        with patch.object(h, 'run_lock', return_value=nullcontext()), patch.object(h, 'request_model', side_effect=lambda u, m, r, **kw: (answer(r), {})), redirect_stdout(io.StringIO()):
            h.run(args)
        path = args.output / 'results/0001.json'
        result = json.loads(path.read_bytes())
        previous = result.pop('answer')
        previous['limitations'] = '未提供主机整体安全状态信息。'
        result.update(status='failed', attempts=[{'answer': previous, 'error': 'Unsupported general safety claim'}])
        h.save(path, result)
        with patch.object(h, 'run_lock', return_value=nullcontext()), patch.object(h, 'request_model') as model, redirect_stdout(io.StringIO()):
            self.assertEqual(h.run(args), 0)
            model.assert_not_called()
        restored = json.loads(path.read_bytes())
        self.assertEqual(restored['answer'], previous)
        self.assertEqual(restored['attempts'][0]['error'], 'Unsupported general safety claim')
        self.assertIn('revalidation', restored)

    def test_output_limit_splits_without_dropping_records(self):
        args = self.prepared()
        def inference(url, model, rows, **kw):
            if len(rows) > 20:
                raise ValueError('Model response incomplete: length')
            return answer(rows), {}
        with patch.object(h, 'run_lock', return_value=nullcontext()), patch.object(h, 'request_model', side_effect=inference) as model, redirect_stdout(io.StringIO()):
            self.assertEqual(h.run(args), 0)
            self.assertEqual(model.call_count, 5)
            self.assertEqual(h.run(args), 0)
            self.assertEqual(model.call_count, 5)
        result = json.loads((args.output / 'results/0001.json').read_bytes())
        self.assertEqual(len(result['parts']), 2)
        self.assertEqual(len(result['answer']['reviewed_refs']), 40)
        self.assertEqual(len(result['attempts']), 2)

    def test_split_resume_keeps_success_and_failed_attempts(self):
        args = self.prepared()
        def incomplete(url, model, rows, **kw):
            if len(rows) > 20:
                raise ValueError('Model response incomplete: length')
            if rows[0]['ref'] == 'ssh:21':
                raise ValueError('Incomplete or reordered reviewed_refs')
            return answer(rows), {}
        with patch.object(h, 'run_lock', return_value=nullcontext()), patch.object(h, 'request_model', side_effect=incomplete), redirect_stdout(io.StringIO()):
            self.assertEqual(h.run(args), 2)
        with patch.object(h, 'run_lock', return_value=nullcontext()), patch.object(h, 'request_model', side_effect=lambda u, m, r, **kw: (answer(r), {})) as model, redirect_stdout(io.StringIO()):
            self.assertEqual(h.run(args), 0)
            self.assertEqual(model.call_count, 1)
        result = json.loads((args.output / 'results/0001.json').read_bytes())
        self.assertEqual(len(result['parts'][0]['attempts']), 1)
        self.assertEqual(len(result['parts'][1]['attempts']), 3)


if __name__ == '__main__':
    unittest.main()
