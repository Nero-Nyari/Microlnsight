"""Collection provenance, legacy honesty, and matching CLI/export/model scope."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import guard
import guard_cli
import guard_models
from terminal_ui import Cancelled


class ScopeDetailsTests(unittest.TestCase):
    def lines(self):
        row = dict(_COMM='sshd', _HOSTNAME='host', __REALTIME_TIMESTAMP='1791770400000000',
                   MESSAGE='Failed password for alice from 192.0.2.1 port 4000 ssh2')
        return '\n'.join([json.dumps(row),
            json.dumps({**row, 'MESSAGE': 'Unrecognized diagnostic message'}),
            json.dumps({**row, '_HOSTNAME': ''}),
            json.dumps({**row, '_COMM': 'webapp'}), '{bad json'])

    def collect(self, limit=5, stderr=b''):
        with patch('guard.subprocess.run', return_value=Mock(returncode=0, stdout=self.lines().encode(), stderr=stderr)):
            return guard.collect_linux(minutes=15, limit=limit)

    def test_rejected_categories_limit_and_warning_are_independent(self):
        collection = self.collect()
        result = guard.detect(collection)
        self.assertEqual(result['coverage']['excluded_reasons'],
                         dict(unsupported=1, missing_metadata=1, unknown_source=1, invalid=1))
        self.assertEqual(sum(result['coverage'][k] for k in ('retained','excluded','duplicates','conflicts')), 5)
        codes = {r['code'] for r in guard.task_scope(result)['reasons']}
        self.assertEqual(codes, {'collection_limit','unsupported','missing_metadata','unknown_source','invalid'})
        warning = guard.task_scope(guard.detect(self.collect(limit=6, stderr=b'No journal files were found.')))
        self.assertIn('collection_warning', {r['code'] for r in warning['reasons']})
        self.assertNotIn('collection_limit', {r['code'] for r in warning['reasons']})
        self.assertTrue(all(r['count'] is None for r in warning['reasons'] if r['code'] == 'collection_warning'))

    def test_duplicate_only_is_complete_but_conflicts_are_explained(self):
        event = guard.demo_events('linux')['events'][0]
        duplicate = guard.detect(dict(events=[event, deepcopy(event)], rejected=0))
        self.assertFalse(guard.task_scope(duplicate)['incomplete'])
        conflict = guard.detect(dict(events=[event, {**event, 'account': 'other'}], rejected=0))
        scope = guard.task_scope(conflict)
        self.assertEqual(scope['reasons'][0]['code'], 'conflicting_records')
        self.assertEqual(scope['reasons'][0]['count'], 2)

    def test_historical_exclusions_do_not_become_unsupported_or_permission_errors(self):
        task = dict(coverage=dict(input=1000, retained=173, excluded=827, duplicates=0,
                                  conflicts=0, scope_incomplete=True),
                    warnings=['达到采集上限；更早记录可能未读取，未读数量未知'])
        before = deepcopy(task)
        scope = guard.task_scope(task)
        self.assertEqual([r['code'] for r in scope['reasons']], ['collection_limit', 'excluded_unknown'])
        self.assertIn('827', scope['reasons'][1]['label'])
        self.assertEqual(task, before)
        task['warnings'] = []
        task['coverage']['scope_incomplete'] = False
        self.assertEqual([r['code'] for r in guard.task_scope(task)['reasons']], ['excluded_unknown'])
        self.assertIn('coverage_unknown', [r['code'] for r in guard.task_scope({})['reasons']])

    def test_saved_task_cli_export_and_model_share_scope_without_rewriting_history(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend/data') as temp:
            store, profiles = guard_cli.resources(Path(temp) / 'agent.db')
            task = guard.run_task(store, 'linux-local', self.collect)
            saved = store.get(task['id'])
            scope = guard.task_scope(saved)
            exported = Path(temp) / 'report.json'
            with patch('guard_cli.choice', side_effect=['3', Cancelled()]), patch('guard_cli.field', return_value=exported), redirect_stdout(io.StringIO()) as output:
                guard_cli.task_detail(store, profiles, saved)
            report = json.loads(exported.read_text(encoding='utf-8'))
            self.assertEqual(report['analysis_scope'], scope)
            self.assertEqual(guard_models.context(saved)['analysis_scope'], scope)
            self.assertEqual(store.get(task['id']), saved)
            # Terminal wrapping may split the longer authentication/activity summary.
            self.assertIn(''.join(scope['summary'].split()), ''.join(output.getvalue().split()))
            for reason in scope['reasons']:
                self.assertIn(reason['label'], output.getvalue())
            self.assertIn('未读数量未知', json.dumps(report, ensure_ascii=False))

    def test_collection_failure_keeps_error_and_never_reports_zero_read_as_success(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend/data') as temp:
            store = guard.TaskStore(Path(temp) / 'tasks.db')
            with self.assertRaisesRegex(RuntimeError, 'Permission denied'):
                guard.run_task(store, 'linux-local', Mock(side_effect=RuntimeError('Permission denied')))
            task = store.recent()[0]
            self.assertEqual(task['error'], 'Permission denied')
            scope = guard_models.context(task)['analysis_scope']
            self.assertEqual(scope['reasons'][0]['code'], 'collection_failed')
            self.assertNotIn('已读取 0', scope['summary'])

    def test_windows_exclusions_are_classified_without_changing_eligibility(self):
        event = dict(EventID=4625, Channel='Security', Computer='host', RecordId=1,
                     TimeCreated='2026-10-12T02:00:00Z', EventData=dict(TargetUserName='alice', IpAddress='192.0.2.1'))
        reasons = {}
        events, rejected = guard.windows_events([event, {**event, 'Channel': 'Application'},
            {**event, 'EventID': 9999}, {**event, 'RecordId': None}], reasons)
        self.assertEqual(len(events), 1)
        self.assertEqual(rejected, 3)
        self.assertEqual(reasons, dict(unknown_source=1, unsupported=1, missing_metadata=1))


if __name__ == '__main__':
    unittest.main()
