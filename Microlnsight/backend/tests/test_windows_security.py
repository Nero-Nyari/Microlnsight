"""Security audit semantics, bounded collection and evidence-only policy contracts."""
from copy import deepcopy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import guard
import guard_models
import windows_security as security


def row(eid, record=1, **data):
    fields = dict(SubjectUserName='actor', SubjectDomainName='LAB', SubjectUserSid='S-1-5-18',
                  SubjectLogonId='0x123', TargetUserName='target', TargetDomainName='LAB',
                  TargetUserSid='S-1-5-21-123', TargetLogonId='0x123',
                  IpAddress='-', PrivilegeList='SeDebugPrivilege', GroupMembership='S-1-5-32-544',
                  CallerProcessName=r'C:\Windows\System32\test.exe', Operation='%%2480',
                  ReadOperation='%%8100', ReturnCode='0x0')
    fields.update(data)
    return dict(EventID=eid, Channel='Security', Computer='WIN-TEST', RecordId=record,
                TimeCreated='2026-10-14T06:00:00Z', EventData=fields)


def analyze(rows):
    reasons, diagnostics = {}, {}
    events, rejected = guard.windows_events(rows, reasons, diagnostics)
    return guard.detect(dict(events=events, rejected=rejected, rejected_reasons=reasons,
                             windows_diagnostics=diagnostics))


class WindowsSecurityTests(unittest.TestCase):
    def test_all_seven_types_preserve_actor_target_and_do_not_become_logins(self):
        result = analyze([row(eid, i + 1) for i, eid in enumerate(security.AUDIT_IDS)])
        self.assertEqual(result['coverage']['retained'], 7)
        self.assertEqual(result['coverage']['excluded'], 0)
        self.assertEqual(result['coverage']['retained_without_ip'], 0)
        self.assertEqual(result['coverage']['security_audit_retained'], 7)
        self.assertEqual(result['assessment']['status'], 'no_findings')
        self.assertEqual(result['findings'], [])
        for event in result['events']:
            self.assertNotIn(event['kind'], ('success', 'failure'))
            self.assertEqual(event['source_ip_status'], 'not_applicable')
            self.assertEqual(event['security']['actor_account'], 'LAB\\actor')
            self.assertEqual(event['security']['target_account'], 'LAB\\target')
            self.assertEqual(event['account'], 'LAB\\target' if event['event_id'] == '4627' else 'LAB\\actor')

    def test_bulk_credential_reads_with_nonzero_codes_are_not_attack_findings(self):
        result = analyze([row(5379, i + 1, ReturnCode='3221226021') for i in range(883)])
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['security_analysis']['event_types'][0]['return_codes'], {'nonzero': 883})
        self.assertEqual(guard.plan(result['findings']), [])

    def test_specific_review_rules_and_never_ip_actions(self):
        result = analyze([row(4672, 1, SubjectUserSid='S-1-5-21-123'),
                          row(4798, 2, CallerProcessName=r'C:\Users\actor\Downloads\tool.exe'),
                          row(4799, 3, CallerProcessName=r'C:\Users\Public\tool.exe'),
                          row(5061, 4, ReturnCode='0x80090016'), row(5058, 5, ReturnCode='5')])
        self.assertEqual(len(result['findings']), 4)
        self.assertEqual({f['rule'] for f in result['findings']},
                         {'windows_group_enumeration_review', 'windows_crypto_operation_failed'})
        self.assertEqual(guard.plan(result['findings']), [])
        forged = deepcopy(result['findings'])
        for f in forged:
            f['ip'] = '192.0.2.99'
        self.assertEqual(guard.plan(forged), [])

    def test_admin_privileges_alone_and_missing_session_are_observations(self):
        for logon_type in ('2', '3', '5', '10', None):
            login = row(4624, 1, LogonType=logon_type)
            privilege = row(4672, 2, SubjectUserSid='S-1-5-21-123')
            for rows in ([privilege], [login, privilege], [login, privilege, row(4627, 3)]):
                result = analyze(rows)
                self.assertEqual(result['findings'], [])
                context = result['security_analysis']['privilege_context']
                self.assertEqual(context['standalone_observations'], 1)
                self.assertEqual(context['correlated_auth_reviews'], 0)

    def test_privilege_review_requires_exact_login_in_failure_success_chain(self):
        failures = [row(4625, 10 + i, IpAddress='192.0.2.5') for i in range(5)]
        login = {**row(4624, 20, IpAddress='192.0.2.5'), 'TimeCreated': '2026-10-14T06:00:01Z'}
        privilege = {**row(4672, 21, SubjectUserSid='S-1-5-21-123'), 'TimeCreated': '2026-10-14T06:00:01Z'}
        result = analyze(failures + [login, privilege])
        self.assertEqual({f['rule'] for f in result['findings']}, {'auth_failure_then_success', 'windows_sensitive_privileges'})
        finding = next(f for f in result['findings'] if f['rule'] == 'windows_sensitive_privileges')
        self.assertEqual(set(finding['refs']), {f'Security:{i}' for i in (10, 11, 12, 13, 14, 20, 21)})
        self.assertEqual(result['security_analysis']['privilege_context']['correlated_auth_reviews'], 1)
        for replacement in ({'Computer': 'OTHER'}, {'TimeCreated': '2026-10-14T06:00:07Z'},
                            {'EventData': {**privilege['EventData'], 'SubjectLogonId': '0x124'}},
                            {'EventData': {**privilege['EventData'], 'SubjectUserSid': 'S-1-5-18'}}):
            other = analyze(failures + [login, {**privilege, **replacement}])
            self.assertNotIn('windows_sensitive_privileges', {f['rule'] for f in other['findings']})

    def test_model_scope_counts_full_records_separately_from_samples(self):
        result = analyze([row(5379, i + 1) for i in range(100)])
        result.update(id='scope', source='windows-local', demo=False)
        payload = guard_models.context(result)
        scope = payload['evidence_scope']
        self.assertEqual(scope['retained_records'], 100)
        self.assertEqual(scope['sent_samples'], len(payload['evidence']))
        self.assertLess(scope['sent_samples'], 100)
        self.assertEqual(scope['omitted_records'] + scope['sent_samples'], 100)
        self.assertEqual(scope['per_type'], [dict(event_type='5379', retained=100, sent_samples=len(payload['evidence']))])
        self.assertFalse(scope['authorization_verified'])
        self.assertFalse(scope['normal_activity_verified'])
        self.assertIn(str(len(payload['evidence'])), guard_models.scope_notice(payload))
        for claim in ('其余活动大多是正常系统或应用行为。', '其他活动正常。', '总体安全，没有风险。', '全部记录都正常。'):
            with self.assertRaises(guard_models.ModelError) as caught:
                guard_models.validate_grounding(claim, payload)
            self.assertEqual(caught.exception.diagnostic['code'], 'unsupported_normality_claim')
        for valid in ('当前规则和提供的证据样本未显示其他明确异常，不能据此确认正常。',
                      '不能确认其余活动正常。', '管理员正常登录也可能产生此事件。',
                      '需核对其他活动是否正常。',
                      'Security:1 返回成功，不代表凭据读取已获授权。'):
            guard_models.validate_grounding(valid, payload)
        with self.assertRaises(guard_models.ModelError) as caught:
            guard_models.validate_grounding('依据 Security:999999 发现入侵。', payload)
        self.assertEqual(caught.exception.diagnostic['code'], 'unsupported_evidence_ref')

    def test_unsupported_model_answer_is_not_saved_as_a_successful_answer(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend' / 'data') as directory:
            store = guard.TaskStore(Path(directory) / 'tasks.db')
            task = guard.run_task(store, 'demo', lambda: guard.demo_events('linux'))
            profiles = guard_models.Profiles(Path(directory) / 'models.json')
            profiles.put('local', dict(kind='ollama', base_url='http://127.0.0.1:11434', model='test'))
            with patch('guard_models.generate', return_value='其余活动大多正常。'):
                with self.assertRaises(guard_models.ModelError):
                    guard_models.ask(store, profiles, task['id'], '总结')
            self.assertEqual(store.history(task['id']), [])
            self.assertEqual(store.get(task['id'])['last_model_diagnostic']['code'], 'unsupported_normality_claim')
            with patch('guard_models.generate', return_value='当前规则发现连续失败后成功，授权仍待核实。'):
                answer = guard_models.ask(store, profiles, task['id'], '总结')
            self.assertTrue(answer.startswith('证据范围：'))
            self.assertEqual(store.history(task['id'])[-1]['content'], answer)

    def test_missing_audit_details_are_retained_and_explained(self):
        item = row(4672)
        item['EventData'] = {}
        result = analyze([item, row(5061, 2, ReturnCode='unknown-code')])
        self.assertEqual(result['coverage']['retained'], 2)
        self.assertEqual(result['findings'], [])
        self.assertTrue(result['assessment']['scope_incomplete'])
        self.assertIn('audit_details_missing', [r['code'] for r in guard.task_scope(result)['reasons']])
        self.assertEqual(result['security_analysis']['event_types'][1]['return_codes'], {'unknown': 1})

    def test_unique_session_correlation_and_identity_boundaries(self):
        login = row(4624, 1)
        privileged = row(4672, 2, SubjectUserSid='S-1-5-21-123')
        membership = row(4627, 3)
        result = analyze([login, privileged, membership])
        self.assertEqual(len(result['security_analysis']['correlations']), 2)
        for replacement in ({'Computer': 'OTHER'}, {'TimeCreated': '2026-10-14T06:00:06Z'},
                            {'EventData': {**privileged['EventData'], 'SubjectLogonId': '0x124'}},
                            {'EventData': {**privileged['EventData'], 'SubjectUserSid': 'S-1-5-21-999'}}):
            self.assertEqual(analyze([login, {**privileged, **replacement}])['security_analysis']['correlations'], [])
        self.assertEqual(analyze([login, {**login, 'RecordId': 4}, privileged])['security_analysis']['correlations'], [])

    def test_collection_is_partitioned_bounded_and_real_only(self):
        sys.path.insert(0, str(ROOT / 'backend'))
        def read(**kwargs):
            eid, limit = kwargs['event_ids'][0], kwargs['max_events']
            rows = [row(eid, eid * 10000 + i) for i in range(limit)]
            return dict(events=rows, is_mock=False, read_status='success', channel_results=[dict(status='success', events_read=limit)])
        with patch('platform.system', return_value='Windows'), patch('app.services.log_reader.read_windows_logs', side_effect=read) as mock:
            result = guard.collect_windows(1000)
        self.assertEqual(len(result['events']), 1000)
        self.assertEqual(mock.call_count, 8)
        self.assertTrue(result['collection']['limit_reached'])
        self.assertEqual(len(result['collection']['partitions']), 8)
        self.assertEqual(result['windows_diagnostics']['event_ids']['5379'], 72)
        for limit in (1, 2, 7, 8, 9, 1000, 5000):
            self.assertEqual(sum(n for _, n in security.query_plan(limit)), limit)
        for bad in (0, True, 5001, '1000'):
            with self.assertRaises(ValueError):
                security.query_plan(bad)
        with patch('platform.system', return_value='Windows'), patch('app.services.log_reader.read_windows_logs', return_value=dict(is_mock=True)):
            with self.assertRaises(RuntimeError):
                guard.collect_windows()

    def test_model_sample_covers_types_and_task_survives_store_and_display(self):
        rows = [row(eid, i + 1) for i, eid in enumerate(security.AUDIT_IDS)]
        rows += [row(5379, 100 + i) for i in range(200)]
        rows += [row(5061, 999, ReturnCode='5')]
        events, rejected = guard.windows_events(rows)
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend' / 'data') as directory:
            store = guard.TaskStore(Path(directory) / 'tasks.db')
            task = guard.run_task(store, 'windows-local', lambda: dict(events=events, rejected=rejected))
            restored = store.get(task['id'])
            self.assertEqual(restored['security_analysis'], task['security_analysis'])
            self.assertEqual(task['actions'], [])
            payload = guard_models.context(restored)
            self.assertEqual({e['event_id'] for e in payload['evidence']}, {str(e) for e in security.AUDIT_IDS})
            self.assertLess(len(json.dumps(payload, ensure_ascii=False)), 22000)
            self.assertIn('Security:999', {e['ref'] for e in payload['evidence']})
            import guard_cli
            with redirect_stdout(io.StringIO()) as output:
                guard_cli.show(restored)
            self.assertIn('5379', output.getvalue())
            self.assertIn('核查建议', output.getvalue())


if __name__ == '__main__':
    unittest.main()
