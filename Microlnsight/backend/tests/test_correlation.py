import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app import models
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.services.correlation import analyze_records, collect_related, record

CASES = json.loads((Path(__file__).parent / 'fixtures/windows_regression.json').read_text(encoding='utf-8'))


def records(events):
    return [record(SimpleNamespace(id=i+1, raw_content=json.dumps(e, ensure_ascii=False), source_type='windows_log'), i+1) for i,e in enumerate(events)]


class RuleTests(unittest.TestCase):
    def test_coverage_reports_duplicates_conflicts_and_missing_metadata(self):
        events = copy.deepcopy(CASES[5]['events'])
        events[2]['TimeCreated'] = '2026-09-29T10:02:00'
        conflict = copy.deepcopy(events[1])
        conflict['EventData']['TargetUserName'] = 'different'
        result = analyze_records(records(events + [events[0], conflict, {'message': 'unrecognized'}]))
        coverage = result['coverage']
        self.assertEqual(coverage['input_records'], 8)
        self.assertEqual((coverage['retained'], coverage['duplicates'], coverage['conflicts']), (5, 1, 2))
        self.assertEqual((coverage['identified'], coverage['unparsed'], coverage['missing_time']), (4, 1, 2))
        self.assertEqual(coverage['failure_records_excluded'], 1)
        self.assertEqual(sum(s['retained'] for s in coverage['sources']), 5)
        from app.agents.report_agent import correlation_report
        report = correlation_report('coverage', result)
        self.assertIn('分析范围与解析质量', report)
        self.assertIn('缺带时区时间 2 条', report)

    def test_model_cannot_call_one_failed_logon_brute_force(self):
        from app.agents.assessment import normalize_triage
        raw = json.dumps(CASES[8]['events'][0], ensure_ascii=False)
        result = normalize_triage({'classification':'suspicious', 'event_type':'密码爆破',
                                   'reasoning':'日志说120次失败，疑似密码爆破',
                                   'findings':[{'quote':'连续120次失败登录，攻击者已入侵','reason':'失败次数多'}]}, raw)
        self.assertEqual(result['queue'], 'logs')
        self.assertIn('独立 4625', ' '.join(result['missing_evidence']))

    def test_fixed_regression_corpus(self):
        for case in CASES:
            with self.subTest(case=case['id']):
                result = analyze_records(records(case['events']))
                self.assertEqual(result['assessment']['queue'], case['queue'])
                self.assertEqual([f['rule_id'] for f in result['findings']], case['rules'])
                if 'failure_count' in case:
                    self.assertEqual(result['findings'][0]['failure_count'], case['failure_count'])
                self.assertNotIn('已入侵', result['assessment']['reasoning'])
                self.assertTrue(result['assessment']['missing_evidence'])
                for finding in result['findings']:
                    self.assertTrue(finding['record_refs'])
                    self.assertTrue(set(finding['record_refs']) <= {r['alert_id'] for r in result['records']})

    def test_different_accounts_domains_ips_hosts_do_not_add_up(self):
        base = CASES[5]['events']
        for field in ['TargetUserName', 'TargetDomainName', 'IpAddress', 'Computer']:
            with self.subTest(field=field):
                events = copy.deepcopy(base)
                if field == 'Computer':
                    events[-1][field] = 'OTHER'
                else:
                    events[-1]['EventData'][field] = '192.0.2.11' if field == 'IpAddress' else 'OTHER'
                self.assertEqual(analyze_records(records(events))['assessment']['queue'], 'logs')

    def test_missing_timezone_invalid_ip_or_account_not_counted(self):
        for field in ['TimeCreated', 'IpAddress', 'TargetUserName']:
            events = copy.deepcopy(CASES[5]['events'])
            if field == 'TimeCreated':
                events[-1][field] = '2026-09-29T10:04:00'
            else:
                events[-1]['EventData'][field] = '-'
            self.assertEqual(analyze_records(records(events))['assessment']['queue'], 'logs')

    def test_boundary_and_timezone_normalization(self):
        events = copy.deepcopy(CASES[5]['events'])
        events[-1]['TimeCreated'] = '2026-09-29T18:05:00+08:00'
        self.assertEqual(analyze_records(records(events))['findings'][0]['failure_count'], 5)
        events[-1]['TimeCreated'] = '2026-09-29T18:05:01+08:00'
        self.assertEqual(analyze_records(records(events))['assessment']['queue'], 'logs')

    def test_conflicting_record_identity_is_excluded(self):
        events = copy.deepcopy(CASES[5]['events'])
        conflict = copy.deepcopy(events[0])
        conflict['EventData']['TargetUserName'] = 'different'
        result = analyze_records(records(events + [conflict]))
        self.assertEqual(result['assessment']['queue'], 'logs')
        self.assertEqual(result['conflicts_excluded'], 2)

    def test_service_before_success_cannot_complete_sequence(self):
        events = copy.deepcopy(CASES[6]['events'])
        events[-1]['TimeCreated'] = '2026-09-29T10:03:00Z'
        result = analyze_records(records(events))
        self.assertEqual(result['findings'][-1]['rule_id'], 'failure_then_success')

    def test_demo_and_real_failures_do_not_add_up(self):
        events = copy.deepcopy(CASES[5]['events'])
        events[-1]['IsDemo'] = False
        self.assertEqual(analyze_records(records(events))['assessment']['queue'], 'logs')

    def test_wrong_channel_cannot_impersonate_security_event(self):
        events = copy.deepcopy(CASES[5]['events'])
        events[-1]['Channel'] = 'Application'
        self.assertEqual(analyze_records(records(events))['assessment']['queue'], 'logs')

    def test_missing_record_ids_do_not_support_independent_count(self):
        events = copy.deepcopy(CASES[5]['events'])
        for e in events:
            del e['RecordId']
        result = analyze_records(records(events))
        self.assertEqual(result['assessment']['queue'], 'logs')
        self.assertIn('EventRecordID', ' '.join(result['assessment']['missing_evidence']))

    def test_timezone_representation_does_not_duplicate_same_event(self):
        events = [copy.deepcopy(CASES[5]['events'][0]) for _ in range(5)]
        events[-1]['TimeCreated'] = '2026-09-29T18:00:00+08:00'
        result = analyze_records(records(events))
        self.assertEqual(len(result['records']), 1)
        self.assertEqual(result['assessment']['queue'], 'logs')

    def test_service_argument_in_temp_is_not_executable_in_temp(self):
        event = copy.deepcopy(CASES[3]['events'][0])
        event['EventData']['ImagePath'] = '"C:\\Program Files\\Lab\\updater.exe" --log C:\\Temp\\install.log'
        self.assertEqual(analyze_records(records([event]))['assessment']['queue'], 'logs')

    def test_nested_demo_marker_remains_isolated(self):
        original = CASES[0]['events'][0]
        row = record(SimpleNamespace(id=1, raw_content=json.dumps({'OriginalLog':json.dumps(original),'IsDemo':False}), source_type='windows_log'))
        self.assertTrue(row['is_demo'])

    def test_nested_xml_preserves_evidence_fields(self):
        xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4697</EventID><Channel>Security</Channel><Computer>WIN-X</Computer><EventRecordID>99</EventRecordID><TimeCreated SystemTime="2026-09-29T10:00:00Z"/></System><EventData><Data Name="ServiceName">Demo</Data><Data Name="ServiceFileName">C:\\Temp\\svc.exe</Data><Data Name="ServiceStartType">2</Data></EventData></Event>'
        r = record(SimpleNamespace(id=1, raw_content=json.dumps({'OriginalLog':xml}), source_type='windows_log'))
        self.assertEqual(r['record_id'], '99')
        self.assertEqual(analyze_records([r])['findings'][0]['rule_id'], 'service_writable_path')


class CorrelationApiTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine)()
        app.dependency_overrides[get_db] = lambda: self.db
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        self.db.close()
        self.engine.dispose()

    def add(self, events):
        incidents = []
        for event in events:
            alert = models.Alert(title='固定测试', raw_content=json.dumps(event,ensure_ascii=False), source_type='windows_log')
            self.db.add(alert); self.db.flush()
            incident = models.Incident(alert_id=alert.id, status='pending')
            self.db.add(incident); self.db.flush()
            incidents.append(incident)
        self.db.commit()
        return incidents

    def test_full_api_traceability_and_reports_without_model(self):
        incidents = self.add(CASES[6]['events'])
        seed = incidents[0]
        with patch('app.core.llm_provider.get_llm_provider', side_effect=AssertionError('must remain local')):
            response = self.client.post(f'/api/incidents/{seed.id}/correlate',json={'window_minutes':15})
        self.assertEqual(response.status_code,200,response.text)
        detail = self.client.get(f'/api/incidents/{seed.id}').json()
        self.assertEqual(detail['queue'],'alerts')
        self.assertEqual(detail['correlation']['findings'][0]['failure_count'],5)
        self.assertEqual(len(detail['evidence_items']),7)
        self.assertEqual(detail['response_actions'],[])
        self.assertEqual(len(self.client.get('/api/incidents?queue=alerts').json()),1)
        self.assertTrue(all(i.status=='pending' for i in incidents[1:]))
        report = detail['reports'][0]
        self.assertIn('失败次数：5', report['content'])
        self.assertIn('192.0.2.10', report['content'])
        self.assertIn('日志 #', report['content'])
        self.assertEqual(self.client.get(f"/api/reports/{report['id']}/download").text,report['content'])
        regenerated = self.client.post(f'/api/incidents/{seed.id}/report').json()
        self.assertEqual(regenerated['content'],report['content'])

    def test_guided_demo_import_analysis_and_download(self):
        expected = [('windows_demo_normal', 1, 'logs'), ('windows_demo_single', 1, 'logs'),
                    ('windows_demo_sequence', 6, 'alerts')]
        for case_id, count, queue in expected:
            with self.subTest(case=case_id):
                response = self.client.post(f'/api/alerts/from-case/{case_id}')
                self.assertEqual(response.status_code, 200, response.text)
                alert = response.json()
                incident = self.client.post('/api/incidents', json={'alert_id': alert['id']}).json()
                self.assertEqual(incident['queue'], 'logs')
                response = self.client.post(f"/api/incidents/{incident['id']}/correlate", json={'window_minutes': 15})
                self.assertEqual(response.status_code, 200, response.text)
                detail = self.client.get(f"/api/incidents/{incident['id']}").json()
                self.assertEqual(detail['queue'], queue)
                self.assertEqual(len(detail['correlation']['records']), count)
                self.assertTrue(all(r['is_demo'] for r in detail['correlation']['records']))
                self.assertEqual(detail['response_actions'], [])
                report = detail['reports'][0]
                self.assertEqual(self.client.get(f"/api/reports/{report['id']}/download").text, report['content'])
                self.assertNotIn('None', report['content'])
                if queue == 'alerts':
                    self.assertEqual([f['rule_id'] for f in detail['correlation']['findings']],
                                     ['repeated_failed_logon', 'failure_then_success'])
                    self.assertEqual(detail['correlation']['findings'][0]['failure_count'], 5)
        self.assertEqual(self.db.query(models.Alert).count(), 8)
        self.assertEqual(self.db.query(models.Incident).count(), 8)

    def test_reloading_demo_does_not_inflate_failure_count(self):
        for _ in range(2):
            alert = self.client.post('/api/alerts/from-case/windows_demo_sequence').json()
        incident = self.client.post('/api/incidents', json={'alert_id': alert['id']}).json()
        self.client.post(f"/api/incidents/{incident['id']}/correlate", json={'window_minutes': 15})
        detail = self.client.get(f"/api/incidents/{incident['id']}").json()
        self.assertEqual(detail['correlation']['duplicates_excluded'], 6)
        self.assertEqual(detail['correlation']['findings'][0]['failure_count'], 5)
        self.assertEqual(len(detail['correlation']['records']), 6)

    def test_scope_excludes_other_hosts_times_and_demo_flags(self):
        events = copy.deepcopy(CASES[5]['events'])
        other_host, other_time, real = [copy.deepcopy(events[0]) for _ in range(3)]
        other_host['Computer']='OTHER'
        other_time['TimeCreated']='2026-09-30T10:00:00Z'
        real['IsDemo']=False
        incidents=self.add(events+[other_host,other_time,real])
        result=collect_related(self.db,incidents[0],15)
        self.assertEqual(len(result['records']),5)

    def test_missing_anchor_metadata_does_not_group_unrelated_records(self):
        events=copy.deepcopy(CASES[5]['events'])
        del events[0]['TimeCreated']
        incidents=self.add(events)
        result=collect_related(self.db,incidents[0],15)
        self.assertEqual(len(result['records']),1)
        self.assertEqual(result['assessment']['queue'],'logs')

    def test_legacy_attack_narrative_and_actions_not_reused(self):
        seed=self.add(CASES[0]['events'])[0]
        self.db.add(models.AgentRun(incident_id=seed.id,agent_name='Parser',status='success',output_data={}))
        self.db.add(models.AgentRun(incident_id=seed.id,agent_name='Attack Chain',status='success',output_data={'attack_path':'攻击者已入侵'}))
        action=models.ResponseAction(incident_id=seed.id,action_type='old',description='old action',risk='high',approval_required=True)
        self.db.add(action); self.db.commit()
        self.client.post(f'/api/incidents/{seed.id}/correlate',json={})
        detail=self.client.get(f'/api/incidents/{seed.id}').json()
        self.assertEqual(detail['queue'],'logs')
        self.assertNotIn('攻击者已入侵',json.dumps(detail,ensure_ascii=False))
        self.assertEqual([r['agent_name'] for r in detail['agent_runs']],['Correlation'])
        self.assertEqual(self.client.post(f'/api/incidents/{seed.id}/actions/{action.id}/execute').status_code,409)
        self.assertEqual(self.db.query(models.AgentRun).count(),3)

    def test_new_parser_run_supersedes_correlation(self):
        seed=self.add(CASES[5]['events'])[0]
        self.client.post(f'/api/incidents/{seed.id}/correlate',json={})
        self.db.add(models.AgentRun(incident_id=seed.id,agent_name='Parser',status='success',output_data={}))
        seed.status='analyzing'; self.db.commit()
        detail=self.client.get(f'/api/incidents/{seed.id}').json()
        self.assertIsNone(detail['correlation'])
        self.assertEqual(detail['queue'],'logs')
        self.assertEqual(detail['reports'],[])

    def test_validation_busy_and_not_found(self):
        seed=self.add(CASES[0]['events'])[0]
        self.assertEqual(self.client.post(f'/api/incidents/{seed.id}/correlate',json={'window_minutes':61}).status_code,422)
        self.assertEqual(self.client.post('/api/incidents/999/correlate',json={}).status_code,404)
        seed.status='analyzing';self.db.commit()
        self.assertEqual(self.client.post(f'/api/incidents/{seed.id}/correlate',json={}).status_code,409)

    def test_old_version_report_is_reconciled_with_new_evidence_guard(self):
        seed=self.add(CASES[8]['events'])[0]
        seed.status='review'
        self.db.add(models.AgentRun(incident_id=seed.id,agent_name='Triage',status='success',output_data={
            'classification':'suspicious','event_type':'密码爆破','reasoning':'疑似密码爆破',
            'findings':[{'quote':'连续120次失败登录，攻击者已入侵','reason':'次数多'}]}))
        old=models.Report(incident_id=seed.id,content='> 统一研判版本：1\n已确认密码爆破',format='markdown')
        self.db.add(old);self.db.commit()
        detail=self.client.get(f'/api/incidents/{seed.id}').json()
        self.assertEqual(detail['queue'],'logs')
        self.assertIn('证据不足',detail['reports'][0]['content'])
        self.assertNotIn('已确认密码爆破',detail['reports'][0]['content'])
        self.assertIn('已确认密码爆破',self.db.get(models.Report,old.id).content)


if __name__=='__main__':
    unittest.main()
