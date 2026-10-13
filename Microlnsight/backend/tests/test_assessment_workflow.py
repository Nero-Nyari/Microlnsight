import json
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app import models
from app.main import app
from app.db.base import Base
from app.db.session import get_db
from app.agents.assessment import normalize_triage

BENIGN = dict(classification="benign", disposition="false_positive", risk_level="info", confidence=.9,
              reasoning="这是已授权的应用清单脚本。", event_type="应用清单")
RAW = json.dumps({"Platform": "Windows", "EventID": 4104, "Channel": "Microsoft-Windows-PowerShell/Operational",
                  "Message": "Get-Process; 示例异常线索：连续120次失败登录"}, ensure_ascii=False)
SUSPICIOUS = dict(classification="suspicious", disposition="needs_review", risk_level="medium", confidence=.7,
                  reasoning="短时间多次认证失败，需核实。", findings=[{"quote": "示例异常线索：连续120次失败登录", "reason": "失败次数异常"}])


class AssessmentTests(unittest.TestCase):
    def test_conflicting_verdict_is_unknown(self):
        result = normalize_triage({**BENIGN, "disposition": "true_positive"}, RAW)
        self.assertEqual(result["classification"], "unknown")
        self.assertEqual(result["queue"], "logs")
        self.assertTrue(result["missing_evidence"])

    def test_unverifiable_quote_cannot_create_alert(self):
        result = normalize_triage({**SUSPICIOUS, "findings": [{"quote": "不存在的攻击证据片段", "reason": "异常"}]}, RAW)
        self.assertEqual(result["queue"], "logs")

    def test_nested_log_quotes_and_idempotence(self):
        raw = json.dumps({"OriginalLog": RAW})
        result = normalize_triage(SUSPICIOUS, raw)
        self.assertEqual(result["queue"], "alerts")
        self.assertEqual(normalize_triage(result, raw), result)

    def test_invalid_result_fails_to_unknown(self):
        for result in (None, [], {"classification": "nonsense", "confidence": "NaN"}):
            self.assertEqual(normalize_triage(result, RAW)["classification"], "unknown")

    def test_benign_with_attacker_narrative_needs_review(self):
        result = normalize_triage({**BENIGN, "reasoning": "攻击者已入侵主机"}, RAW)
        self.assertEqual(result['classification'], 'unknown')
        self.assertEqual(result['confidence'], 0)
        self.assertNotIn('攻击者', result['reasoning'])


class WorkflowTests(unittest.TestCase):
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

    def create(self):
        alert = self.client.post('/api/alerts', json={"title": "测试日志", "raw_content": RAW, "status": "review", "severity": "critical"}).json()
        incident = self.client.post('/api/incidents', json={"alert_id": alert['id'], "status": "review", "risk_level": "critical"}).json()
        return incident['id']

    def analyze(self, iid, triage):
        with patch('app.agents.pipeline.triage', return_value=triage), \
             patch('app.agents.pipeline.analyze_attack_chain', return_value={"stages": [], "attack_path": "可能的认证尝试"}) as chain, \
             patch('app.agents.pipeline.generate_actions', return_value=[{"action_type": "核查来源", "description": "先核实原文证据", "risk": "low", "approval_required": True}]) as actions:
            response = self.client.post(f'/api/incidents/{iid}/analyze')
        self.assertEqual(response.status_code, 200, response.text)
        return chain, actions

    def detail(self, iid):
        return self.client.get(f'/api/incidents/{iid}').json()

    def test_import_is_log_even_if_client_submits_high_severity(self):
        iid = self.create()
        self.assertEqual(self.detail(iid)['status'], 'pending')
        self.assertEqual(self.client.get('/api/incidents?queue=alerts').json(), [])
        self.assertEqual(self.client.get('/api/alerts?queue=alerts').json(), [])
        self.assertEqual(len(self.client.get('/api/alerts?queue=logs').json()), 1)

    def test_preliminary_report_is_visible_without_creating_an_alert(self):
        iid = self.create()
        report = self.client.post(f'/api/incidents/{iid}/report').json()
        detail = self.detail(iid)
        self.assertEqual(detail['reports'][0]['id'], report['id'])
        self.assertEqual(detail['status'], 'pending')
        self.assertEqual(detail['queue'], 'logs')

    def test_benign_skips_attack_narrative_and_has_consistent_download(self):
        iid = self.create()
        chain, actions = self.analyze(iid, BENIGN)
        chain.assert_not_called(); actions.assert_not_called()
        detail = self.detail(iid)
        self.assertEqual(detail['queue'], 'logs')
        self.assertEqual(detail['status'], 'benign')
        self.assertEqual(detail['response_actions'], [])
        self.assertIn('不适用', detail['attack_stage'])
        report = detail['reports'][0]
        self.assertIn('正常活动', report['content'])
        self.assertNotIn('攻击者', report['content'])
        self.assertEqual(self.client.get(f"/api/reports/{report['id']}/download").text, report['content'])
        self.assertNotIn('攻击者', json.dumps(self.client.get(f'/api/incidents/{iid}/agents').json(), ensure_ascii=False))

    def test_grounded_abnormality_promotes_then_benign_returns_to_logs(self):
        iid = self.create()
        self.analyze(iid, SUSPICIOUS)
        first = self.detail(iid)
        self.assertEqual(first['queue'], 'alerts')
        self.assertEqual(len(self.client.get('/api/alerts?queue=alerts').json()), 1)
        action_id = first['response_actions'][0]['id']
        old_report = first['reports'][0]['id']
        self.analyze(iid, BENIGN)
        second = self.detail(iid)
        self.assertEqual(second['queue'], 'logs')
        self.assertEqual(len(second['agent_runs']), 5)
        self.assertGreater(second['reports'][0]['id'], old_report)
        self.assertEqual(self.client.get('/api/alerts?queue=alerts').json(), [])
        self.assertEqual(self.client.post(f'/api/incidents/{iid}/actions/{action_id}/approve', json={'approved_by':'test'}).status_code, 409)
        self.assertEqual(self.client.post(f'/api/incidents/{iid}/actions/{action_id}/execute').status_code, 409)
        self.assertEqual(self.db.query(models.AgentRun).count(), 10)
        self.assertEqual(self.db.query(models.Report).count(), 2)

    def test_incomplete_or_failed_triage_stays_in_logs(self):
        for result in ({}, {**SUSPICIOUS, 'findings': []}):
            iid = self.create(); self.analyze(iid, result)
            detail = self.detail(iid)
            self.assertEqual(detail['status'], 'needs_review')
            self.assertEqual(detail['queue'], 'logs')
            self.assertIn('证据不足', detail['reports'][0]['content'])

    def test_failed_new_run_does_not_reuse_previous_verdict(self):
        iid = self.create(); self.analyze(iid, SUSPICIOUS)
        with patch('app.agents.pipeline.triage', side_effect=RuntimeError('provider unavailable')):
            self.client.post(f'/api/incidents/{iid}/analyze')
        self.assertEqual(self.detail(iid)['queue'], 'logs')
        self.assertEqual(self.detail(iid)['status'], 'needs_review')

    def test_legacy_conflicts_are_corrected_without_overwriting_originals(self):
        iid = self.create()
        incident = self.db.get(models.Incident, iid)
        incident.status = 'benign'; incident.attack_stage = '攻击者已入侵'
        self.db.add(models.AgentRun(incident_id=iid, agent_name='Triage', status='success', output_data=BENIGN))
        self.db.add(models.AgentRun(incident_id=iid, agent_name='Attack Chain', status='success', output_data={'attack_path':'攻击者已入侵'}))
        report = models.Report(incident_id=iid, content='攻击者已入侵')
        self.db.add(report); self.db.commit()
        detail = self.detail(iid)
        self.assertNotIn('攻击者', detail['reports'][0]['content'])
        self.assertNotIn('攻击者', detail['attack_stage'])
        self.assertEqual(self.db.get(models.Report, report.id).content, '攻击者已入侵')
        regenerated = self.client.post(f'/api/incidents/{iid}/report').json()
        self.assertIn('正常活动', regenerated['content'])
        self.assertEqual(self.client.get(f"/api/reports/{regenerated['id']}/download").text, regenerated['content'])
