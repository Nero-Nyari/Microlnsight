"""Consistent current views; original historical results remain in the database."""
from app import schemas
from app.agents.assessment import normalize_triage, constrained_chain, constrained_actions
from app.agents.parser_agent import _fallback_parse
from app.agents.evidence_agent import gather_evidence


def current_runs(incident):
    runs = sorted(incident.agent_runs, key=lambda r: r.id)
    start = max((r.id for r in runs if r.agent_name in ("Parser", "Correlation")), default=0)
    latest = {}
    for run in runs:
        if run.id >= start:
            latest[run.agent_name] = run
    return latest


def assessment_for(incident):
    correlation = current_runs(incident).get("Correlation")
    if correlation and correlation.status == "success" and incident.status not in ("pending", "analyzing", "failed", "interrupted"):
        return correlation.output_data['assessment']
    run = current_runs(incident).get("Triage")
    result = run.output_data if run and run.status == "success" else {}
    assessment = normalize_triage(result, incident.alert.raw_content if incident.alert else "")
    if incident.status in ("pending", "analyzing", "failed", "interrupted"):
        assessment = normalize_triage({}, "")
        assessment["label"] = {"pending": "待分析", "analyzing": "分析中", "failed": "分析失败", "interrupted": "分析中断"}[incident.status]
    return assessment


def incident_summary(incident):
    data = schemas.IncidentOut.model_validate(incident).model_dump()
    assessment = assessment_for(incident)
    data["assessment"] = assessment
    data["queue"] = assessment["queue"]
    if incident.status in ("pending", "analyzing", "failed", "interrupted"):
        data.update(risk_level=None, confidence=0.0, summary=None, attack_stage=None)
    if incident.status not in ("pending", "analyzing", "failed", "interrupted"):
        data.update(risk_level=assessment["risk_level"], confidence=assessment["confidence"],
                    summary=assessment["reasoning"], event_type=assessment["event_type"],
                    status="benign" if assessment["classification"] == "benign" else
                           "review" if assessment["queue"] == "alerts" else "needs_review")
    if assessment["queue"] != "alerts" and incident.status not in ("pending", "analyzing", "failed", "interrupted"):
        data["attack_stage"] = constrained_chain(assessment)["attack_path"]
    return data


def current_actions(incident):
    if assessment_for(incident)["queue"] != "alerts":
        return []
    run = current_runs(incident).get("Response")
    if not run or run.status != "success":
        return []
    return [a for a in incident.response_actions if a.created_at >= run.started_at]


def report_inputs(incident):
    assessment = assessment_for(incident)
    raw = incident.alert.raw_content or ""
    parsed = _fallback_parse(raw)
    run = current_runs(incident).get("Attack Chain")
    chain = run.output_data if run and run.status == "success" else {}
    actions = [schemas.ResponseActionOut.model_validate(a).model_dump() for a in current_actions(incident)]
    if assessment["queue"] != "alerts":
        chain, actions = constrained_chain(assessment), constrained_actions(assessment)
    inputs = dict(alert_title=incident.alert.title, parsed=parsed, triage=assessment,
                  evidence=gather_evidence(parsed, raw), attack_chain=chain, actions=actions)
    correlation = current_runs(incident).get('Correlation')
    if correlation and correlation.status == 'success':
        inputs['correlation'] = correlation.output_data
    return inputs


def report_view(report):
    from app.agents.report_agent import generate_report, REPORT_MARKER
    data = schemas.ReportOut.model_validate(report).model_dump()
    if REPORT_MARKER not in report.content:
        data["content"] = "> 历史报告的一致性修正版：根据现有日志与统一研判重新整理；原报告仍保留。\n\n" + generate_report(**report_inputs(report.incident))
    return data


def incident_detail(incident):
    data = incident_summary(incident)
    data["alert"] = schemas.AlertOut.model_validate(incident.alert).model_dump() if incident.alert else None
    from app.services.correlation import record
    data['source_record'] = record(incident.alert, incident.id) if incident.alert else None
    correlation = current_runs(incident).get('Correlation')
    data['correlation'] = correlation.output_data if correlation and correlation.status == 'success' else None
    assessment = data["assessment"]
    runs = []
    for run in current_runs(incident).values():
        item = schemas.AgentRunOut.model_validate(run).model_dump()
        if run.status == "success" and run.agent_name == "Triage":
            item["output_data"] = assessment
        if run.status == "success" and assessment["queue"] != "alerts":
            if run.agent_name == "Attack Chain":
                item["output_data"] = constrained_chain(assessment)
            if run.agent_name == "Response":
                item["output_data"] = {"result": constrained_actions(assessment)}
        runs.append(item)
    data["agent_runs"] = runs
    data["response_actions"] = [schemas.ResponseActionOut.model_validate(a).model_dump() for a in current_actions(incident)]
    evidence_run = current_runs(incident).get("Evidence") or current_runs(incident).get("Correlation")
    data["evidence_items"] = [schemas.EvidenceItemOut.model_validate(e).model_dump() for e in incident.evidence_items
                              if evidence_run and e.created_at >= evidence_run.started_at]
    latest_report = max(incident.reports, key=lambda r: r.id, default=None)
    data["reports"] = [report_view(latest_report)] if latest_report and incident.status not in ("analyzing", "failed", "interrupted") else []
    return data
