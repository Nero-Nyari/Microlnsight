"""Agent pipeline orchestration."""
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app import models, schemas
from app.agents.parser_agent import parse_alert
from app.agents.triage_agent import triage
from app.agents.evidence_agent import gather_evidence
from app.agents.attack_chain_agent import analyze_attack_chain
from app.agents.response_agent import generate_actions
from app.agents.report_agent import generate_report
from app.agents.assessment import normalize_triage, constrained_chain, constrained_actions


def assess(parsed, raw_content):
    return normalize_triage(triage(parsed, raw_content), raw_content)


def chain_for_assessment(parsed, raw_content, evidence, assessment):
    if assessment["queue"] != "alerts":
        return constrained_chain(assessment)
    result = analyze_attack_chain(parsed, raw_content, evidence, assessment=assessment)
    # These are hypotheses, not a separate verdict or proof of success.
    result["attack_path"] = "待核实的可能路径：" + str(result.get("attack_path", "证据不足"))
    result["suspicious_success"] = "未确认攻击成功；阶段映射只用于排查线索。"
    return result


def actions_for_assessment(parsed, raw_content, attack_chain, assessment):
    if assessment["queue"] != "alerts":
        return constrained_actions(assessment)
    return generate_actions(parsed, raw_content, attack_chain, assessment=assessment)


def run_agent(
    db: Session,
    incident_id: int,
    agent_name: str,
    func,
    input_data: Dict[str, Any],
) -> Dict[str, Any]:
    """运行单个智能体并记录到数据库."""
    run = models.AgentRun(
        incident_id=incident_id,
        agent_name=agent_name,
        status="running",
        input_data=input_data,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    try:
        output = func(**input_data)
        run.status = "success"
        run.output_data = output if isinstance(output, dict) else {"result": output}
    except Exception as exc:
        run.status = "failed"
        run.error_message = str(exc)
        run.output_data = {"error": str(exc)}

    run.finished_at = datetime.utcnow()
    db.commit()
    db.refresh(run)
    return run.output_data or {}


def analyze_incident(db: Session, incident_id: int) -> None:
    """Run full analysis pipeline for an incident."""
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident or not incident.alert:
        return

    raw = incident.alert.raw_content or ""
    incident.status = "analyzing"
    db.commit()

    # 1. Parser
    parsed = run_agent(db, incident_id, "Parser", parse_alert, {"raw_content": raw})
    incident.event_type = parsed.get("alert_type") or parsed.get("title", "未知")[:100]

    # 2. Triage
    triage_result = run_agent(
        db, incident_id, "Triage", assess,
        {"parsed": parsed, "raw_content": raw}
    )
    triage_result = normalize_triage(triage_result, raw)
    incident.event_type = triage_result.get("event_type") or incident.event_type
    incident.risk_level = triage_result.get("risk_level", "medium")
    incident.confidence = triage_result.get("confidence", 0.0)
    incident.summary = triage_result.get("reasoning", "")

    # 3. Evidence
    evidence_result = run_agent(
        db, incident_id, "Evidence", gather_evidence,
        {"parsed": parsed, "raw_content": raw}
    )
    evidence_list = evidence_result if isinstance(evidence_result, list) else evidence_result.get("result", [])
    if isinstance(evidence_list, list):
        for e in evidence_list:
            item = models.EvidenceItem(
                incident_id=incident_id,
                type=e.get("type", "log"),
                title=e.get("title", ""),
                content=e.get("content", ""),
                source=e.get("source", ""),
                confidence=e.get("confidence", 0.0),
            )
            db.add(item)
        db.commit()

    # Refresh evidence from DB for downstream agents
    evidence_dicts = evidence_list if isinstance(evidence_list, list) else []

    # 4. Attack Chain
    chain_result = run_agent(
        db, incident_id, "Attack Chain", chain_for_assessment,
        {"parsed": parsed, "raw_content": raw, "evidence": evidence_dicts, "assessment": triage_result}
    )
    stages = chain_result.get("stages", [])
    incident.attack_stage = chain_result.get("attack_path", "")[:200]

    # 5. Response
    actions_result = run_agent(
        db, incident_id, "Response", actions_for_assessment,
        {"parsed": parsed, "raw_content": raw, "attack_chain": chain_result, "assessment": triage_result}
    )
    actions_list = actions_result if isinstance(actions_result, list) else actions_result.get("result", [])
    if isinstance(actions_list, list):
        for a in actions_list:
            action = models.ResponseAction(
                incident_id=incident_id,
                action_type=a.get("action_type", ""),
                description=a.get("description", ""),
                risk=a.get("risk", "medium"),
                approval_required=a.get("approval_required", False),
                status="pending",
            )
            db.add(action)
        db.commit()

    # 6. Report
    action_dicts = actions_list if isinstance(actions_list, list) else []
    report_content = generate_report(
        alert_title=incident.alert.title,
        parsed=parsed,
        triage=triage_result,
        evidence=evidence_dicts,
        attack_chain=chain_result,
        actions=action_dicts,
    )
    report = models.Report(
        incident_id=incident_id,
        content=report_content,
        format="markdown",
    )
    db.add(report)

    if triage_result["classification"] == "benign":
        incident.status = "benign"
    elif triage_result["classification"] == "unknown":
        incident.status = "needs_review"
    else:
        incident.status = "review"
    db.commit()
