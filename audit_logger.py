from datetime import datetime
import json


def log_security_event(
    agent: str,
    tool: str,
    action: str,
    destination: str | None,
    risk_score: int,
    decision: str,
    reason: str,
    request_id: str | None = None,
    user_id: str | None = None,
    authorization_scope: dict | None = None,
    proposed_action: dict | None = None,
    authorization_consistency: dict | None = None,
    approval_request: dict | None = None,
    outcome: str | None = None
):
    timestamp = datetime.now().isoformat()

    log_entry = {
        "timestamp": timestamp,
        "request_id": request_id,
        "user_id": user_id,
        "agent": agent,
        "tool": tool,
        "action": action,
        "destination": destination,
        "risk_score": risk_score,
        "decision": decision,
        "reason": reason,
        "authorization_scope": authorization_scope,
        "proposed_action": proposed_action,
        "authorization_consistency": authorization_consistency,
        "approval_request": approval_request,
        "outcome": outcome
    }

    with open("security.log", "a") as log_file:
        log_file.write(
            json.dumps(log_entry) + "\n"
        )