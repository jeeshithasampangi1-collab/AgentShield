def create_approval_request(
    request_id: str,
    user_id: str | None,
    agent_id: str,
    tool: str,
    action: str,
    risk_score: int,
    reason: str
) -> dict:

    return {
        "request_id": request_id,
        "user_id": user_id,
        "agent_id": agent_id,
        "tool": tool,
        "action": action,
        "risk_score": risk_score,
        "approval_required": True,
        "approver": None,
        "approver_authority": None,
        "approval_decision": "PENDING",
        "reason": reason
    }


def approve_approval_request(
    approval_request: dict,
    approver: str,
    approver_authority: str
) -> dict:

    if approval_request["approval_decision"] != "PENDING":
        return {
            **approval_request,
            "approval_error": "Approval request is no longer pending"
        }

    approval_request["approver"] = approver
    approval_request["approver_authority"] = approver_authority
    approval_request["approval_decision"] = "APPROVED"

    return approval_request


def deny_approval_request(
    approval_request: dict,
    approver: str,
    approver_authority: str
) -> dict:

    if approval_request["approval_decision"] != "PENDING":
        return {
            **approval_request,
            "approval_error": "Approval request is no longer pending"
        }

    approval_request["approver"] = approver
    approval_request["approver_authority"] = approver_authority
    approval_request["approval_decision"] = "DENIED"

    return approval_request