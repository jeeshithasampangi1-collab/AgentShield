from fastapi import FastAPI, HTTPException
from uuid import uuid4

from policy_engine import (
    is_tool_allowed,
    evaluate_policy
)
from auth import authenticate_agent
from audit_logger import log_security_event
from risk_engine import calculate_risk
from destination_checker import check_destination
from secret_detector import contains_secret
from prompt_injection_detector import contains_prompt_injection
from authorization_consistency import check_authorization_consistency
from approval_control import (
    create_approval_request,
    approve_approval_request,
    deny_approval_request
)
from behavioral_learning import (
    record_approved_action,
    calculate_behavioral_anomaly
)
from response_security import (
    contains_response_injection,
    contains_sensitive_response_data,
    calculate_response_risk
)

from models import (
    AgentRequest,
    ToolResponse,
    ApprovalDecisionRequest
)


app = FastAPI()


PENDING_APPROVALS = {}


@app.get("/")
def home():
    return {"message": "AI Agent Security Gateway is running!"}


@app.post("/check-request")
def check_request(request: AgentRequest):
    request_id = f"REQ-{uuid4().hex[:12]}"

    authorization_result = None
    behavioral_result = None

    authorization_mismatch = False
    scope_expansion = False
    operation_mismatch = False
    resource_mismatch = False
    behavioral_anomaly = False

    authorization_scope = [
        authorization.model_dump()
        for authorization in request.user_authorizations
    ]

    proposed_action = (
        request.proposed_action.model_dump()
        if request.proposed_action
        else None
    )

    if request.user_authorizations and request.proposed_action:
        authorization_result = check_authorization_consistency(
            authorization_scope,
            proposed_action
        )

        authorization_mismatch = (
            authorization_result["authorization_mismatch"]
        )

        scope_expansion = authorization_result["scope_expansion"]

        operation_mismatch = (
            authorization_result["operation_mismatch"]
        )

        resource_mismatch = (
            authorization_result["resource_mismatch"]
        )

    if request.user_id and request.proposed_action:
        behavioral_result = calculate_behavioral_anomaly(
            user_id=request.user_id,
            resource=request.proposed_action.resource,
            operation=request.proposed_action.operation,
            scope=request.proposed_action.scope,
            tool=request.proposed_action.tool
        )

        behavioral_anomaly = behavioral_result["anomaly_detected"]

    risk_score = calculate_risk(
        request.tool,
        request.destination,
        request.data,
        authorization_mismatch=authorization_mismatch,
        scope_expansion=scope_expansion,
        operation_mismatch=operation_mismatch,
        resource_mismatch=resource_mismatch,
        behavioral_anomaly=behavioral_anomaly
    )

    policy_decision = evaluate_policy(risk_score)

    if not authenticate_agent(
        request.agent,
        request.api_key
    ):
        reason = "Authentication failed"

        log_security_event(
            request.agent,
            request.tool,
            request.action,
            request.destination,
            risk_score,
            "BLOCK",
            reason,
            request_id=request_id,
            user_id=request.user_id,
            authorization_scope=authorization_scope,
            proposed_action=proposed_action,
            authorization_consistency=authorization_result,
            outcome="BLOCKED"
        )

        return {
            "decision": "BLOCK",
            "request_id": request_id,
            "agent": request.agent,
            "tool": request.tool,
            "action": request.action,
            "destination": request.destination,
            "data": request.data,
            "risk_score": risk_score,
            "policy_decision": "DENY",
            "reason": reason
        }

    if not is_tool_allowed(
        request.agent,
        request.tool
    ):
        reason = "Agent is not authorized to use this tool"

        log_security_event(
            request.agent,
            request.tool,
            request.action,
            request.destination,
            risk_score,
            "BLOCK",
            reason,
            request_id=request_id,
            user_id=request.user_id,
            authorization_scope=authorization_scope,
            proposed_action=proposed_action,
            authorization_consistency=authorization_result,
            outcome="BLOCKED"
        )

        return {
            "decision": "BLOCK",
            "request_id": request_id,
            "agent": request.agent,
            "tool": request.tool,
            "action": request.action,
            "destination": request.destination,
            "data": request.data,
            "risk_score": risk_score,
            "policy_decision": "DENY",
            "reason": reason
        }

    if not check_destination(request.destination):
        reason = "Destination is not allowed"

        log_security_event(
            request.agent,
            request.tool,
            request.action,
            request.destination,
            risk_score,
            "BLOCK",
            reason,
            request_id=request_id,
            user_id=request.user_id,
            authorization_scope=authorization_scope,
            proposed_action=proposed_action,
            authorization_consistency=authorization_result,
            outcome="BLOCKED"
        )

        return {
            "decision": "BLOCK",
            "request_id": request_id,
            "agent": request.agent,
            "tool": request.tool,
            "action": request.action,
            "destination": request.destination,
            "data": request.data,
            "risk_score": risk_score,
            "policy_decision": "DENY",
            "reason": reason
        }

    if contains_secret(request.data):
        reason = "Sensitive information detected"

        log_security_event(
            request.agent,
            request.tool,
            request.action,
            request.destination,
            risk_score,
            "BLOCK",
            reason,
            request_id=request_id,
            user_id=request.user_id,
            authorization_scope=authorization_scope,
            proposed_action=proposed_action,
            authorization_consistency=authorization_result,
            outcome="BLOCKED"
        )

        return {
            "decision": "BLOCK",
            "request_id": request_id,
            "agent": request.agent,
            "tool": request.tool,
            "action": request.action,
            "destination": request.destination,
            "data": request.data,
            "risk_score": risk_score,
            "policy_decision": "DENY",
            "reason": reason
        }

    if contains_prompt_injection(request.data):
        reason = "Prompt injection detected"

        log_security_event(
            request.agent,
            request.tool,
            request.action,
            request.destination,
            risk_score,
            "BLOCK",
            reason,
            request_id=request_id,
            user_id=request.user_id,
            authorization_scope=authorization_scope,
            proposed_action=proposed_action,
            authorization_consistency=authorization_result,
            outcome="BLOCKED"
        )

        return {
            "decision": "BLOCK",
            "request_id": request_id,
            "agent": request.agent,
            "tool": request.tool,
            "action": request.action,
            "destination": request.destination,
            "data": request.data,
            "risk_score": risk_score,
            "policy_decision": "DENY",
            "reason": reason
        }

    if (
        policy_decision == "APPROVAL"
        and authorization_result is not None
        and authorization_result["authorized"] is True
    ):
        policy_decision = "ALLOW"

    if policy_decision == "DENY":
        reason = "Risk score is too high"

        if authorization_result is not None:
            if authorization_result["authorization_mismatch"]:
                reason = authorization_result["reason"]

        log_security_event(
            request.agent,
            request.tool,
            request.action,
            request.destination,
            risk_score,
            "BLOCK",
            reason,
            request_id=request_id,
            user_id=request.user_id,
            authorization_scope=authorization_scope,
            proposed_action=proposed_action,
            authorization_consistency=authorization_result,
            outcome="BLOCKED"
        )

        response = {
            "decision": "BLOCK",
            "request_id": request_id,
            "agent": request.agent,
            "user_id": request.user_id,
            "tool": request.tool,
            "action": request.action,
            "destination": request.destination,
            "data": request.data,
            "risk_score": risk_score,
            "policy_decision": policy_decision,
            "reason": reason
        }

        if authorization_result is not None:
            response["authorization_consistency"] = authorization_result

        if behavioral_result is not None:
            response["behavioral_analysis"] = behavioral_result

        return response

    if policy_decision == "APPROVAL":
        reason = "Human approval required"

        approval_request = create_approval_request(
            request_id=request_id,
            user_id=request.user_id,
            agent_id=request.agent,
            tool=request.tool,
            action=request.action,
            risk_score=risk_score,
            reason=reason
        )

        PENDING_APPROVALS[request_id] = {
            "approval_request": approval_request,
            "user_id": request.user_id,
            "proposed_action": proposed_action,
            "authorization_scope": authorization_scope,
            "authorization_consistency": authorization_result
        }

        log_security_event(
            request.agent,
            request.tool,
            request.action,
            request.destination,
            risk_score,
            "APPROVAL",
            reason,
            request_id=request_id,
            user_id=request.user_id,
            authorization_scope=authorization_scope,
            proposed_action=proposed_action,
            authorization_consistency=authorization_result,
            approval_request=approval_request,
            outcome="PENDING_APPROVAL"
        )

        response = {
            "decision": "APPROVAL_REQUIRED",
            "request_id": request_id,
            "agent": request.agent,
            "user_id": request.user_id,
            "tool": request.tool,
            "action": request.action,
            "destination": request.destination,
            "data": request.data,
            "risk_score": risk_score,
            "policy_decision": policy_decision,
            "reason": reason,
            "approval_request": approval_request
        }

        if authorization_result is not None:
            response["authorization_consistency"] = authorization_result

        if behavioral_result is not None:
            response["behavioral_analysis"] = behavioral_result

        return response

    reason = "Request passed all security checks"

    log_security_event(
        request.agent,
        request.tool,
        request.action,
        request.destination,
        risk_score,
        "ALLOW",
        reason,
        request_id=request_id,
        user_id=request.user_id,
        authorization_scope=authorization_scope,
        proposed_action=proposed_action,
        authorization_consistency=authorization_result,
        outcome="ALLOWED"
    )

    response = {
        "decision": "ALLOW",
        "request_id": request_id,
        "agent": request.agent,
        "user_id": request.user_id,
        "tool": request.tool,
        "action": request.action,
        "destination": request.destination,
        "data": request.data,
        "risk_score": risk_score,
        "policy_decision": policy_decision,
        "reason": reason
    }

    if authorization_result is not None:
        response["authorization_consistency"] = authorization_result

    if behavioral_result is not None:
        response["behavioral_analysis"] = behavioral_result

    return response


@app.post("/approval/{request_id}")
def process_approval(
    request_id: str,
    decision_request: ApprovalDecisionRequest
):
    if request_id not in PENDING_APPROVALS:
        raise HTTPException(
            status_code=404,
            detail="Approval request not found or already completed"
        )

    decision = decision_request.decision.upper()

    if decision not in ["APPROVE", "DENY"]:
        raise HTTPException(
            status_code=400,
            detail="Decision must be APPROVE or DENY"
        )

    pending_record = PENDING_APPROVALS[request_id]

    approval_request = pending_record["approval_request"]

    if decision == "APPROVE":
        completed_request = approve_approval_request(
            approval_request=approval_request,
            approver=decision_request.approver,
            approver_authority=decision_request.approver_authority
        )

        if pending_record["proposed_action"] is not None:
            proposed = pending_record["proposed_action"]

            record_approved_action(
                user_id=pending_record["user_id"],
                resource=proposed["resource"],
                operation=proposed["operation"],
                scope=proposed["scope"],
                tool=proposed["tool"]
            )

        log_security_event(
            approval_request["agent_id"],
            approval_request["tool"],
            approval_request["action"],
            None,
            approval_request["risk_score"],
            "APPROVED",
            "Human approver approved the request",
            request_id=request_id,
            user_id=approval_request["user_id"],
            authorization_scope=pending_record["authorization_scope"],
            proposed_action=pending_record["proposed_action"],
            authorization_consistency=pending_record[
                "authorization_consistency"
            ],
            approval_request=completed_request,
            outcome="APPROVED"
        )

        del PENDING_APPROVALS[request_id]

        return {
            "decision": "APPROVED",
            "request_id": request_id,
            "approval_request": completed_request,
            "outcome": "APPROVED"
        }

    completed_request = deny_approval_request(
        approval_request=approval_request,
        approver=decision_request.approver,
        approver_authority=decision_request.approver_authority
    )

    log_security_event(
        approval_request["agent_id"],
        approval_request["tool"],
        approval_request["action"],
        None,
        approval_request["risk_score"],
        "DENIED",
        "Human approver denied the request",
        request_id=request_id,
        user_id=approval_request["user_id"],
        authorization_scope=pending_record["authorization_scope"],
        proposed_action=pending_record["proposed_action"],
        authorization_consistency=pending_record[
            "authorization_consistency"
        ],
        approval_request=completed_request,
        outcome="DENIED"
    )

    del PENDING_APPROVALS[request_id]

    return {
        "decision": "DENIED",
        "request_id": request_id,
        "approval_request": completed_request,
        "outcome": "DENIED"
    }


@app.post("/check-response")
def check_response(response: ToolResponse):
    request_id = f"RESP-{uuid4().hex[:12]}"

    response_risk = calculate_response_risk(
        response.response_data
    )

    injection_detected = contains_response_injection(
        response.response_data
    )

    sensitive_data_detected = contains_sensitive_response_data(
        response.response_data
    )

    if injection_detected:
        decision = "BLOCK"
        reason = "Response injection detected"
        outcome = "BLOCKED"

    elif sensitive_data_detected:
        decision = "BLOCK"
        reason = "Sensitive information detected in response"
        outcome = "BLOCKED"

    else:
        decision = "ALLOW"
        reason = "Response passed security checks"
        outcome = "ALLOWED"

    log_security_event(
        response.agent,
        response.tool,
        "response_inspection",
        None,
        response_risk,
        decision,
        reason,
        request_id=request_id,
        user_id=None,
        authorization_scope=None,
        proposed_action=None,
        authorization_consistency=None,
        approval_request=None,
        outcome=outcome
    )

    return {
        "decision": decision,
        "request_id": request_id,
        "agent": response.agent,
        "tool": response.tool,
        "response_risk": response_risk,
        "response_injection_detected": injection_detected,
        "sensitive_data_detected": sensitive_data_detected,
        "reason": reason
    }