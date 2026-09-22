from fastapi import FastAPI
from policy_engine import is_tool_allowed
from auth import authenticate_agent
from audit_logger import log_security_event
from risk_engine import calculate_risk, RISK_THRESHOLD
from destination_checker import check_destination
from secret_detector import contains_secret
from prompt_injection_detector import contains_prompt_injection
from models import AgentRequest

app = FastAPI()


@app.get("/")
def home():
    return {"message": "AI Agent Security Gateway is running!"}


@app.post("/check-request")
def check_request(request: AgentRequest):
    risk_score = calculate_risk(
        request.tool,
        request.destination,
        request.data
    )

    if risk_score > RISK_THRESHOLD:
        log_security_event(
            request.agent,
            request.tool,
            request.action,
            request.destination,
            risk_score,
            "BLOCK",
            "Risk score is too high"
        )

        return {
            "decision": "BLOCK",
            "agent": request.agent,
            "tool": request.tool,
            "action": request.action,
            "destination": request.destination,
            "data": request.data,
            "risk_score": risk_score,
            "reason": "Risk score is too high"
        }

    if not authenticate_agent(request.agent, request.api_key):
        log_security_event(
            request.agent,
            request.tool,
            request.action,
            request.destination,
            risk_score,
            "BLOCK",
            "Authentication failed"
        )

        return {
            "decision": "BLOCK",
            "agent": request.agent,
            "tool": request.tool,
            "action": request.action,
            "destination": request.destination,
            "data": request.data,
            "risk_score": risk_score,
            "reason": "Authentication failed"
        }

    if not is_tool_allowed(request.agent, request.tool):
        log_security_event(
            request.agent,
            request.tool,
            request.action,
            request.destination,
            risk_score,
            "BLOCK",
            "Agent is not authorized to use this tool"
        )

        return {
            "decision": "BLOCK",
            "agent": request.agent,
            "tool": request.tool,
            "action": request.action,
            "destination": request.destination,
            "data": request.data,
            "risk_score": risk_score,
            "reason": "Agent is not authorized to use this tool"
        }

    if not check_destination(request.destination):
        log_security_event(
            request.agent,
            request.tool,
            request.action,
            request.destination,
            risk_score,
            "BLOCK",
            "Destination is not allowed"
        )

        return {
            "decision": "BLOCK",
            "agent": request.agent,
            "tool": request.tool,
            "action": request.action,
            "destination": request.destination,
            "data": request.data,
            "risk_score": risk_score,
            "reason": "Destination is not allowed"
        }

    if contains_secret(request.data):
        log_security_event(
            request.agent,
            request.tool,
            request.action,
            request.destination,
            risk_score,
            "BLOCK",
            "Sensitive information detected"
        )

        return {
            "decision": "BLOCK",
            "agent": request.agent,
            "tool": request.tool,
            "action": request.action,
            "destination": request.destination,
            "data": request.data,
            "risk_score": risk_score,
            "reason": "Sensitive information detected"
        }

    if contains_prompt_injection(request.data):
        log_security_event(
            request.agent,
            request.tool,
            request.action,
            request.destination,
            risk_score,
            "BLOCK",
            "Prompt injection detected"
        )

        return {
            "decision": "BLOCK",
            "agent": request.agent,
            "tool": request.tool,
            "action": request.action,
            "destination": request.destination,
            "data": request.data,
            "risk_score": risk_score,
            "reason": "Prompt injection detected"
        }

    log_security_event(
        request.agent,
        request.tool,
        request.action,
        request.destination,
        risk_score,
        "ALLOW",
        "Request passed all security checks"
    )

    return {
        "decision": "ALLOW",
        "agent": request.agent,
        "tool": request.tool,
        "action": request.action,
        "destination": request.destination,
        "data": request.data,
        "risk_score": risk_score,
        "reason": "Request passed all security checks"
    }