LOW_RISK_THRESHOLD = 20
HIGH_RISK_THRESHOLD = 40


def evaluate_policy(risk_score: int) -> str:
    if risk_score < LOW_RISK_THRESHOLD:
        return "ALLOW"

    if risk_score < HIGH_RISK_THRESHOLD:
        return "APPROVAL"

    return "DENY"


AGENT_PERMISSIONS = {
    "demo-agent": ["weather", "calculator", "database"],
    "limited-agent": ["weather"]
}


def is_tool_allowed(agent: str, tool: str) -> bool:
    if agent not in AGENT_PERMISSIONS:
        return False

    return tool in AGENT_PERMISSIONS[agent]