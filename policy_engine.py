AGENT_PERMISSIONS = {
    "demo-agent": ["weather", "calculator"],
    "limited-agent": ["weather"]
}


def is_tool_allowed(agent: str, tool: str) -> bool:
    if agent not in AGENT_PERMISSIONS:
        return False

    return tool in AGENT_PERMISSIONS[agent]