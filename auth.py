import os

from dotenv import load_dotenv


load_dotenv()


AGENT_API_KEYS = {
    "demo-agent": os.getenv("DEMO_AGENT_API_KEY"),
    "limited-agent": os.getenv("LIMITED_AGENT_API_KEY")
}


def authenticate_agent(agent: str, api_key: str) -> bool:
    if agent not in AGENT_API_KEYS:
        return False

    return AGENT_API_KEYS[agent] == api_key