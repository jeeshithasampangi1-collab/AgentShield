from pydantic import BaseModel


from pydantic import BaseModel


class AgentRequest(BaseModel):
    agent: str
    tool: str
    action: str
    api_key: str
    destination: str | None = None
    data: str | None = None