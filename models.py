from pydantic import BaseModel, Field


class UserAuthorization(BaseModel):

    resource: str

    operations: list[str]

    scope: str


class UserRequestContext(BaseModel):

    prompt: str

    requested_resource: str | None = None

    requested_operation: str | None = None

    requested_scope: str | None = None


class ProposedAction(BaseModel):

    resource: str

    operation: str

    scope: str

    tool: str

    destination: str | None = None

    data: str | None = None


class AgentRequest(BaseModel):

    agent: str

    tool: str

    action: str

    api_key: str

    destination: str | None = None

    data: str | None = None

    user_id: str | None = None

    user_request: UserRequestContext | None = None

    user_authorizations: list[UserAuthorization] = Field(
        default_factory=list
    )

    proposed_action: ProposedAction | None = None


class ToolResponse(BaseModel):

    agent: str

    tool: str

    response_data: str


class ApprovalDecisionRequest(BaseModel):

    approver: str

    approver_authority: str

    decision: str