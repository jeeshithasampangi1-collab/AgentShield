APPROVED_ACTION_HISTORY = []


def record_approved_action(
    user_id: str | None,
    resource: str,
    operation: str,
    scope: str,
    tool: str
) -> None:
    APPROVED_ACTION_HISTORY.append(
        {
            "user_id": user_id,
            "resource": resource,
            "operation": operation,
            "scope": scope,
            "tool": tool
        }
    )


def calculate_behavioral_anomaly(
    user_id: str | None,
    resource: str,
    operation: str,
    scope: str,
    tool: str
) -> dict:
    if user_id is None:
        return {
            "anomaly_detected": False,
            "anomaly_score": 0,
            "reason": "No user identity available for behavioral analysis"
        }

    user_history = [
        action
        for action in APPROVED_ACTION_HISTORY
        if action["user_id"] == user_id
    ]

    if not user_history:
        return {
            "anomaly_detected": False,
            "anomaly_score": 0,
            "reason": "No established behavioral baseline"
        }

    matching_actions = [
        action
        for action in user_history
        if (
            action["resource"] == resource
            and action["operation"] == operation
            and action["scope"] == scope
            and action["tool"] == tool
        )
    ]

    if matching_actions:
        return {
            "anomaly_detected": False,
            "anomaly_score": 0,
            "reason": "Action matches established behavioral baseline"
        }

    return {
        "anomaly_detected": True,
        "anomaly_score": 20,
        "reason": "Action differs from established behavioral baseline"
    }