RISK_THRESHOLD = 30


def calculate_risk(
    tool: str,
    destination: str | None = None,
    data: str | None = None,
    authorization_mismatch: bool = False,
    scope_expansion: bool = False,
    operation_mismatch: bool = False,
    resource_mismatch: bool = False,
    behavioral_anomaly: bool = False
) -> int:
    risk_score = 0

    tool_risk_scores = {
        "weather": 5,
        "calculator": 10,
        "database": 30
    }

    risk_score += tool_risk_scores.get(tool, 30)

    if destination:
        external_destinations = [
            "http://",
            "https://",
            ".com",
            ".net",
            ".org"
        ]

        destination_lower = destination.lower()

        for pattern in external_destinations:
            if pattern in destination_lower:
                risk_score += 10
                break

    if data:
        sensitive_keywords = [
            "password",
            "api_key",
            "apikey",
            "secret",
            "access_token",
            "access token"
        ]

        data_lower = data.lower()

        for keyword in sensitive_keywords:
            if keyword in data_lower:
                risk_score += 20
                break

    if authorization_mismatch:
        risk_score += 25

    if resource_mismatch:
        risk_score += 15

    if operation_mismatch:
        risk_score += 30

    if scope_expansion:
        risk_score += 20

    if behavioral_anomaly:
        risk_score += 20

    return risk_score