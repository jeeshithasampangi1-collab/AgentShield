RISK_THRESHOLD = 30


def calculate_risk(
    tool: str,
    destination: str | None = None,
    data: str | None = None
) -> int:
    risk_score = 0

    if tool == "calculator":
        risk_score += 10

    elif tool == "weather":
        risk_score += 5

    else:
        risk_score += 30

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

    return risk_score