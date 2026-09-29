def contains_response_injection(response_data: str | None) -> bool:
    if response_data is None:
        return False

    suspicious_phrases = [
        "ignore previous instructions",
        "ignore all instructions",
        "ignore your instructions",
        "system prompt",
        "reveal your instructions",
        "reveal the system prompt",
        "bypass security",
        "disable security",
        "override security"
    ]

    response_lower = response_data.lower()

    for phrase in suspicious_phrases:
        if phrase in response_lower:
            return True

    return False


def contains_sensitive_response_data(response_data: str | None) -> bool:
    if response_data is None:
        return False

    sensitive_keywords = [
        "password",
        "api_key",
        "apikey",
        "secret",
        "access_token",
        "access token"
    ]

    response_lower = response_data.lower()

    for keyword in sensitive_keywords:
        if keyword in response_lower:
            return True

    return False


def calculate_response_risk(response_data: str | None) -> int:
    risk_score = 0

    if contains_response_injection(response_data):
        risk_score += 50

    if contains_sensitive_response_data(response_data):
        risk_score += 30

    return risk_score