def contains_prompt_injection(data: str | None) -> bool:
    if data is None:
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

    data_lower = data.lower()

    for phrase in suspicious_phrases:
        if phrase in data_lower:
            return True

    return False