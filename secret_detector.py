def contains_secret(data: str | None) -> bool:
    if data is None:
        return False

    sensitive_keywords = [
        "api_key",
        "apikey",
        "password",
        "secret",
        "access_token",
        "access token"
    ]

    data_lower = data.lower()

    for keyword in sensitive_keywords:
        if keyword in data_lower:
            return True

    return False