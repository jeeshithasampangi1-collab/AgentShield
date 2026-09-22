def check_destination(destination: str | None) -> bool:
    if destination is None:
        return True

    blocked_destinations = [
        "malicious-site.com",
        "suspicious-site.com"
    ]

    return destination not in blocked_destinations