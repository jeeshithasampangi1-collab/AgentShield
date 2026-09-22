from datetime import datetime


def log_security_event(
    agent: str,
    tool: str,
    action: str,
    destination: str | None,
    risk_score: int,
    decision: str,
    reason: str
):
    timestamp = datetime.now().isoformat()

    log_entry = (
        f"{timestamp} | "
        f"agent={agent} | "
        f"tool={tool} | "
        f"action={action} | "
        f"destination={destination} | "
        f"risk_score={risk_score} | "
        f"decision={decision} | "
        f"reason={reason}"
    )

    with open("security.log", "a") as log_file:
        log_file.write(log_entry + "\n")