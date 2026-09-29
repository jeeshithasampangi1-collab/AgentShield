def check_authorization_consistency(
    authorizations: list[dict],
    proposed_action: dict
) -> dict:
    """
    Compare the AI agent's proposed action against
    the user's authorized actions.

    Each authorization should contain:
    - resource
    - operations
    - scope

    The proposed action should contain:
    - resource
    - operation
    - scope
    """

    proposed_resource = proposed_action.get("resource")
    proposed_operation = proposed_action.get("operation")
    proposed_scope = proposed_action.get("scope")

    for authorization in authorizations:
        authorized_resource = authorization.get("resource")
        authorized_operations = authorization.get("operations", [])
        authorized_scope = authorization.get("scope")

        resource_matches = (
            authorized_resource == proposed_resource
        )

        operation_matches = (
            proposed_operation in authorized_operations
        )

        scope_matches = (
            authorized_scope == proposed_scope
        )

        if (
            resource_matches
            and operation_matches
            and scope_matches
        ):
            return {
                "authorized": True,
                "authorization_mismatch": False,
                "resource_mismatch": False,
                "operation_mismatch": False,
                "scope_expansion": False,
                "reason": (
                    "AI proposed action matches "
                    "user authorization"
                )
            }

    resource_authorized = False
    operation_authorized = False
    scope_authorized = False

    for authorization in authorizations:
        if authorization.get("resource") == proposed_resource:
            resource_authorized = True

            if proposed_operation in authorization.get(
                "operations", []
            ):
                operation_authorized = True

                if authorization.get("scope") == proposed_scope:
                    scope_authorized = True

    return {
        "authorized": False,
        "authorization_mismatch": True,
        "resource_mismatch": not resource_authorized,
        "operation_mismatch": (
            resource_authorized and not operation_authorized
        ),
        "scope_expansion": (
            resource_authorized
            and operation_authorized
            and not scope_authorized
        ),
        "reason": (
            "AI proposed action does not match "
            "the user's authorized scope"
        )
    }