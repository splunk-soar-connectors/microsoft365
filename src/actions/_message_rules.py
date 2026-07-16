# Copyright (c) 2017-2026 Splunk Inc.

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from ..helper import MsGraphHelper


def message_rules_endpoint(email_address: str) -> str:
    return f"/users/{email_address}/mailFolders/inbox/messageRules"


def list_message_rules(helper: "MsGraphHelper", email_address: str) -> list[dict]:
    endpoint = message_rules_endpoint(email_address)
    rules = []
    next_link = None
    while True:
        response = helper.make_rest_call_helper(endpoint, nextLink=next_link)
        rules.extend(response.get("value", []))
        next_link = response.get("@odata.nextLink")
        if not next_link:
            return rules
