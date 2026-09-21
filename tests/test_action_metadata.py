# Copyright (c) 2017-2026 Splunk Inc.

from src.actions import (
    copy_email,
    create_folder,
    delete_email,
    delete_event,
    delete_rule,
    disable_rule,
    get_folder_id,
    list_addresses,
    list_users,
    move_email,
    send_email,
    trace_email,
    update_email,
)


def test_mutating_actions_are_not_read_only():
    actions = (
        copy_email.copy_email,
        create_folder.create_folder,
        delete_email.delete_email,
        delete_event.delete_event,
        delete_rule.delete_rule,
        disable_rule.disable_rule,
        move_email.move_email,
        send_email.send_email,
        update_email.update_email,
    )

    assert all(action.meta.read_only is False for action in actions)


def test_investigation_actions_are_read_only():
    actions = (
        list_addresses.list_addresses,
        trace_email.trace_email,
        get_folder_id.get_folder_id,
        list_users.list_users,
    )

    assert all(action.meta.read_only is True for action in actions)
