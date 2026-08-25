# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the vPC pair state-machine resource service."""

from types import SimpleNamespace
from unittest.mock import Mock

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.resources import (
    VpcPairStateMachine,
)


def test_vpc_override_deletions_respect_override_exceptions():
    """An override exception must retain its pair while other stale pairs are deleted."""
    retained_identifier = ("SERIAL1", "SERIAL2")
    deleted_identifier = ("SERIAL3", "SERIAL4")
    retained_item = Mock()
    deleted_item = Mock()
    deleted_item.model_dump.return_value = {
        "switchId": "SERIAL3",
        "peerSwitchId": "SERIAL4",
    }

    state_machine = object.__new__(VpcPairStateMachine)
    state_machine.previous = Mock()
    state_machine.previous.get_diff_identifiers.return_value = [
        retained_identifier,
        deleted_identifier,
    ]
    state_machine.proposed = Mock()
    state_machine.existing = Mock()
    state_machine.existing.get.side_effect = {
        retained_identifier: retained_item,
        deleted_identifier: deleted_item,
    }.get
    state_machine.model_orchestrator = Mock()
    state_machine.model_orchestrator.delete.return_value = True
    state_machine.format_log = Mock()
    state_machine.module = SimpleNamespace(params={"ignore_errors": False})

    state_machine._manage_vpc_override_deletions([retained_identifier])

    state_machine.model_orchestrator.delete.assert_called_once_with(deleted_item)
    state_machine.existing.delete.assert_called_once_with(deleted_identifier)
    state_machine.format_log.assert_called_once_with(
        identifier=deleted_identifier,
        status="deleted",
        after_data={},
    )
