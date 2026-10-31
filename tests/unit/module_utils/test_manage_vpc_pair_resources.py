# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the vPC pair state-machine resource service."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair import resources
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.exceptions import VpcPairResourceError
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


def _make_nrm(logs):
    """Build a duck-typed stand-in for VpcPairStateMachine, sufficient for _refresh_after_state."""
    module = MagicMock()
    module.params = {"state": "deleted", "verify": {"enabled": True, "retries": 1, "timeout": 30}}
    module.check_mode = False
    model_orchestrator = MagicMock()
    model_orchestrator.query_all.side_effect = RuntimeError("list query failed")
    return SimpleNamespace(
        module=module,
        logs=logs,
        model_orchestrator=model_orchestrator,
        model_class=MagicMock(),
        existing=None,
    )


def test_manage_vpc_pair_resources_00010_refresh_failure_after_real_change_reports_changed_true():
    """A post-apply refresh failure after a write already succeeded must carry changed=True, not default False."""
    nrm = _make_nrm(logs=[{"identifier": ("SW-A", "SW-B"), "status": "deleted"}])

    with pytest.raises(VpcPairResourceError) as exc:
        resources.VpcPairStateMachine._refresh_after_state(nrm)

    assert exc.value.details["changed"] is True


def test_manage_vpc_pair_resources_00020_refresh_failure_with_no_logged_change_reports_changed_false():
    """A refresh failure with nothing logged as created/updated/deleted reports changed=False."""
    nrm = _make_nrm(logs=[])

    with pytest.raises(VpcPairResourceError) as exc:
        resources.VpcPairStateMachine._refresh_after_state(nrm)

    assert exc.value.details["changed"] is False
