# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for shared security orchestrator behavior."""

from __future__ import annotations

from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.security.groups import SecurityGroupModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.security import (
    SecurityAssociationOrchestrator,
    SecurityGroupOrchestrator,
    SecurityProtocolDefinitionOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


def _rest_send(config_actions: dict | None = None) -> RestSend:
    """Build a RestSend instance with module params only."""
    return RestSend(
        {
            "check_mode": False,
            "fabric_name": "SITE1",
            "cluster_name": "cluster-a",
            "config_actions": config_actions or {"save": True, "deploy": True, "type": "switch"},
        }
    )


def test_security_orchestrator_00010():
    """Verify concrete orchestrator class variables."""
    instance = SecurityProtocolDefinitionOrchestrator(rest_send=_rest_send())

    assert instance.list_response_key == "securityProtocolDefinitions"
    assert instance.create_payload_key == "securityProtocolDefinitions"
    assert instance.remove_payload_key == "securityProtocolDefinitionNames"


def test_security_orchestrator_00020():
    """Verify 207 responses with failed items raise."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())
    result = {"securityGroups": [{"name": "app_web", "status": "failed", "message": "bad selector"}]}

    with pytest.raises(RuntimeError, match="app_web: failed - bad selector"):
        instance._raise_on_207_errors(result, "securityGroups")  # pylint: disable=protected-access


def test_security_orchestrator_00030():
    """Verify explicit attach/detach values are queued."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send())

    instance._queue_attach_or_detach(SecurityGroupModel(name="attach_me", id=101, vrf_names=["vrf1"], attach=True))  # pylint: disable=protected-access
    instance._queue_attach_or_detach(SecurityGroupModel(name="detach_me", id=102, vrf_names=["vrf1"], attach=False))  # pylint: disable=protected-access

    assert instance._pending_attach == ["attach_me"]  # pylint: disable=protected-access
    assert instance._pending_detach == ["detach_me"]  # pylint: disable=protected-access


def test_security_orchestrator_00040():
    """Verify config_actions are skipped when no resource changed."""
    instance = SecurityGroupOrchestrator(rest_send=_rest_send({"save": False, "deploy": False, "type": "global"}))

    result = instance.apply_config_actions(changed=False)

    assert result["config_actions"] == {"save": False, "deploy": False, "type": "global"}
    assert result["skipped"] == "No resource changes were detected."


def test_security_orchestrator_00050():
    """Verify association immutable fields are tracked centrally."""
    instance = SecurityAssociationOrchestrator(rest_send=_rest_send())

    assert "contract_name" in instance.immutable_update_fields
    assert "src_security_group_name" in instance.immutable_update_fields
    assert "dst_security_group_name" in instance.immutable_update_fields


def test_security_orchestrator_00060():
    """Verify instantiation succeeds for all shared orchestrators."""
    with does_not_raise():
        SecurityProtocolDefinitionOrchestrator(rest_send=_rest_send())
        SecurityGroupOrchestrator(rest_send=_rest_send())
        SecurityAssociationOrchestrator(rest_send=_rest_send())

