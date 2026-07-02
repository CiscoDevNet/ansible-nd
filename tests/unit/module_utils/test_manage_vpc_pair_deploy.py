# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

from unittest.mock import patch

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.exceptions import (
    VpcPairResourceError,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair import deploy


class _FakeModule:
    def __init__(self, params, check_mode=False):
        self.params = params
        self.check_mode = check_mode
        self.warnings = []

    def warn(self, msg):
        self.warnings.append(msg)


class _FakeNrm:
    def __init__(self, module):
        self.module = module


class _FakeNDModuleV2:
    """Records every request issued during deploy for assertions."""

    calls = []
    fail_on_path = None
    fail_message = "request failed"
    fail_status = 500

    def __init__(self, module):
        self.module = module
        self.status = 200

    def request(self, path, verb, payload):
        type(self).calls.append({"path": path, "verb": verb, "payload": payload})
        if type(self).fail_on_path and type(self).fail_on_path in path:
            raise deploy.NDModuleError(type(self).fail_message, status=type(self).fail_status)
        return {}


@pytest.fixture(autouse=True)
def _reset_calls():
    _FakeNDModuleV2.calls = []
    _FakeNDModuleV2.fail_on_path = None
    _FakeNDModuleV2.fail_message = "request failed"
    _FakeNDModuleV2.fail_status = 500
    yield
    _FakeNDModuleV2.calls = []
    _FakeNDModuleV2.fail_on_path = None
    _FakeNDModuleV2.fail_message = "request failed"
    _FakeNDModuleV2.fail_status = 500


def _build_nrm(config_type="switch", check_mode=False, pending_create=None):
    params = {
        "fabric_name": "myFabric",
        "config_actions": {"save": True, "deploy": True, "type": config_type},
        "_pending_create": pending_create if pending_create is not None else [],
        "_pending_delete": [],
        "_not_in_sync_pairs": [],
    }
    return _FakeNrm(_FakeModule(params, check_mode=check_mode))


def test_switch_scoped_deploy_targets_affected_switches():
    """type=switch deploys via switchActions/deploy with both peer serials (issue #335)."""
    nrm = _build_nrm(config_type="switch")
    # Fresh create: query-phase pending lists are empty; serials come from the
    # authoritative per-run diff in result.
    result = {"changed": True, "created": [("FOC1", "FOC2")], "deleted": [], "updated": []}

    with patch.object(deploy, "NDModuleV2", _FakeNDModuleV2):
        deploy.custom_vpc_deploy(nrm, "myFabric", result)

    assert len(_FakeNDModuleV2.calls) == 1
    call = _FakeNDModuleV2.calls[0]
    assert call["path"] == "/api/v1/manage/fabrics/myFabric/switchActions/deploy"
    assert call["payload"] == {"switchIds": ["FOC1", "FOC2"]}
    # No fabric-level configSave is issued for the switch-scoped path.
    assert all("configSave" not in c["path"] for c in _FakeNDModuleV2.calls)


def test_switch_scoped_deploy_uses_pending_when_no_diff():
    """Deploy-only no-diff case resolves serials from query-phase pending context."""
    nrm = _build_nrm(config_type="switch")
    nrm.module.params["_not_in_sync_pairs"] = [{"switchId": "FOC9", "peerSwitchId": "FOC8"}]
    result = {"changed": False, "created": [], "deleted": [], "updated": []}

    with patch.object(deploy, "NDModuleV2", _FakeNDModuleV2):
        deploy.custom_vpc_deploy(nrm, "myFabric", result)

    assert len(_FakeNDModuleV2.calls) == 1
    call = _FakeNDModuleV2.calls[0]
    assert call["path"] == "/api/v1/manage/fabrics/myFabric/switchActions/deploy"
    assert call["payload"] == {"switchIds": ["FOC9", "FOC8"]}


def test_global_scoped_deploy_uses_fabric_actions():
    """type=global retains the fabric-level configSave + deploy flow."""
    nrm = _build_nrm(config_type="global")
    result = {"changed": True, "created": [("FOC1", "FOC2")], "deleted": [], "updated": []}

    with patch.object(deploy, "NDModuleV2", _FakeNDModuleV2):
        deploy.custom_vpc_deploy(nrm, "myFabric", result)

    paths = [c["path"] for c in _FakeNDModuleV2.calls]
    assert any("actions/configSave" in p for p in paths)
    assert any("actions/deploy" in p for p in paths)
    assert all("switchActions/deploy" not in p for p in paths)


def test_global_config_save_vpc_generation_error_is_fatal():
    """The issue #335 configSave 500 must not be masked and followed by deploy."""
    nrm = _build_nrm(config_type="global")
    result = {"changed": True, "created": [("FOC1", "FOC2")], "deleted": [], "updated": []}
    _FakeNDModuleV2.fail_on_path = "actions/configSave"
    _FakeNDModuleV2.fail_message = (
        "ND Error 500: [FOC1/NX_1] - Unexpected error generating vPC configuration. "
        "Last Status [Peer Link Interface]<br>Switch [NX_1/FOC1]: Member port Ethernet1/1 "
        "is a member of VPC_PAIR, remove Ethernet1/1 from VPC_PAIR first."
    )

    with patch.object(deploy, "NDModuleV2", _FakeNDModuleV2):
        with pytest.raises(VpcPairResourceError):
            deploy.custom_vpc_deploy(nrm, "myFabric", result)

    paths = [c["path"] for c in _FakeNDModuleV2.calls]
    assert any("actions/configSave" in p for p in paths)
    assert all("actions/deploy" not in p for p in paths)
    assert all("switchActions/deploy" not in p for p in paths)


def test_switch_scoped_check_mode_previews_switch_deploy():
    """check_mode preview for type=switch references the switch-scoped endpoint."""
    nrm = _build_nrm(config_type="switch", check_mode=True)
    result = {"changed": True, "created": [("FOC1", "FOC2")], "deleted": [], "updated": []}

    info = deploy.custom_vpc_deploy(nrm, "myFabric", result)

    assert info["deployment_needed"] is True
    assert any("switchActions/deploy" in action for action in info["planned_actions"])
