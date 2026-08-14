# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from unittest.mock import patch

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair import deploy
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.exceptions import (
    VpcPairResourceError,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.utils import FabricUtils

SAVE_PATH = "/api/v1/manage/fabrics/fab1/actions/configSave"
GLOBAL_DEPLOY_PATH = "/api/v1/manage/fabrics/fab1/actions/deploy?forceShowRun=true"
SWITCH_DEPLOY_PATH = "/api/v1/manage/fabrics/fab1/switchActions/deploy"
SWITCHES_PATH = "/api/v1/manage/fabrics/fab1/switches"


class _FakeModule:
    def __init__(self, params, check_mode=False):
        self.params = params
        self.check_mode = check_mode
        self.warnings = []

    def warn(self, msg):
        self.warnings.append(msg)


class _FakeNrm:
    def __init__(self, params, check_mode=False):
        self.module = _FakeModule(params, check_mode=check_mode)


class _FakeNDModuleV2:
    """Records (path, verb, payload) calls and routes switches/action requests."""

    def __init__(self, module, switches_response=None, status=200, switches_exception=None, fail_on=None, fail_exception=None):
        self.module = module
        self.status = status
        self.calls = []
        self._switches_response = switches_response if switches_response is not None else {"switches": []}
        self._switches_exception = switches_exception
        self._fail_on = fail_on
        self._fail_exception = fail_exception

    def request(self, path, verb, payload=None):
        self.calls.append((path, verb, payload))
        if path.endswith("/switches"):
            if self._switches_exception is not None:
                raise self._switches_exception
            return self._switches_response
        if self._fail_on is not None and self._fail_on in path:
            raise self._fail_exception
        return {"success": True}

    def paths(self):
        return [path for (path, _verb, _payload) in self.calls]

    def payloads_for(self, target_path):
        return [payload for (path, _verb, payload) in self.calls if path == target_path]


def _boom(*_args, **_kwargs):
    raise AssertionError("NDModuleV2 must not be constructed in check_mode")


def _make_nrm(action_type, save=True, deploy_flag=True, check_mode=False):
    params = {
        "fabric_name": "fab1",
        "config_actions": {"save": save, "deploy": deploy_flag, "type": action_type},
    }
    return _FakeNrm(params, check_mode=check_mode)


def _run_deploy(nrm, fake_nd):
    with patch.object(deploy, "NDModuleV2", lambda module: fake_nd):
        return deploy.custom_vpc_deploy(nrm, "fab1", {"changed": True})


def test_manage_vpc_pair_deploy_00010_global_scope_uses_fabric_deploy():
    # type=global keeps the fabric-scoped configSave + actions/deploy dispatch
    # and never queries or deploys individual switches.
    nrm = _make_nrm("global")
    fake_nd = _FakeNDModuleV2(nrm.module)

    _run_deploy(nrm, fake_nd)

    paths = fake_nd.paths()
    assert SAVE_PATH in paths
    assert GLOBAL_DEPLOY_PATH in paths
    assert SWITCH_DEPLOY_PATH not in paths
    assert SWITCHES_PATH not in paths
    assert fake_nd.payloads_for(GLOBAL_DEPLOY_PATH) == [{"type": "global"}]


def test_manage_vpc_pair_deploy_00020_switch_scope_deploys_only_out_of_sync_switches():
    # type=switch routes deploy to switchActions/deploy with only the switch
    # serials that are not confirmed in-sync (out-of-sync + unknown status).
    nrm = _make_nrm("switch")
    switches_response = {
        "switches": [
            {"serialNumber": "FOX222AAA", "configSyncStatus": "In-Sync"},
            {"serialNumber": "FOX111AAA", "configSyncStatus": "Out-of-Sync"},
            {"serialNumber": "FOX333AAA"},  # unknown/missing status -> must deploy
        ]
    }
    fake_nd = _FakeNDModuleV2(nrm.module, switches_response=switches_response)

    _run_deploy(nrm, fake_nd)

    paths = fake_nd.paths()
    assert SAVE_PATH in paths  # save stays fabric-scoped configSave
    assert SWITCHES_PATH in paths  # switch inventory queried at deploy time
    assert GLOBAL_DEPLOY_PATH not in paths
    assert SWITCH_DEPLOY_PATH in paths
    assert fake_nd.payloads_for(SWITCH_DEPLOY_PATH) == [{"switchIds": ["FOX111AAA", "FOX333AAA"]}]


def test_manage_vpc_pair_deploy_00030_switch_scope_noop_when_all_in_sync():
    # type=switch with every switch in-sync: still saves, queries switches, but
    # never posts an empty switchActions/deploy.
    nrm = _make_nrm("switch")
    switches_response = {
        "switches": [
            {"serialNumber": "FOX222AAA", "configSyncStatus": "In-Sync"},
            {"serialNumber": "FOX444AAA", "additionalData": {"configSyncStatus": "in_sync"}},
        ]
    }
    fake_nd = _FakeNDModuleV2(nrm.module, switches_response=switches_response)

    _run_deploy(nrm, fake_nd)

    paths = fake_nd.paths()
    assert SAVE_PATH in paths
    assert SWITCHES_PATH in paths
    assert SWITCH_DEPLOY_PATH not in paths


def test_manage_vpc_pair_deploy_00040_check_mode_switch_scope_previews_switch_endpoint():
    # check_mode must be side-effect free: no NDModuleV2 is constructed and the
    # preview names the switch-scoped endpoint.
    nrm = _make_nrm("switch", check_mode=True)

    with patch.object(deploy, "NDModuleV2", _boom):
        out = deploy.custom_vpc_deploy(nrm, "fab1", {"changed": True})

    assert out["deployment_needed"] is True
    planned = out["planned_actions"]
    assert any(SAVE_PATH in action for action in planned)
    assert any(SWITCH_DEPLOY_PATH in action for action in planned)
    assert any('"switchIds"' in action for action in planned)
    assert all(GLOBAL_DEPLOY_PATH not in action for action in planned)


def test_manage_vpc_pair_deploy_00050_check_mode_global_scope_previews_fabric_endpoint():
    nrm = _make_nrm("global", check_mode=True)

    with patch.object(deploy, "NDModuleV2", _boom):
        out = deploy.custom_vpc_deploy(nrm, "fab1", {"changed": True})

    planned = out["planned_actions"]
    assert any(GLOBAL_DEPLOY_PATH in action for action in planned)
    assert all(SWITCH_DEPLOY_PATH not in action for action in planned)


def test_manage_vpc_pair_deploy_00060_global_deploy_failure_raises_vpc_error():
    # Save succeeds, the fabric deploy fails -> structured VpcPairResourceError.
    nrm = _make_nrm("global")
    fake_nd = _FakeNDModuleV2(
        nrm.module,
        fail_on="/actions/deploy",
        fail_exception=NDModuleError(msg="deploy boom", status=500),
    )

    with patch.object(deploy, "NDModuleV2", lambda module: fake_nd):
        with pytest.raises(VpcPairResourceError) as exc:
            deploy.custom_vpc_deploy(nrm, "fab1", {"changed": True})

    assert exc.value.msg == "Fabric deployment failed"
    assert SAVE_PATH in fake_nd.paths()
    assert GLOBAL_DEPLOY_PATH in fake_nd.paths()


def test_manage_vpc_pair_deploy_00070_switch_query_failure_raises_vpc_error():
    # A failed switch inventory lookup during switch-scoped deploy surfaces as a
    # deploy failure and never posts to switchActions/deploy.
    nrm = _make_nrm("switch")
    fake_nd = _FakeNDModuleV2(
        nrm.module,
        switches_exception=NDModuleError(msg="switch query boom", status=500),
    )

    with patch.object(deploy, "NDModuleV2", lambda module: fake_nd):
        with pytest.raises(VpcPairResourceError) as exc:
            deploy.custom_vpc_deploy(nrm, "fab1", {"changed": True})

    assert exc.value.msg == "Fabric deployment failed"
    assert SWITCHES_PATH in fake_nd.paths()
    assert SWITCH_DEPLOY_PATH not in fake_nd.paths()


def test_manage_vpc_pair_deploy_00080_fabric_utils_deploy_switches_posts_switch_endpoint():
    fake_nd = _FakeNDModuleV2(_FakeModule({}))
    fabric_utils = FabricUtils(fake_nd, "fab1")

    out = fabric_utils.deploy_switches(["FOX111AAA", "FOX222AAA"])

    assert len(fake_nd.calls) == 1
    path, _verb, payload = fake_nd.calls[0]
    assert path == SWITCH_DEPLOY_PATH
    assert payload == {"switchIds": ["FOX111AAA", "FOX222AAA"]}
    assert out["path"] == SWITCH_DEPLOY_PATH
    assert out["status"] == 200


def test_manage_vpc_pair_deploy_00090_switch_deploy_path_builders_match_endpoint():
    assert FabricUtils.build_switch_deploy_path("fab1") == SWITCH_DEPLOY_PATH
    fabric_utils = FabricUtils(_FakeNDModuleV2(_FakeModule({})), "fab1")
    assert fabric_utils.switch_deploy_path == SWITCH_DEPLOY_PATH


def test_manage_vpc_pair_deploy_00100_get_switches_needing_deploy_filters_and_sorts():
    # In-sync excluded; out-of-sync + unknown included; duplicate serials deduped;
    # result sorted for deterministic payloads.
    switches_response = {
        "switches": [
            {"serialNumber": "FOXZZZ", "configSyncStatus": "In-Sync"},
            {"serialNumber": "FOXBBB", "configSyncStatus": "Pending"},
            {"serialNumber": "FOXAAA"},
            {"serialNumber": "FOXAAA", "configSyncStatus": "Out-of-Sync"},
        ]
    }
    fake_nd = _FakeNDModuleV2(_FakeModule({}), switches_response=switches_response)

    result = deploy._get_switches_needing_deploy(fake_nd, "fab1")

    assert result == ["FOXAAA", "FOXBBB"]


def _make_resource_nrm(config, save=True, deploy_flag=True, check_mode=False):
    params = {
        "fabric_name": "fab1",
        "config_actions": {"save": save, "deploy": deploy_flag, "type": "resource"},
        "config": config,
    }
    return _FakeNrm(params, check_mode=check_mode)


def test_manage_vpc_pair_deploy_00110_resource_scope_deploys_only_managed_pair_switches():
    # type=resource scopes switchActions/deploy to just the managed pair's peers
    # that are out-of-sync, ignoring unrelated out-of-sync switches in the fabric.
    nrm = _make_resource_nrm(config=[{"switch_id": "FOX111AAA", "peer_switch_id": "FOX222AAA"}])
    switches_response = {
        "switches": [
            {"serialNumber": "FOX111AAA", "configSyncStatus": "Out-of-Sync"},
            {"serialNumber": "FOX222AAA", "configSyncStatus": "Out-of-Sync"},
            {"serialNumber": "FOX999ZZZ", "configSyncStatus": "Out-of-Sync"},  # unrelated -> excluded
        ]
    }
    fake_nd = _FakeNDModuleV2(nrm.module, switches_response=switches_response)

    _run_deploy(nrm, fake_nd)

    paths = fake_nd.paths()
    assert SAVE_PATH in paths
    assert SWITCHES_PATH in paths
    assert GLOBAL_DEPLOY_PATH not in paths
    assert SWITCH_DEPLOY_PATH in paths
    assert fake_nd.payloads_for(SWITCH_DEPLOY_PATH) == [{"switchIds": ["FOX111AAA", "FOX222AAA"]}]


def test_manage_vpc_pair_deploy_00120_resource_scope_warns_when_peer_not_in_inventory():
    # Peers absent from fabric inventory (typo/wrong fabric) must warn instead of
    # silently no-opping, and no switchActions/deploy is posted.
    nrm = _make_resource_nrm(config=[{"switch_id": "FOXABSENT1", "peer_switch_id": "FOXABSENT2"}])
    switches_response = {
        "switches": [
            {"serialNumber": "FOX111AAA", "configSyncStatus": "Out-of-Sync"},  # unrelated
        ]
    }
    fake_nd = _FakeNDModuleV2(nrm.module, switches_response=switches_response)

    _run_deploy(nrm, fake_nd)

    assert SWITCH_DEPLOY_PATH not in fake_nd.paths()
    assert any("not found in fabric" in warning for warning in nrm.module.warnings)


def test_manage_vpc_pair_deploy_00130_resource_scope_noop_when_pair_in_sync():
    # type=resource with both pair switches in-sync: still saves and queries the
    # inventory, but never posts switchActions/deploy even if other switches are
    # out-of-sync.
    nrm = _make_resource_nrm(config=[{"switch_id": "FOX111AAA", "peer_switch_id": "FOX222AAA"}])
    switches_response = {
        "switches": [
            {"serialNumber": "FOX111AAA", "configSyncStatus": "In-Sync"},
            {"serialNumber": "FOX222AAA", "additionalData": {"configSyncStatus": "in_sync"}},
            {"serialNumber": "FOX999ZZZ", "configSyncStatus": "Out-of-Sync"},  # unrelated
        ]
    }
    fake_nd = _FakeNDModuleV2(nrm.module, switches_response=switches_response)

    _run_deploy(nrm, fake_nd)

    paths = fake_nd.paths()
    assert SAVE_PATH in paths
    assert SWITCHES_PATH in paths
    assert SWITCH_DEPLOY_PATH not in paths


def test_manage_vpc_pair_deploy_00140_check_mode_resource_scope_previews_switch_endpoint():
    # check_mode resource preview names the switch-scoped endpoint and stays
    # side-effect free (no NDModuleV2 construction).
    nrm = _make_resource_nrm(config=[{"switch_id": "FOX111AAA", "peer_switch_id": "FOX222AAA"}], check_mode=True)

    with patch.object(deploy, "NDModuleV2", _boom):
        out = deploy.custom_vpc_deploy(nrm, "fab1", {"changed": True})

    assert out["deployment_needed"] is True
    planned = out["planned_actions"]
    assert any(SWITCH_DEPLOY_PATH in action for action in planned)
    assert all(GLOBAL_DEPLOY_PATH not in action for action in planned)


def test_manage_vpc_pair_deploy_00150_get_managed_pair_switches_scopes_and_filters_sync():
    # Direct helper check: managed pair serials are matched to inventory and
    # filtered to out-of-sync; unrelated out-of-sync switches are excluded and no
    # spurious warning is emitted when every peer resolves.
    switches_response = {
        "switches": [
            {"serialNumber": "FOXAAA", "configSyncStatus": "Out-of-Sync"},
            {"serialNumber": "FOXBBB", "configSyncStatus": "In-Sync"},
            {"serialNumber": "FOXCCC", "configSyncStatus": "Out-of-Sync"},  # unrelated
        ]
    }
    module = _FakeModule({})
    fake_nd = _FakeNDModuleV2(module, switches_response=switches_response)
    config_entries = [{"switch_id": "FOXAAA", "peer_switch_id": "FOXBBB"}]

    result = deploy._get_managed_pair_switches_needing_deploy(fake_nd, "fab1", config_entries)

    # FOXAAA out-of-sync -> included; FOXBBB in-sync -> excluded; FOXCCC unrelated -> excluded
    assert result == ["FOXAAA"]
    assert module.warnings == []
