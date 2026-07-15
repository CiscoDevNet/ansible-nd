# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from unittest.mock import patch

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair import actions
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.exceptions import (
    VpcPairResourceError,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import (
    VpcFieldNames,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    FabricTypeEnum,
)


class _FakeModule:
    def __init__(self, params, check_mode=False):
        self.params = params
        self.check_mode = check_mode
        self.warnings = []

    def warn(self, msg):
        self.warnings.append(msg)


class _FakeNrm:
    def __init__(self, params, proposed_config, existing_config=None):
        self.module = _FakeModule(params)
        self.proposed_config = proposed_config
        self.existing_config = existing_config or {}
        self.current_identifier = (
            proposed_config.get(VpcFieldNames.SWITCH_ID),
            proposed_config.get(VpcFieldNames.PEER_SWITCH_ID),
        )


class _FakeNDModuleV2:
    def __init__(self, module):
        self.module = module

    def request(self, path, verb, payload=None):
        if path == "/api/v1/manage/fabrics/fab1":
            mgmt_type = self.module.params.get("_test_management_type_response", "")
            if mgmt_type:
                return {"management": {"type": mgmt_type}}
            return {}
        if path == "/api/v1/manage/fabrics/fab1/switches":
            fabric_type = self.module.params.get("_test_switch_fabric_type", "")
            if fabric_type:
                return [{"fabricType": fabric_type}]
            return []
        return {}


@pytest.fixture
def _base_params():
    return {
        "fabric_name": "fab1",
        "_have": [],
        "_fabric_type": "",
    }


@pytest.fixture
def _details_config():
    return {
        VpcFieldNames.SWITCH_ID: "SN01",
        VpcFieldNames.PEER_SWITCH_ID: "SN02",
        VpcFieldNames.USE_VIRTUAL_PEER_LINK: False,
        "vpc_pair_details": {
            "type": "default",
            "domain_id": 1,
            "keep_alive_vrf": "management",
        },
    }


def test_manage_vpc_pair_actions_00010_block_vpc_pair_details_on_ibgp_create(_base_params, _details_config):
    nrm = _FakeNrm(
        {**_base_params, "_test_management_type_response": "vxlanIbgp"},
        _details_config,
    )

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        with pytest.raises(VpcPairResourceError) as exc:
            actions.custom_vpc_create(nrm)

    assert "vpc_pair_details" in exc.value.msg
    assert "iBGP/eBGP VXLAN fabrics" in exc.value.msg


def test_manage_vpc_pair_actions_00020_block_vpc_pair_details_on_ebgp_update(_base_params, _details_config):
    nrm = _FakeNrm(
        {**_base_params, "_test_management_type_response": "vxlanEbgp"},
        _details_config,
        existing_config={
            VpcFieldNames.SWITCH_ID: "SN01",
            VpcFieldNames.PEER_SWITCH_ID: "SN02",
            VpcFieldNames.USE_VIRTUAL_PEER_LINK: False,
        },
    )

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        with pytest.raises(VpcPairResourceError) as exc:
            actions.custom_vpc_update(nrm)

    assert "vpc_pair_details" in exc.value.msg
    assert "iBGP/eBGP VXLAN fabrics" in exc.value.msg


def test_manage_vpc_pair_actions_00030_allow_vpc_pair_details_on_external(_base_params, _details_config):
    nrm = _FakeNrm(
        {
            **_base_params,
            "_fabric_type": FabricTypeEnum.EXTERNAL_CONNECTIVITY.value,
        },
        _details_config,
    )

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        with patch.object(actions, "_validate_switches_exist_in_fabric", return_value=None):
            with patch.object(actions, "_get_pairing_support_details", return_value=None):
                with patch.object(actions, "_validate_fabric_peering_support", return_value=None):
                    with patch.object(actions, "_build_vpc_pair_payload", return_value={"ok": True}):
                        response = actions.custom_vpc_create(nrm)

    assert response == {}


def test_manage_vpc_pair_actions_00040_allow_vpc_pair_details_when_fabric_type_unknown(_base_params, _details_config):
    nrm = _FakeNrm(_base_params, _details_config)

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        with patch.object(actions, "_validate_switches_exist_in_fabric", return_value=None):
            with patch.object(actions, "_get_pairing_support_details", return_value=None):
                with patch.object(actions, "_validate_fabric_peering_support", return_value=None):
                    with patch.object(actions, "_build_vpc_pair_payload", return_value={"ok": True}):
                        response = actions.custom_vpc_create(nrm)

    assert response == {}


def test_manage_vpc_pair_actions_00050_get_proposed_vpc_pair_details_normalizes_empty_values():
    assert actions._get_proposed_vpc_pair_details({"vpc_pair_details": {}}) is None
    assert actions._get_proposed_vpc_pair_details({"vpc_pair_details": []}) is None
    assert actions._get_proposed_vpc_pair_details({"vpc_pair_details": "x"}) is None
    assert actions._get_proposed_vpc_pair_details({"vpc_pair_details": {"domain_id": 10}}) == {"domain_id": 10}


def test_manage_vpc_pair_actions_00060_resolve_fabric_type_handles_empty_exception_message():
    class _RaisingNDModuleV2:
        def request(self, path, verb, payload=None):
            raise Exception()

    module = _FakeModule({"_fabric_type": ""})
    fabric_type = actions._resolve_fabric_type(_RaisingNDModuleV2(), "fab1", module)

    assert fabric_type == ""
    assert len(module.warnings) == 1
    assert "unknown error" in module.warnings[0]


def test_manage_vpc_pair_actions_00070_resolve_fabric_type_uses_management_type():
    class _PrecedenceNDModuleV2:
        def request(self, path, verb, payload=None):
            if path == "/api/v1/manage/fabrics/fab1/switches":
                return [{"fabricType": "vxlanEbgp"}]
            return {
                "fabricType": "VXLAN",
                "management": {"type": FabricTypeEnum.VXLAN_EBGP.value},
            }

    module = _FakeModule({"_fabric_type": ""})
    fabric_type = actions._resolve_fabric_type(_PrecedenceNDModuleV2(), "fab1", module)

    assert fabric_type == FabricTypeEnum.VXLAN_EBGP.value
    assert module.params.get("_fabric_type") == FabricTypeEnum.VXLAN_EBGP.value


def test_manage_vpc_pair_actions_00080_resolve_fabric_type_does_not_infer_from_other_fields():
    class _NoManagementTypeNDModuleV2:
        def request(self, path, verb, payload=None):
            return {"fabricType": "VXLAN_EBGP"}

    module = _FakeModule({"_fabric_type": ""})
    fabric_type = actions._resolve_fabric_type(_NoManagementTypeNDModuleV2(), "fab1", module)

    assert fabric_type == ""
    assert module.params.get("_fabric_type") == ""
