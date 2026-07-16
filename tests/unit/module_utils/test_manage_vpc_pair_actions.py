# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from unittest.mock import patch

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair import actions
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import (
    VpcFieldNames,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.exceptions import (
    VpcPairResourceError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    FabricTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModuleError


class _FakeModule:
    def __init__(self, params, check_mode=False):
        self.params = params
        self.check_mode = check_mode
        self.warnings = []

    def warn(self, msg):
        self.warnings.append(msg)


class _FakeNrm:
    def __init__(
        self,
        params,
        proposed_config,
        existing_config=None,
        check_mode=False,
        fabric_type=None,
    ):
        self.module = _FakeModule(params, check_mode=check_mode)
        self.proposed_config = proposed_config
        self.existing_config = existing_config or {}
        self.fabric_type = fabric_type
        self.current_identifier = (
            proposed_config.get(VpcFieldNames.SWITCH_ID),
            proposed_config.get(VpcFieldNames.PEER_SWITCH_ID),
        )


class _FakeNDModuleV2:
    def __init__(self, module):
        self.module = module

    def request(self, path, verb, payload=None):
        self.module.params["_test_request_count"] = self.module.params.get("_test_request_count", 0) + 1
        request_exception = self.module.params.get("_test_request_exception")
        if request_exception is not None:
            raise request_exception
        if path == "/api/v1/manage/fabrics/fab1":
            if "_test_fabric_details_response" in self.module.params:
                return self.module.params["_test_fabric_details_response"]
            management_type = self.module.params.get("_test_management_type_response", "")
            if management_type:
                return {"management": {"type": management_type}}
            return {}
        return {}


@pytest.fixture
def _base_params():
    return {
        "fabric_name": "fab1",
        "_have": [],
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


def _run_supported_create(nrm):
    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        with patch.object(actions, "_validate_switches_exist_in_fabric", return_value=None):
            with patch.object(actions, "_get_pairing_support_details", return_value=None):
                with patch.object(actions, "_validate_fabric_peering_support", return_value=None):
                    with patch.object(actions, "_build_vpc_pair_payload", return_value={"ok": True}):
                        return actions.custom_vpc_create(nrm)


def test_manage_vpc_pair_actions_00010_block_vpc_pair_details_on_ibgp_create(_base_params, _details_config):
    nrm = _FakeNrm(
        {
            **_base_params,
            "_test_management_type_response": FabricTypeEnum.VXLAN_IBGP.value,
        },
        _details_config,
    )

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        with pytest.raises(VpcPairResourceError) as exc:
            actions.custom_vpc_create(nrm)

    assert "vpc_pair_details" in exc.value.msg
    assert "iBGP/eBGP VXLAN fabrics" in exc.value.msg


def test_manage_vpc_pair_actions_00020_block_vpc_pair_details_on_ebgp_update(_base_params, _details_config):
    nrm = _FakeNrm(
        {
            **_base_params,
            "_test_management_type_response": FabricTypeEnum.VXLAN_EBGP.value,
        },
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


def test_manage_vpc_pair_actions_00030_allow_cached_external_fabric_type(_base_params, _details_config):
    nrm = _FakeNrm(
        _base_params,
        _details_config,
        fabric_type=FabricTypeEnum.EXTERNAL_CONNECTIVITY.value,
    )

    response = _run_supported_create(nrm)

    assert response == {}


def test_manage_vpc_pair_actions_00040_allow_future_fabric_type(_base_params, _details_config):
    nrm = _FakeNrm(
        {**_base_params, "_test_management_type_response": "futureFabricType"},
        _details_config,
    )

    response = _run_supported_create(nrm)

    assert response == {}
    assert nrm.fabric_type == "futureFabricType"


def test_manage_vpc_pair_actions_00050_get_proposed_vpc_pair_details_normalizes_empty_values():
    assert actions._get_proposed_vpc_pair_details({"vpc_pair_details": {}}) is None
    assert actions._get_proposed_vpc_pair_details({"vpc_pair_details": []}) is None
    assert actions._get_proposed_vpc_pair_details({"vpc_pair_details": "x"}) is None
    assert actions._get_proposed_vpc_pair_details({"vpc_pair_details": {"domain_id": 10}}) == {"domain_id": 10}


def test_manage_vpc_pair_actions_00060_first_exception_line_uses_first_message_line():
    assert actions._first_exception_line(ValueError("first line\nsecond line")) == "first line"


def test_manage_vpc_pair_actions_00070_first_exception_line_uses_exception_class_for_empty_message():
    assert actions._first_exception_line(ValueError()) == "ValueError"


def test_manage_vpc_pair_actions_00080_first_exception_line_rejects_non_exception():
    with pytest.raises(TypeError, match="error must be an exception"):
        actions._first_exception_line(None)


def test_manage_vpc_pair_actions_00090_resolve_fabric_type_uses_management_type_and_encoded_endpoint():
    class _FabricDetailsNDModuleV2:
        def __init__(self):
            self.paths = []

        def request(self, path, verb, payload=None):
            self.paths.append(path)
            return {
                "fabricType": "VXLAN",
                "management": {"type": FabricTypeEnum.VXLAN_EBGP.value},
            }

    nd_v2 = _FabricDetailsNDModuleV2()

    fabric_type = actions._resolve_fabric_type(nd_v2, "fab/name")

    assert fabric_type == FabricTypeEnum.VXLAN_EBGP.value
    assert nd_v2.paths == ["/api/v1/manage/fabrics/fab%2Fname"]


@pytest.mark.parametrize(
    ("request_error", "expected_status"),
    [
        (NDModuleError(msg="controller failed", status=503), 503),
        (ValueError("invalid request settings"), None),
        (TypeError("invalid request type"), None),
    ],
)
def test_manage_vpc_pair_actions_00100_resolve_fabric_type_wraps_expected_request_errors(request_error, expected_status):
    class _RaisingNDModuleV2:
        def request(self, path, verb, payload=None):
            raise request_error

    with pytest.raises(VpcPairResourceError) as exc:
        actions._resolve_fabric_type(_RaisingNDModuleV2(), "fab1")

    assert "Unable to determine fabric type" in exc.value.msg
    assert exc.value.details["exception_type"] == type(request_error).__name__
    if expected_status is not None:
        assert exc.value.details["status"] == expected_status
    else:
        assert "status" not in exc.value.details


def test_manage_vpc_pair_actions_00105_resolve_fabric_type_wraps_endpoint_validation_error():
    class _NeverCalledNDModuleV2:
        def request(self, path, verb, payload=None):
            raise AssertionError("request should not be called")

    with pytest.raises(VpcPairResourceError) as exc:
        actions._resolve_fabric_type(_NeverCalledNDModuleV2(), "x" * 65)

    assert "Unable to determine fabric type" in exc.value.msg
    assert exc.value.details["path"] is None
    assert exc.value.details["exception_type"] == "ValidationError"


def test_manage_vpc_pair_actions_00110_resolve_fabric_type_does_not_hide_unexpected_error():
    class _RaisingNDModuleV2:
        def request(self, path, verb, payload=None):
            raise RuntimeError("programming error")

    with pytest.raises(RuntimeError, match="programming error"):
        actions._resolve_fabric_type(_RaisingNDModuleV2(), "fab1")


@pytest.mark.parametrize(
    "response",
    [
        [],
        {},
        {"management": []},
        {"management": {}},
        {"management": {"type": None}},
        {"management": {"type": "  "}},
        {"fabricType": "VXLAN_EBGP"},
    ],
)
def test_manage_vpc_pair_actions_00120_resolve_fabric_type_rejects_malformed_response(
    response,
):
    class _MalformedResponseNDModuleV2:
        def request(self, path, verb, payload=None):
            return response

    with pytest.raises(VpcPairResourceError) as exc:
        actions._resolve_fabric_type(_MalformedResponseNDModuleV2(), "fab1")

    assert "Unable to determine fabric type" in exc.value.msg


def test_manage_vpc_pair_actions_00130_cache_reuses_successful_fabric_type(_base_params, _details_config):
    class _CountingNDModuleV2:
        def __init__(self):
            self.request_count = 0

        def request(self, path, verb, payload=None):
            self.request_count += 1
            return {"management": {"type": FabricTypeEnum.EXTERNAL_CONNECTIVITY.value}}

    nrm = _FakeNrm(_base_params, _details_config)
    nd_v2 = _CountingNDModuleV2()

    actions._validate_vpc_pair_details_fabric_support(nrm, nd_v2, "fab1")
    actions._validate_vpc_pair_details_fabric_support(nrm, nd_v2, "fab1")

    assert nd_v2.request_count == 1
    assert nrm.fabric_type == FabricTypeEnum.EXTERNAL_CONNECTIVITY.value


def test_manage_vpc_pair_actions_00135_failed_resolution_does_not_populate_cache(_base_params, _details_config):
    class _MalformedResponseNDModuleV2:
        def request(self, path, verb, payload=None):
            return {}

    nrm = _FakeNrm(_base_params, _details_config)

    with pytest.raises(VpcPairResourceError):
        actions._validate_vpc_pair_details_fabric_support(nrm, _MalformedResponseNDModuleV2(), "fab1")

    assert nrm.fabric_type is None


@pytest.mark.parametrize(
    "proposed_config",
    [
        {},
        {"vpc_pair_details": {}},
        {VpcFieldNames.VPC_PAIR_DETAILS: []},
    ],
)
def test_manage_vpc_pair_actions_00140_no_details_skips_fabric_lookup(_base_params, proposed_config):
    class _NeverCalledNDModuleV2:
        def request(self, path, verb, payload=None):
            raise AssertionError("fabric lookup should not be called")

    nrm = _FakeNrm(_base_params, proposed_config)

    actions._validate_vpc_pair_details_fabric_support(nrm, _NeverCalledNDModuleV2(), "fab1")

    assert nrm.fabric_type is None


def test_manage_vpc_pair_actions_00150_check_mode_create_rejects_ibgp_details(_base_params, _details_config):
    nrm = _FakeNrm(
        {
            **_base_params,
            "_test_management_type_response": FabricTypeEnum.VXLAN_IBGP.value,
        },
        _details_config,
        check_mode=True,
    )

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        with pytest.raises(VpcPairResourceError):
            actions.custom_vpc_create(nrm)

    assert nrm.module.params["_test_request_count"] == 1


def test_manage_vpc_pair_actions_00160_check_mode_update_rejects_ebgp_details(_base_params, _details_config):
    nrm = _FakeNrm(
        {
            **_base_params,
            "_test_management_type_response": FabricTypeEnum.VXLAN_EBGP.value,
        },
        _details_config,
        existing_config={VpcFieldNames.SWITCH_ID: "SN01"},
        check_mode=True,
    )

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        with pytest.raises(VpcPairResourceError):
            actions.custom_vpc_update(nrm)

    assert nrm.module.params["_test_request_count"] == 1


def test_manage_vpc_pair_actions_00170_check_mode_allows_supported_details_without_write(_base_params, _details_config):
    nrm = _FakeNrm(
        {
            **_base_params,
            "_test_management_type_response": FabricTypeEnum.EXTERNAL_CONNECTIVITY.value,
        },
        _details_config,
        check_mode=True,
    )

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        response = actions.custom_vpc_create(nrm)

    assert response == _details_config
    assert nrm.fabric_type == FabricTypeEnum.EXTERNAL_CONNECTIVITY.value
    assert nrm.module.params["_test_request_count"] == 1
