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
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vpc_pair.vpc_pair_model import (
    VpcPairModel,
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


def test_manage_vpc_pair_actions_00040_preflight_allows_unknown_fabric_type(_base_params):
    # Only the explicit blocked set (iBGP/eBGP VXLAN) is rejected; any other
    # fabric type (including an unknown/future value) accepts explicit details.
    proposed_item = _details_model()
    nrm = _FakeNrm(
        {**_base_params, "_test_management_type_response": "futureFabricType"},
        _inherited_payload(),
    )

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        actions.validate_proposed_details_support(nrm, proposed_item)

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


def test_manage_vpc_pair_actions_00130_cache_reuses_successful_fabric_type(_base_params):
    class _CountingNDModuleV2:
        def __init__(self):
            self.request_count = 0

        def request(self, path, verb, payload=None):
            self.request_count += 1
            return {"management": {"type": FabricTypeEnum.EXTERNAL_CONNECTIVITY.value}}

    nrm = _FakeNrm(_base_params, {})
    nd_v2 = _CountingNDModuleV2()

    actions._ensure_fabric_type(nrm, nd_v2, "fab1")
    actions._ensure_fabric_type(nrm, nd_v2, "fab1")

    assert nd_v2.request_count == 1
    assert nrm.fabric_type == FabricTypeEnum.EXTERNAL_CONNECTIVITY.value


def test_manage_vpc_pair_actions_00135_failed_resolution_does_not_populate_cache(_base_params):
    class _MalformedResponseNDModuleV2:
        def request(self, path, verb, payload=None):
            return {}

    nrm = _FakeNrm(_base_params, {})

    with pytest.raises(VpcPairResourceError):
        actions._ensure_fabric_type(nrm, _MalformedResponseNDModuleV2(), "fab1")

    assert nrm.fabric_type is None


@pytest.mark.parametrize(
    "proposed_item",
    [
        {},
        {"vpc_pair_details": {}},
        {VpcFieldNames.VPC_PAIR_DETAILS: []},
    ],
)
def test_manage_vpc_pair_actions_00140_no_details_skips_fabric_lookup(_base_params, proposed_item):
    class _NeverCalledNDModuleV2:
        def __init__(self, module=None):
            pass

        def request(self, path, verb, payload=None):
            raise AssertionError("fabric lookup should not be called")

    nrm = _FakeNrm(_base_params, {})

    with patch.object(actions, "NDModuleV2", _NeverCalledNDModuleV2):
        actions.validate_proposed_details_support(nrm, proposed_item)

    assert nrm.fabric_type is None


# ---------------------------------------------------------------------------
# Fix for GitHub review comment (actions.py:147): fabric-support validation must
# examine the raw user intent, not the reconciled/merged state. These tests
# exercise the two helpers wired into the state machine
# (``_manage_create_update_state``):
#   * ``validate_proposed_details_support`` runs BEFORE the diff/no_diff decision
#     so an unsupported field is rejected even when it matches existing state
#     (an idempotent request must not silently accept a prohibited field), and it
#     only considers fields the user explicitly supplied.
#   * ``strip_inherited_details_for_blocked_fabric`` removes merge-inherited
#     vpcPairDetails from the outgoing payload on blocked fabrics so the field is
#     never sent back to Nexus Dashboard, while leaving explicit and
#     External/ISN/LANClassic details intact.
# ---------------------------------------------------------------------------

_DETAILS_INPUT = {"type": "default", "domain_id": 1}


def _details_model():
    """Raw user model that explicitly supplies vpc_pair_details."""
    return VpcPairModel.from_config(
        {
            "switch_id": "SN01",
            "peer_switch_id": "SN02",
            "use_virtual_peer_link": False,
            "vpc_pair_details": dict(_DETAILS_INPUT),
        }
    )


def _no_details_model():
    """Raw user model that omits vpc_pair_details (id-only intent)."""
    return VpcPairModel.from_config(
        {
            "switch_id": "SN01",
            "peer_switch_id": "SN02",
            "use_virtual_peer_link": False,
        }
    )


def _inherited_payload():
    """Reconciled payload that carries vpcPairDetails (e.g. inherited via merge)."""
    return {
        VpcFieldNames.SWITCH_ID: "SN01",
        VpcFieldNames.PEER_SWITCH_ID: "SN02",
        VpcFieldNames.USE_VIRTUAL_PEER_LINK: False,
        VpcFieldNames.VPC_PAIR_DETAILS: dict(_DETAILS_INPUT),
    }


@pytest.mark.parametrize(
    "blocked_type",
    [FabricTypeEnum.VXLAN_IBGP.value, FabricTypeEnum.VXLAN_EBGP.value],
)
@pytest.mark.parametrize("check_mode", [False, True])
def test_manage_vpc_pair_actions_00180_preflight_rejects_explicit_details_even_when_idempotent(_base_params, check_mode, blocked_type):
    # Mike case 1 (+ check mode): explicit unsupported details are rejected from
    # the raw user intent, regardless of whether the requested value already
    # matches controller state. The preflight never consults existing_config, so
    # the state machine's no_diff early-return cannot silently accept the field.
    # Parametrized over both blocked fabric types (iBGP/eBGP VXLAN) and check
    # mode, replacing the retired handler-level block tests.
    proposed_item = _details_model()
    nrm = _FakeNrm(
        {**_base_params, "_test_management_type_response": blocked_type},
        _inherited_payload(),
        existing_config=_inherited_payload(),
        check_mode=check_mode,
    )

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        with pytest.raises(VpcPairResourceError) as exc:
            actions.validate_proposed_details_support(nrm, proposed_item)

    assert "vpc_pair_details" in exc.value.msg
    assert "iBGP/eBGP VXLAN fabrics" in exc.value.msg


def test_manage_vpc_pair_actions_00190_preflight_ignores_omitted_details_without_fabric_lookup(_base_params):
    # Mike case 2 (preflight half): when the user omits details, merge-inherited
    # details must not be treated as user intent, and no controller lookup runs.
    proposed_item = _no_details_model()
    nrm = _FakeNrm(
        {**_base_params, "_test_management_type_response": FabricTypeEnum.VXLAN_IBGP.value},
        _inherited_payload(),
    )

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        actions.validate_proposed_details_support(nrm, proposed_item)

    assert nrm.fabric_type is None
    assert "_test_request_count" not in nrm.module.params


def test_manage_vpc_pair_actions_00200_preflight_allows_explicit_details_on_external(_base_params):
    # Mike point 4: External continues to accept explicitly supplied details.
    proposed_item = _details_model()
    nrm = _FakeNrm(
        {**_base_params, "_test_management_type_response": FabricTypeEnum.EXTERNAL_CONNECTIVITY.value},
        _inherited_payload(),
    )

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        actions.validate_proposed_details_support(nrm, proposed_item)

    assert nrm.fabric_type == FabricTypeEnum.EXTERNAL_CONNECTIVITY.value


def test_manage_vpc_pair_actions_00210_sanitize_strips_inherited_details_on_blocked_fabric(_base_params):
    # Mike case 2 + point 3: inherited details are stripped from the outgoing
    # payload on blocked fabrics, so the update does NOT send vpcPairDetails.
    proposed_item = _no_details_model()
    nrm = _FakeNrm(
        {**_base_params, "_test_management_type_response": FabricTypeEnum.VXLAN_EBGP.value},
        _inherited_payload(),
    )

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        actions.strip_inherited_details_for_blocked_fabric(nrm, proposed_item)

    assert VpcFieldNames.VPC_PAIR_DETAILS not in nrm.proposed_config
    assert "vpc_pair_details" not in nrm.proposed_config


def test_manage_vpc_pair_actions_00220_sanitize_preserves_inherited_details_on_external(_base_params):
    # Mike point 4: External preserves details even when inherited via merge.
    proposed_item = _no_details_model()
    nrm = _FakeNrm(
        {**_base_params, "_test_management_type_response": FabricTypeEnum.EXTERNAL_CONNECTIVITY.value},
        _inherited_payload(),
    )

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        actions.strip_inherited_details_for_blocked_fabric(nrm, proposed_item)

    assert nrm.proposed_config[VpcFieldNames.VPC_PAIR_DETAILS] == _DETAILS_INPUT


def test_manage_vpc_pair_actions_00230_sanitize_keeps_explicit_details_without_fabric_lookup(_base_params):
    # Explicit user details are never stripped by the sanitizer and require no
    # fabric lookup there (they are governed by the preflight validator instead).
    proposed_item = _details_model()
    nrm = _FakeNrm(
        {**_base_params, "_test_management_type_response": FabricTypeEnum.VXLAN_IBGP.value},
        _inherited_payload(),
    )

    with patch.object(actions, "NDModuleV2", _FakeNDModuleV2):
        actions.strip_inherited_details_for_blocked_fabric(nrm, proposed_item)

    assert nrm.proposed_config[VpcFieldNames.VPC_PAIR_DETAILS] == _DETAILS_INPUT
    assert nrm.fabric_type is None
    assert "_test_request_count" not in nrm.module.params
