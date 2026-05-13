# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for vpc_access_interface orchestrator.

Verifies that `AccessVpcHostInterfaceOrchestrator` correctly:
- declares the right `model_class` and `_managed_policy_types`
- inherits bulk-support flags from `VpcInterfaceBaseOrchestrator`
- resolves the peer switch's serial via the vPC pair GET endpoint
- raises a clear `RuntimeError` when the primary switch is not in a vPC pair
- caches peer-serial lookups per orchestrator instance
- filters fabric-wide interface results to `interfaceType: "vpc"` plus the managed
  policy types (so non-vPC interfaces and other-flavor vPCs are excluded)
- propagates `RuntimeError` from the inherited `validate_prerequisites` path

Uses the file-based `Sender` from `tests/unit/module_utils/sender_file.py` as the
`sender` dependency injected into a real `RestSend`. Responses are read from
`tests/unit/module_utils/fixtures/fixture_data/test_vpc_access_interface_orchestrator.json`.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_access_interface import (
    AccessVpcHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_access_interface import (
    AccessVpcHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_vpc_access(key: str):
    """Load fixture data for the orchestrator's test_vpc_access_interface_orchestrator.json file."""
    return load_fixture("test_vpc_access_interface_orchestrator")[key]


def _build_rest_send(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1") -> RestSend:
    """Build a RestSend wired to the file-based Sender and the real ResponseHandler."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    rest_send = RestSend({"check_mode": False, "fabric_name": fabric_name})
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _build_orchestrator(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1") -> AccessVpcHostInterfaceOrchestrator:
    """Construct an orchestrator with the file-based RestSend injected."""
    rest_send = _build_rest_send(gen_responses, fabric_name=fabric_name)
    return AccessVpcHostInterfaceOrchestrator(rest_send=rest_send)


# =============================================================================
# Test: ClassVar / model_class
# =============================================================================


def test_vpc_access_orchestrator_00010() -> None:
    """
    # Summary

    Verify `model_class` points to `AccessVpcHostInterfaceModel`.

    ## Test

    - model_class is AccessVpcHostInterfaceModel

    ## Classes and Methods

    - AccessVpcHostInterfaceOrchestrator.model_class
    """
    assert AccessVpcHostInterfaceOrchestrator.model_class is AccessVpcHostInterfaceModel


def test_vpc_access_orchestrator_00020() -> None:
    """
    # Summary

    Verify bulk-support flags inherited from `VpcInterfaceBaseOrchestrator`. Bulk-create is enabled (POST /interfaces accepts
    an array); bulk-delete is disabled because ND 4.2.1's `interfaceActions/remove` returns `Invalid Interface` for
    vPC entries — we use per-interface `DELETE` instead via the state machine's individual delete path.

    ## Test

    - supports_bulk_create is True
    - supports_bulk_delete is False

    ## Classes and Methods

    - AccessVpcHostInterfaceOrchestrator
    """
    assert AccessVpcHostInterfaceOrchestrator.supports_bulk_create is True
    assert AccessVpcHostInterfaceOrchestrator.supports_bulk_delete is False


# =============================================================================
# Test: _managed_policy_types
# =============================================================================


def test_vpc_access_orchestrator_00100() -> None:
    """
    # Summary

    Verify `_managed_policy_types` returns the single `"accessVpcHost"` API value.

    ## Test

    - Returned set contains exactly "accessVpcHost"

    ## Classes and Methods

    - AccessVpcHostInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    assert orchestrator._managed_policy_types() == {"accessVpcHost"}


def test_vpc_access_orchestrator_00110() -> None:
    """
    # Summary

    Verify `_managed_policy_types` returns a set.

    ## Test

    - Return type is set

    ## Classes and Methods

    - AccessVpcHostInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    result = orchestrator._managed_policy_types()
    assert isinstance(result, set)
    assert "accessVpcHost" in result


# =============================================================================
# Test: _resolve_peer_switch_id
# =============================================================================


def test_vpc_access_orchestrator_00500_peer_resolve_happy() -> None:
    """
    # Summary

    Verify `_resolve_peer_switch_id` returns the peer serial when the primary is in a vPC pair.

    ## Test

    - GET /vpcPair returns peerSwitchId
    - Helper returns that value
    - Result is cached on the orchestrator

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator._resolve_peer_switch_id()
    """

    def responses():
        yield responses_vpc_access("test_peer_resolve_happy_path_00500a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)

    with does_not_raise():
        peer = orchestrator._resolve_peer_switch_id("192.168.1.1", "FDO11111AAA")
    assert peer == "FDO22222BBB"
    assert orchestrator._peer_serial_cache == {"FDO11111AAA": "FDO22222BBB"}


def test_vpc_access_orchestrator_00505_peer_resolve_cached() -> None:
    """
    # Summary

    Verify `_resolve_peer_switch_id` returns the cached value without issuing a second GET.

    ## Test

    - First call fetches and caches
    - Second call returns the cached value (no additional response is yielded)

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator._resolve_peer_switch_id()
    """

    def responses():
        yield responses_vpc_access("test_peer_resolve_happy_path_00500a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)

    first = orchestrator._resolve_peer_switch_id("192.168.1.1", "FDO11111AAA")
    second = orchestrator._resolve_peer_switch_id("192.168.1.1", "FDO11111AAA")
    assert first == second == "FDO22222BBB"


def test_vpc_access_orchestrator_00510_peer_resolve_not_paired() -> None:
    """
    # Summary

    Verify `_resolve_peer_switch_id` raises a clear RuntimeError when the primary switch is not in a vPC pair.

    ## Test

    - GET /vpcPair returns 404 (live-lab structured error body)
    - Helper raises RuntimeError mentioning the switch_ip and pointing the user at nd_manage_vpc_pair

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator._resolve_peer_switch_id()
    """

    def responses():
        yield responses_vpc_access("test_peer_resolve_not_paired_00510a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)

    with pytest.raises(RuntimeError, match=r"192\.168\.1\.1.*not in a vPC pair.*nd_manage_vpc_pair"):
        orchestrator._resolve_peer_switch_id("192.168.1.1", "FDO11111AAA")


def test_vpc_access_orchestrator_00520_peer_resolve_missing_field() -> None:
    """
    # Summary

    Verify `_resolve_peer_switch_id` raises RuntimeError when the vPC pair record is missing `peerSwitchId`.

    ## Test

    - GET /vpcPair returns 200 but body omits peerSwitchId
    - Helper raises RuntimeError mentioning the missing field

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator._resolve_peer_switch_id()
    """

    def responses():
        yield responses_vpc_access("test_peer_resolve_missing_field_00520a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)

    with pytest.raises(RuntimeError, match=r"missing 'peerSwitchId'"):
        orchestrator._resolve_peer_switch_id("192.168.1.1", "FDO11111AAA")


# =============================================================================
# Test: query_all — happy path with filtering
# =============================================================================


def test_vpc_access_orchestrator_00600_delete_uses_per_interface_endpoint() -> None:
    """
    # Summary

    Verify `delete()` calls the per-interface `DELETE /interfaces/{name}` endpoint (not the bulk
    `interfaceActions/remove` which silently fails for vPC on ND 4.2.1) and queues a deploy for the same
    `(interface_name, switch_id)` pair.

    ## Test

    - Switch-map fixture resolves switch_ip -> switch_id
    - DELETE call returns 204 (no body)
    - delete() does not raise
    - Deploy queue contains exactly one entry: (vpc100, FDOAAAAAAAA)

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.delete()
    """
    method_name = "test_delete_per_interface_00600"

    def responses():
        yield {
            "RETURN_CODE": 200,
            "METHOD": "GET",
            "REQUEST_PATH": "/api/v1/manage/fabrics/fabric_1/switches",
            "MESSAGE": "OK",
            "DATA": {"switches": [{"fabricManagementIp": "192.168.1.1", "switchId": "FDOAAAAAAAA"}]},
        }
        yield {
            "RETURN_CODE": 204,
            "METHOD": "DELETE",
            "REQUEST_PATH": "/api/v1/manage/fabrics/fabric_1/switches/FDOAAAAAAAA/interfaces/vpc100",
            "MESSAGE": "No Content",
            "DATA": {},
        }

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)

    from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_access_interface import (
        AccessVpcHostInterfaceModel,
    )

    model = AccessVpcHostInterfaceModel(switch_ip="192.168.1.1", interface_name="vpc100")
    with does_not_raise():
        orchestrator.delete(model)

    assert orchestrator._pending_deploys == [("vpc100", "FDOAAAAAAAA")]
    # Bulk-remove queue stays untouched because we use per-interface DELETE.
    assert orchestrator._pending_removes == []
    # Sanity reference
    assert method_name.endswith("00600")


def test_vpc_access_orchestrator_00400_query_all_happy() -> None:
    """
    # Summary

    Verify `query_all` validates the fabric, iterates all switches, filters to interfaceType=="vpc"
    and policyType=="accessVpcHost", and injects `switchIp` onto each kept interface.

    ## Test

    - Fabric summary (validate_prerequisites) returns 200
    - Switches list returns two switches
    - Switch 1 returns: configured accessVpcHost vpc, trunkVpcHost vpc, ethernet trunkHost
    - Switch 2 returns: one configured accessVpcHost vpc
    - Result contains exactly the two accessVpcHost vPC interfaces
    - Each has switchIp injected with the fabricManagementIp

    ## Classes and Methods

    - AccessVpcHostInterfaceOrchestrator._managed_policy_types()
    - VpcInterfaceBaseOrchestrator.query_all()
    """

    def responses():
        yield responses_vpc_access("test_query_all_happy_path_00400a")
        yield responses_vpc_access("test_query_all_happy_path_00400b")
        yield responses_vpc_access("test_query_all_happy_path_00400c")
        yield responses_vpc_access("test_query_all_happy_path_00400d")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 2

    by_name = {iface["interfaceName"]: iface for iface in result}
    assert set(by_name) == {"vpc100", "vpc200"}

    assert by_name["vpc100"]["switchIp"] == "192.168.1.1"
    assert by_name["vpc200"]["switchIp"] == "192.168.1.2"

    # Filtered out: trunkVpcHost (vpc101) and ethernet trunkHost (Ethernet1/1)
    assert "vpc101" not in by_name
    assert "Ethernet1/1" not in by_name


def test_vpc_access_orchestrator_00410_query_all_no_match() -> None:
    """
    # Summary

    Verify `query_all` returns an empty list when no switch reports any accessVpcHost vPC.

    ## Test

    - Switch returns only non-vPC and non-accessVpcHost vPC interfaces
    - Result is an empty list

    ## Classes and Methods

    - AccessVpcHostInterfaceOrchestrator._managed_policy_types()
    - VpcInterfaceBaseOrchestrator.query_all()
    """

    def responses():
        yield responses_vpc_access("test_query_all_no_match_00410a")
        yield responses_vpc_access("test_query_all_no_match_00410b")
        yield responses_vpc_access("test_query_all_no_match_00410c")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        result = orchestrator.query_all()

    assert result == []


def test_vpc_access_orchestrator_00430_query_all_dedup() -> None:
    """
    # Summary

    Verify `query_all` dedupes vPC interfaces that appear on both peers. ND returns each vPC interface twice
    (once per peer GET) with identical configData; without dedupe, `_manage_override_deletions` would treat the
    peer-side copy as "not in proposed" and queue a spurious delete.

    ## Test

    - Two switches in the fabric, both return the same `vpc100` configuration
    - Result contains exactly ONE entry for `vpc100`
    - Canonical representative is the entry with the alphabetically-lower `switchId`
      (FDOAAAAAAAA = 192.168.1.1 is kept; FDOBBBBBBBB = 192.168.1.2 is dropped)

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.query_all() dedupe logic
    """

    def responses():
        yield responses_vpc_access("test_query_all_dedup_00430a")
        yield responses_vpc_access("test_query_all_dedup_00430b")
        yield responses_vpc_access("test_query_all_dedup_00430c")
        yield responses_vpc_access("test_query_all_dedup_00430d")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["interfaceName"] == "vpc100"
    # Canonical representative is the lower-switchId one
    assert result[0]["switchIp"] == "192.168.1.1"
    assert result[0]["configData"]["networkOS"]["policy"]["peerSwitchId"] == "FDOBBBBBBBB"


def test_vpc_access_orchestrator_00420_query_all_fabric_not_found() -> None:
    """
    # Summary

    Verify `query_all` raises `RuntimeError` when the fabric does not exist.

    ## Test

    - Fabric summary returns 404
    - query_all raises RuntimeError with "Query all failed"

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.query_all()
    - FabricContext.validate_for_mutation()
    """

    def responses():
        yield responses_vpc_access("test_query_all_fabric_not_found_00420a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses, fabric_name="missing_fabric")

    with pytest.raises(RuntimeError, match=r"Query all failed.*missing_fabric"):
        orchestrator.query_all()
