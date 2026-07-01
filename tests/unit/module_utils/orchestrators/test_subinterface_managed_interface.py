# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for subinterface_managed_interface orchestrator.

Verifies that `SubinterfaceManagedInterfaceOrchestrator` correctly:
- declares the right `model_class` and bulk-support flags
- filters `query_all` results down to interfaceType=subInterface + managed policyType=subinterface
- builds correct POST/PUT payloads on create/update
- queues remove + deploy on delete (no immediate API call)
- groups create_bulk by switch
- raises on 207 Multi-Status bodies that carry per-item failures

Uses the file-based `Sender` from `tests/unit/module_utils/sender_file.py` as the `sender` injected into a real
`RestSend`. Responses are read from
`tests/unit/module_utils/fixtures/fixture_data/test_subinterface_managed_interface.json`.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.subinterface_managed_interface import SubinterfaceManagedInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.subinterface_managed_interface import SubinterfaceManagedInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_subif(key: str):
    """Load fixture data for the orchestrator's test_subinterface_managed_interface.json file."""
    return load_fixture("test_subinterface_managed_interface")[key]


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


def _build_orchestrator(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1") -> SubinterfaceManagedInterfaceOrchestrator:
    """Construct an orchestrator with the file-based RestSend injected."""
    rest_send = _build_rest_send(gen_responses, fabric_name=fabric_name)
    return SubinterfaceManagedInterfaceOrchestrator(rest_send=rest_send)


def _build_model(switch_ip: str = "192.168.1.1", interface_name: str = "Ethernet1/3.2", **policy_kwargs) -> SubinterfaceManagedInterfaceModel:
    """Build a SubinterfaceManagedInterfaceModel with optional policy fields populated."""
    config_data = None
    if policy_kwargs:
        config_data = {"mode": "managed", "network_os": {"network_os_type": "nx-os", "policy": policy_kwargs}}
    return SubinterfaceManagedInterfaceModel.from_config(
        {"switch_ip": switch_ip, "interface_name": interface_name, "interface_type": "subInterface", "config_data": config_data}
    )


# =============================================================================
# Test: ClassVar / model_class
# =============================================================================


def test_subinterface_managed_orchestrator_00010() -> None:
    """
    # Summary

    Verify `model_class` points to `SubinterfaceManagedInterfaceModel`.

    ## Test

    - model_class is SubinterfaceManagedInterfaceModel

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.model_class
    """
    assert SubinterfaceManagedInterfaceOrchestrator.model_class is SubinterfaceManagedInterfaceModel


def test_subinterface_managed_orchestrator_00020() -> None:
    """
    # Summary

    Verify bulk-support flags are enabled.

    ## Test

    - supports_bulk_create is True
    - supports_bulk_delete is True

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator
    """
    assert SubinterfaceManagedInterfaceOrchestrator.supports_bulk_create is True
    assert SubinterfaceManagedInterfaceOrchestrator.supports_bulk_delete is True


# =============================================================================
# Test: _raise_on_multi_status_failures — 207 Multi-Status handling
# =============================================================================


@pytest.mark.parametrize(
    "response",
    [
        None,
        "not a dict",
        {},
        {"results": []},
        {"results": [{"name": "Ethernet1/3.2", "status": "success"}]},
    ],
    ids=["none", "non_dict", "empty_dict", "empty_results", "all_success"],
)
def test_subinterface_managed_orchestrator_00100(response) -> None:
    """
    # Summary

    Verify `_raise_on_multi_status_failures` does NOT raise for non-dict bodies, missing/empty results, or
    all-success results.

    ## Test

    - None / non-dict / empty results / all-success bodies do not raise

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator._raise_on_multi_status_failures()
    """
    with does_not_raise():
        SubinterfaceManagedInterfaceOrchestrator._raise_on_multi_status_failures(response)


@pytest.mark.parametrize(
    "status",
    ["failed", "error"],
    ids=["failed", "error"],
)
def test_subinterface_managed_orchestrator_00110(status) -> None:
    """
    # Summary

    Verify `_raise_on_multi_status_failures` raises `RuntimeError` when any result item carries
    `status: "failed"` or `status: "error"`, surfacing the per-item name and message.

    ND returns HTTP 207 Multi-Status on subinterface POST with per-item failures (e.g. parent not in routed mode)
    that the RestSend layer treats as success; this guard converts those into a hard failure.

    ## Test

    - A results body with one failed item raises RuntimeError mentioning the count and message

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator._raise_on_multi_status_failures()
    """
    response = {
        "results": [
            {"name": "Ethernet1/3.2", "status": "success"},
            {"name": "Ethernet1/3.3", "status": status, "message": "parent not in routed mode"},
        ]
    }
    with pytest.raises(RuntimeError, match=r"ND rejected 1 interface\(s\).*parent not in routed mode"):
        SubinterfaceManagedInterfaceOrchestrator._raise_on_multi_status_failures(response)


# =============================================================================
# Test: query_all — happy path with filtering
# =============================================================================


def test_subinterface_managed_orchestrator_00400() -> None:
    """
    # Summary

    Verify `query_all` validates the fabric, iterates all switches, filters to interfaceType=subInterface AND
    managed policyType=subinterface, and injects `switchIp` onto each kept interface.

    ## Test

    - Fabric summary returns 200
    - Two switches in the switch list
    - Switch 1 returns: managed subinterface (kept), ethernet (filtered by interfaceType),
      unmanaged subinterface with policyType=monitorSubinterface (filtered by policyType)
    - Switch 2 returns: managed subinterface (kept)
    - Result contains exactly two subinterfaces with switchIp injected

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.query_all()
    """

    def responses():
        yield responses_subif("test_query_all_happy_path_00400a")
        yield responses_subif("test_query_all_happy_path_00400b")
        yield responses_subif("test_query_all_happy_path_00400c")
        yield responses_subif("test_query_all_happy_path_00400d")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 2

    by_name = {iface["interfaceName"]: iface for iface in result}
    assert set(by_name) == {"Ethernet1/3.2", "Port-channel10.5"}

    assert by_name["Ethernet1/3.2"]["switchIp"] == "192.168.1.1"
    assert by_name["Port-channel10.5"]["switchIp"] == "192.168.1.2"

    # Filtered out: ethernet (interfaceType) and monitorSubinterface (policyType)
    assert "Ethernet1/1" not in by_name
    assert "Ethernet1/3.9" not in by_name


def test_subinterface_managed_orchestrator_00420() -> None:
    """
    # Summary

    Verify `query_all` raises `RuntimeError` when the fabric does not exist.

    ## Test

    - Fabric summary returns 404
    - query_all raises RuntimeError mentioning the fabric name

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.query_all()
    - FabricContext.validate_for_mutation()
    """

    def responses():
        yield responses_subif("test_query_all_fabric_not_found_00420a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses, fabric_name="missing_fabric")

    with pytest.raises(RuntimeError, match=r"Query all failed.*missing_fabric"):
        orchestrator.query_all()


# =============================================================================
# Test: query_one — happy path
# =============================================================================


def test_subinterface_managed_orchestrator_00500() -> None:
    """
    # Summary

    Verify `query_one` resolves the switch_ip and issues a GET on the interface.

    ## Test

    - Switch list returns one switch
    - Interface GET returns the subinterface body
    - query_one returns the response DATA

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.query_one()
    """

    def responses():
        yield responses_subif("test_query_one_happy_path_00500a")
        yield responses_subif("test_query_one_happy_path_00500b")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        model = _build_model(interface_name="Ethernet1/3.2")
        result = orchestrator.query_one(model)

    assert result["interfaceName"] == "Ethernet1/3.2"
    assert result["interfaceType"] == "subInterface"
    assert result["configData"]["networkOS"]["policy"]["policyType"] == "subinterface"


# =============================================================================
# Test: create — happy path; payload inspection
# =============================================================================


def test_subinterface_managed_orchestrator_00600() -> None:
    """
    # Summary

    Verify `create` resolves switch_ip, issues a POST wrapping the payload in `interfaces[]`, injects `switchId`, and
    queues a deploy.

    ## Test

    - Switch list returns one switch
    - POST returns success
    - After create, the interface is queued in `_pending_deploys`

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.create()
    """

    def responses():
        yield responses_subif("test_create_happy_path_00600a")
        yield responses_subif("test_create_happy_path_00600b")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        model = _build_model(interface_name="Ethernet1/3.2", admin_state=True, vlan_id=2, ip="10.20.30.40", prefix=24)
        orchestrator.create(model)

    assert ("Ethernet1/3.2", "FDO11111AAA") in orchestrator._pending_deploys


def test_subinterface_managed_orchestrator_00610() -> None:
    """
    # Summary

    Verify `create` raises `RuntimeError` when the POST returns a 207 Multi-Status body with a per-item failure,
    rather than silently reporting success and queuing a deploy.

    ## Test

    - Switch list returns one switch
    - POST returns a results body containing one item with status "failed"
    - create raises RuntimeError mentioning the create failure
    - No deploy is queued

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.create()
    - SubinterfaceManagedInterfaceOrchestrator._raise_on_multi_status_failures()
    """

    def responses():
        yield responses_subif("test_create_multi_status_failure_00610a")
        yield responses_subif("test_create_multi_status_failure_00610b")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    model = _build_model(interface_name="Ethernet1/3.2", admin_state=True, vlan_id=2, ip="10.20.30.40", prefix=24)

    with pytest.raises(RuntimeError, match=r"Create failed.*parent not in routed mode"):
        orchestrator.create(model)

    assert ("Ethernet1/3.2", "FDO11111AAA") not in orchestrator._pending_deploys


# =============================================================================
# Test: update — happy path
# =============================================================================


def test_subinterface_managed_orchestrator_00700() -> None:
    """
    # Summary

    Verify `update` resolves switch_ip, issues a PUT on the interface, and queues a deploy.

    ## Test

    - Switch list returns one switch
    - PUT returns 200
    - After update, the interface is queued in `_pending_deploys`

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.update()
    """

    def responses():
        yield responses_subif("test_update_happy_path_00700a")
        yield responses_subif("test_update_happy_path_00700b")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        model = _build_model(interface_name="Ethernet1/3.2", description="updated description")
        orchestrator.update(model)

    assert ("Ethernet1/3.2", "FDO11111AAA") in orchestrator._pending_deploys


# =============================================================================
# Test: delete — queues remove + deploy, no immediate API call
# =============================================================================


def test_subinterface_managed_orchestrator_00800() -> None:
    """
    # Summary

    Verify `delete` queues both a remove and a deploy without making any API call beyond the switch_id resolution.
    The actual remove/deploy happens later via `remove_pending` / `deploy_pending`.

    ## Test

    - Switch list returns one switch
    - delete() makes only the switch_map GET (one fixture consumed)
    - After delete, the interface is queued in both `_pending_removes` and `_pending_deploys`

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.delete()
    """

    def responses():
        yield responses_subif("test_delete_happy_path_00800a")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        model = _build_model(interface_name="Ethernet1/3.2")
        orchestrator.delete(model)

    assert ("Ethernet1/3.2", "FDO11111AAA") in orchestrator._pending_removes
    assert ("Ethernet1/3.2", "FDO11111AAA") in orchestrator._pending_deploys


def test_subinterface_managed_orchestrator_00810() -> None:
    """
    # Summary

    Verify `remove_pending` issues `interfaceActions/remove` with all queued interfaces and clears the queue.

    ## Test

    - Queue one interface manually (no preceding switch_map GET needed)
    - Call remove_pending
    - Queue is empty after success

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.remove_pending()
    """

    def responses():
        yield responses_subif("test_remove_pending_happy_path_00810a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    orchestrator._queue_remove("Ethernet1/3.2", "FDO11111AAA")

    with does_not_raise():
        orchestrator.remove_pending()

    assert orchestrator._pending_removes == []


def test_subinterface_managed_orchestrator_00820() -> None:
    """
    # Summary

    Verify `deploy_pending` issues `interfaceActions/deploy` with all queued interfaces and clears the queue.

    ## Test

    - Queue one interface manually
    - Call deploy_pending
    - Queue is empty after success

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.deploy_pending()
    """

    def responses():
        yield responses_subif("test_deploy_pending_happy_path_00820a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    orchestrator._queue_deploy("Ethernet1/3.2", "FDO11111AAA")

    with does_not_raise():
        orchestrator.deploy_pending()

    assert orchestrator._pending_deploys == []


# =============================================================================
# Test: create_bulk — multiple subinterfaces grouped per switch
# =============================================================================


def test_subinterface_managed_orchestrator_00900() -> None:
    """
    # Summary

    Verify `create_bulk` groups interfaces by switch and sends one POST per switch with all subinterfaces in the
    `interfaces` array. Both interfaces are queued for deploy.

    ## Test

    - Two subinterfaces on the same switch
    - One POST issued (one switch group)
    - Both interfaces queued in `_pending_deploys`

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.create_bulk()
    """

    def responses():
        yield responses_subif("test_create_bulk_happy_path_00900a")
        yield responses_subif("test_create_bulk_happy_path_00900b")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        models = [
            _build_model(interface_name="Ethernet1/3.2", admin_state=True, vlan_id=2, ip="10.20.30.40", prefix=24),
            _build_model(interface_name="Ethernet1/3.3", admin_state=True, vlan_id=3, ip="10.20.31.40", prefix=24),
        ]
        orchestrator.create_bulk(models)

    assert ("Ethernet1/3.2", "FDO11111AAA") in orchestrator._pending_deploys
    assert ("Ethernet1/3.3", "FDO11111AAA") in orchestrator._pending_deploys


# =============================================================================
# Test: payload shape — verify the nested PUT body shape
# =============================================================================


def test_subinterface_managed_orchestrator_01000() -> None:
    """
    # Summary

    Verify the in-memory payload built by `to_payload` for a subinterface is shaped correctly for the PUT API:
    nested `configData.networkOS.policy` block, no `switch_ip` or `oper_data` at top level. (Wire dispatch is
    exercised elsewhere; this asserts the payload shape on a model the orchestrator would send unmodified.)

    ## Test

    - Build a partial-update model (description-only)
    - to_payload produces the canonical nested shape
    - switchId injection done by orchestrator is not in to_payload

    ## Classes and Methods

    - SubinterfaceManagedInterfaceModel.to_payload()
    - SubinterfaceManagedInterfaceOrchestrator.update() — payload assembly
    """
    model = _build_model(interface_name="Ethernet1/3.2", description="just description")
    payload = model.to_payload()

    assert payload["interfaceName"] == "Ethernet1/3.2"
    assert payload["interfaceType"] == "subInterface"
    assert "switchIp" not in payload
    assert "operData" not in payload
    assert "switchId" not in payload  # injected by orchestrator, not by model

    policy = payload["configData"]["networkOS"]["policy"]
    assert policy["policyType"] == "subinterface"
    assert policy["description"] == "just description"
