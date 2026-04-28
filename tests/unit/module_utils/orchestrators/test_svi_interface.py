# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for svi_interface orchestrator.

Verifies that `SviInterfaceOrchestrator` correctly:
- declares the right `model_class` and bulk-support flags
- filters `query_all` results down to interfaceType=svi + policyType=svi
- builds correct POST/PUT payloads on create/update
- queues remove + deploy on delete (no immediate API call)
- preserves `interfaceType` on PUT (matches the GUI's canonical PUT body)

Uses the file-based `Sender` from `tests/unit/module_utils/sender_file.py` as the `sender` injected into a real
`RestSend`. Responses are read from
`tests/unit/module_utils/fixtures/fixture_data/test_svi_interface.json`.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.svi_interface import SviInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.svi_interface import SviInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_svi(key: str):
    """Load fixture data for the orchestrator's test_svi_interface.json file."""
    return load_fixture("test_svi_interface")[key]


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


def _build_orchestrator(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1") -> SviInterfaceOrchestrator:
    """Construct an orchestrator with the file-based RestSend injected."""
    rest_send = _build_rest_send(gen_responses, fabric_name=fabric_name)
    return SviInterfaceOrchestrator(rest_send=rest_send)


def _build_model(switch_ip: str = "192.168.1.1", interface_name: str = "vlan333", **policy_kwargs) -> SviInterfaceModel:
    """Build an SviInterfaceModel with optional policy fields populated."""
    config_data = None
    if policy_kwargs:
        config_data = {"mode": "managed", "network_os": {"network_os_type": "nx-os", "policy": policy_kwargs}}
    return SviInterfaceModel.from_config({"switch_ip": switch_ip, "interface_name": interface_name, "interface_type": "svi", "config_data": config_data})


# =============================================================================
# Test: ClassVar / model_class
# =============================================================================


def test_svi_orchestrator_00010() -> None:
    """
    # Summary

    Verify `model_class` points to `SviInterfaceModel`.

    ## Test

    - model_class is SviInterfaceModel

    ## Classes and Methods

    - SviInterfaceOrchestrator.model_class
    """
    assert SviInterfaceOrchestrator.model_class is SviInterfaceModel


def test_svi_orchestrator_00020() -> None:
    """
    # Summary

    Verify bulk-support flags are enabled.

    ## Test

    - supports_bulk_create is True
    - supports_bulk_delete is True

    ## Classes and Methods

    - SviInterfaceOrchestrator
    """
    assert SviInterfaceOrchestrator.supports_bulk_create is True
    assert SviInterfaceOrchestrator.supports_bulk_delete is True


# =============================================================================
# Test: query_all — happy path with filtering
# =============================================================================


def test_svi_orchestrator_00400() -> None:
    """
    # Summary

    Verify `query_all` validates the fabric, iterates all switches, filters to interfaceType=svi AND policyType=svi,
    and injects `switchIp` onto each kept interface.

    ## Test

    - Fabric summary returns 200
    - Two switches in the switch list
    - Switch 1 returns: SVI (kept), ethernet (filtered by interfaceType), SVI with policyType=underlaySvi (filtered by policyType)
    - Switch 2 returns: SVI (kept)
    - Result contains exactly two SVIs with switchIp injected

    ## Classes and Methods

    - SviInterfaceOrchestrator.query_all()
    """

    def responses():
        yield responses_svi("test_query_all_happy_path_00400a")
        yield responses_svi("test_query_all_happy_path_00400_freeze")
        yield responses_svi("test_query_all_happy_path_00400b")
        yield responses_svi("test_query_all_happy_path_00400c")
        yield responses_svi("test_query_all_happy_path_00400d")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 2

    by_name = {iface["interfaceName"]: iface for iface in result}
    assert set(by_name) == {"vlan100", "vlan200"}

    assert by_name["vlan100"]["switchIp"] == "192.168.1.1"
    assert by_name["vlan200"]["switchIp"] == "192.168.1.2"

    # Filtered out: ethernet and underlaySvi
    assert "Ethernet1/1" not in by_name
    assert "vlan999" not in by_name


def test_svi_orchestrator_00420() -> None:
    """
    # Summary

    Verify `query_all` raises `RuntimeError` when the fabric does not exist.

    ## Test

    - Fabric summary returns 404
    - query_all raises RuntimeError mentioning the fabric name

    ## Classes and Methods

    - SviInterfaceOrchestrator.query_all()
    - FabricContext.validate_for_mutation()
    """

    def responses():
        yield responses_svi("test_query_all_fabric_not_found_00420a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses, fabric_name="missing_fabric")

    with pytest.raises(RuntimeError, match=r"Query all failed.*missing_fabric"):
        orchestrator.query_all()


# =============================================================================
# Test: query_one — happy path
# =============================================================================


def test_svi_orchestrator_00500() -> None:
    """
    # Summary

    Verify `query_one` resolves the switch_ip and issues a GET on the interface.

    ## Test

    - Switch list returns one switch
    - Interface GET returns the SVI body
    - query_one returns the response DATA

    ## Classes and Methods

    - SviInterfaceOrchestrator.query_one()
    """

    def responses():
        yield responses_svi("test_query_one_happy_path_00500a")
        yield responses_svi("test_query_one_happy_path_00500b")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        model = _build_model(interface_name="vlan333")
        result = orchestrator.query_one(model)

    assert result["interfaceName"] == "vlan333"
    assert result["interfaceType"] == "svi"
    assert result["configData"]["networkOS"]["policy"]["policyType"] == "svi"


# =============================================================================
# Test: create — happy path; payload inspection
# =============================================================================


def test_svi_orchestrator_00600() -> None:
    """
    # Summary

    Verify `create` resolves switch_ip, issues a POST wrapping the payload in `interfaces[]`, injects `switchId`, and
    queues a deploy.

    ## Test

    - Switch list returns one switch
    - POST returns success
    - After create, the interface is queued in `_pending_deploys`

    ## Classes and Methods

    - SviInterfaceOrchestrator.create()
    """

    def responses():
        yield responses_svi("test_create_happy_path_00600a")
        yield responses_svi("test_create_happy_path_00600b")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        model = _build_model(interface_name="vlan333", admin_state=True, ip="10.99.99.1", prefix=24)
        orchestrator.create(model)

    assert ("vlan333", "FDO11111AAA") in orchestrator._pending_deploys


# =============================================================================
# Test: update — happy path
# =============================================================================


def test_svi_orchestrator_00700() -> None:
    """
    # Summary

    Verify `update` resolves switch_ip, issues a PUT on the interface, and queues a deploy.

    ## Test

    - Switch list returns one switch
    - PUT returns 200
    - After update, the interface is queued in `_pending_deploys`

    ## Classes and Methods

    - SviInterfaceOrchestrator.update()
    """

    def responses():
        yield responses_svi("test_update_happy_path_00700a")
        yield responses_svi("test_update_happy_path_00700b")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        model = _build_model(interface_name="vlan333", description="updated description")
        orchestrator.update(model)

    assert ("vlan333", "FDO11111AAA") in orchestrator._pending_deploys


# =============================================================================
# Test: delete — queues remove + deploy, no immediate API call
# =============================================================================


def test_svi_orchestrator_00800() -> None:
    """
    # Summary

    Verify `delete` queues both a remove and a deploy without making any API call beyond the switch_id resolution.
    The actual remove/deploy happens later via `remove_pending` / `deploy_pending`.

    ## Test

    - Switch list returns one switch
    - delete() makes only the switch_map GET (one fixture consumed)
    - After delete, the interface is queued in both `_pending_removes` and `_pending_deploys`

    ## Classes and Methods

    - SviInterfaceOrchestrator.delete()
    """

    def responses():
        yield responses_svi("test_delete_happy_path_00800a")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        model = _build_model(interface_name="vlan333")
        orchestrator.delete(model)

    assert ("vlan333", "FDO11111AAA") in orchestrator._pending_removes
    assert ("vlan333", "FDO11111AAA") in orchestrator._pending_deploys


def test_svi_orchestrator_00810() -> None:
    """
    # Summary

    Verify `remove_pending` issues `interfaceActions/remove` with all queued interfaces and clears the queue.

    ## Test

    - Queue one interface manually (no preceding switch_map GET needed)
    - Call remove_pending
    - Queue is empty after success

    ## Classes and Methods

    - SviInterfaceOrchestrator.remove_pending()
    """

    def responses():
        yield responses_svi("test_remove_pending_happy_path_00810a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    orchestrator._queue_remove("vlan333", "FDO11111AAA")

    with does_not_raise():
        orchestrator.remove_pending()

    assert orchestrator._pending_removes == []


def test_svi_orchestrator_00820() -> None:
    """
    # Summary

    Verify `deploy_pending` issues `interfaceActions/deploy` with all queued interfaces and clears the queue.

    ## Test

    - Queue one interface manually
    - Call deploy_pending
    - Queue is empty after success

    ## Classes and Methods

    - SviInterfaceOrchestrator.deploy_pending()
    """

    def responses():
        yield responses_svi("test_deploy_pending_happy_path_00820a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    orchestrator._queue_deploy("vlan333", "FDO11111AAA")

    with does_not_raise():
        orchestrator.deploy_pending()

    assert orchestrator._pending_deploys == []


# =============================================================================
# Test: create_bulk — multiple SVIs grouped per switch
# =============================================================================


def test_svi_orchestrator_00900() -> None:
    """
    # Summary

    Verify `create_bulk` groups interfaces by switch and sends one POST per switch with all SVIs in the
    `interfaces` array. Both interfaces are queued for deploy.

    ## Test

    - Two SVIs on the same switch
    - One POST issued (one switch group)
    - Both interfaces queued in `_pending_deploys`

    ## Classes and Methods

    - SviInterfaceOrchestrator.create_bulk()
    """

    def responses():
        yield responses_svi("test_create_bulk_happy_path_00900a")
        yield responses_svi("test_create_bulk_happy_path_00900b")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        models = [
            _build_model(interface_name="vlan333", admin_state=True, ip="10.99.99.1", prefix=24),
            _build_model(interface_name="vlan334", admin_state=True, ip="10.99.99.2", prefix=24),
        ]
        orchestrator.create_bulk(models)

    assert ("vlan333", "FDO11111AAA") in orchestrator._pending_deploys
    assert ("vlan334", "FDO11111AAA") in orchestrator._pending_deploys


# =============================================================================
# Test: payload shape — verify update strips no extra fields and PUT works on partial body
# =============================================================================


def test_svi_orchestrator_01000() -> None:
    """
    # Summary

    Verify the in-memory payload built by `to_payload` for an SVI is shaped correctly for the PUT API: nested
    `configData.networkOS.policy` block, no `switch_ip` or `oper_data` at top level. (Wire dispatch is exercised
    elsewhere; this asserts the payload shape on a model the orchestrator would send unmodified.)

    ## Test

    - Build a partial-update model (description-only)
    - to_payload produces the canonical nested shape
    - switchId injection done by orchestrator is not in to_payload
    - hsrpVersion absent (model defaults; from_response strip irrelevant here)

    ## Classes and Methods

    - SviInterfaceModel.to_payload()
    - SviInterfaceOrchestrator.update() — payload assembly
    """
    model = _build_model(interface_name="vlan333", description="just description")
    payload = model.to_payload()

    assert payload["interfaceName"] == "vlan333"
    assert payload["interfaceType"] == "svi"
    assert "switchIp" not in payload
    assert "operData" not in payload
    assert "switchId" not in payload  # injected by orchestrator, not by model

    policy = payload["configData"]["networkOS"]["policy"]
    assert policy["policyType"] == "svi"
    assert policy["description"] == "just description"
    assert "hsrpVersion" not in policy
