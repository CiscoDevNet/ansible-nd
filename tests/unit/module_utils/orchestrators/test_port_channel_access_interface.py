# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for port_channel_access_interface orchestrator.

Verifies that `PortChannelAccessInterfaceOrchestrator` correctly:
- declares the right `model_class` and `_managed_policy_types`
- inherits bulk-support flags from `PortChannelBaseOrchestrator`
- filters fabric-wide interface results to `interfaceType: "portChannel"` plus the managed
  policy types (so non-port-channel and other-flavor port-channels are excluded)
- propagates `RuntimeError` from the inherited `validate_prerequisites` path

Uses the file-based `Sender` from `tests/unit/module_utils/sender_file.py` as the
`sender` dependency injected into a real `RestSend`. Responses are read from
`tests/unit/module_utils/fixtures/fixture_data/test_port_channel_access_interface.json`.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines
# pylint: disable=assignment-from-no-return
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_access_interface import (
    PortChannelAccessConfigDataModel,
    PortChannelAccessInterfaceModel,
    PortChannelAccessNetworkOSModel,
    PortChannelAccessPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_access_interface import (
    PortChannelAccessInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_pc_access(key: str):
    """Load fixture data for the orchestrator's test_port_channel_access_interface.json file."""
    return load_fixture("test_port_channel_access_interface")[key]


def _build_rest_send(
    gen_responses: ResponseGenerator,
    fabric_name: str = "fabric_1",
    state: str | None = None,
    config: list[dict] | None = None,
) -> RestSend:
    """Build a RestSend wired to the file-based Sender and the real ResponseHandler.

    `state` and `config` populate `rest_send.params` so `query_all`'s `_switches_to_query` scoping
    (fabric-wide for `overridden`, config-scoped otherwise) can be exercised.
    """
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    params: dict = {"check_mode": False, "fabric_name": fabric_name}
    if state is not None:
        params["state"] = state
    if config is not None:
        params["config"] = config

    rest_send = RestSend(params)
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _build_orchestrator(
    gen_responses: ResponseGenerator,
    fabric_name: str = "fabric_1",
    state: str | None = None,
    config: list[dict] | None = None,
) -> PortChannelAccessInterfaceOrchestrator:
    """Construct an orchestrator with the file-based RestSend injected."""
    rest_send = _build_rest_send(gen_responses, fabric_name=fabric_name, state=state, config=config)
    return PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)


def _build_pc_model(
    switch_ip: str = "192.168.1.1",
    interface_name: str = "port-channel501",
    include_config: bool = True,
) -> PortChannelAccessInterfaceModel:
    """Build a minimal `PortChannelAccessInterfaceModel` instance for CRUD tests."""
    kwargs: dict = {"switch_ip": switch_ip, "interface_name": interface_name}
    if include_config:
        kwargs["config_data"] = PortChannelAccessConfigDataModel(
            network_os=PortChannelAccessNetworkOSModel(
                policy=PortChannelAccessPolicyModel(admin_state=True, access_vlan=100, port_channel_mode="active", ports=["Ethernet1/1"]),
            ),
        )
    return PortChannelAccessInterfaceModel(**kwargs)


# =============================================================================
# Test: ClassVar / model_class
# =============================================================================


def test_port_channel_access_orchestrator_00010() -> None:
    """
    # Summary

    Verify `model_class` points to `PortChannelAccessInterfaceModel`.

    ## Test

    - model_class is PortChannelAccessInterfaceModel

    ## Classes and Methods

    - PortChannelAccessInterfaceOrchestrator.model_class
    """
    assert PortChannelAccessInterfaceOrchestrator.model_class is PortChannelAccessInterfaceModel


def test_port_channel_access_orchestrator_00020() -> None:
    """
    # Summary

    Verify bulk-support flags inherited from `PortChannelBaseOrchestrator`.

    ## Test

    - supports_bulk_create is True
    - supports_bulk_delete is True

    ## Classes and Methods

    - PortChannelAccessInterfaceOrchestrator
    """
    assert PortChannelAccessInterfaceOrchestrator.supports_bulk_create is True
    assert PortChannelAccessInterfaceOrchestrator.supports_bulk_delete is True


# =============================================================================
# Test: _managed_policy_types
# =============================================================================


def test_port_channel_access_orchestrator_00100() -> None:
    """
    # Summary

    Verify `_managed_policy_types` returns the single `"accessPoHost"` API value.

    ## Test

    - Returned set contains exactly "accessPoHost"

    ## Classes and Methods

    - PortChannelAccessInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    assert orchestrator._managed_policy_types() == {"accessPoHost"}


def test_port_channel_access_orchestrator_00110() -> None:
    """
    # Summary

    Verify `_managed_policy_types` returns a set (supports set membership for `in` checks).

    ## Test

    - Return type is set

    ## Classes and Methods

    - PortChannelAccessInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    result = orchestrator._managed_policy_types()
    assert isinstance(result, set)
    assert "accessPoHost" in result


# =============================================================================
# Test: query_all — happy path with filtering
# =============================================================================


def test_port_channel_access_orchestrator_00400() -> None:
    """
    # Summary

    Verify `query_all` validates the fabric, iterates all switches, filters to interfaceType=="portChannel"
    and policyType=="accessPoHost", and injects `switchIp` onto each kept interface.

    ## Test

    - Fabric summary (validate_prerequisites) returns 200
    - Switches list returns two switches
    - Switch 1 returns: configured accessPoHost portChannel, trunkPoHost portChannel, ethernet trunkHost
    - Switch 2 returns: one configured accessPoHost portChannel
    - Result contains exactly the two accessPoHost port-channels
    - Each has switchIp injected with the fabricManagementIp

    ## Classes and Methods

    - PortChannelAccessInterfaceOrchestrator._managed_policy_types()
    - PortChannelBaseOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access("test_query_all_happy_path_00400a")
        yield responses_pc_access("test_query_all_happy_path_00400b")
        yield responses_pc_access("test_query_all_happy_path_00400c")
        yield responses_pc_access("test_query_all_happy_path_00400d")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        # state=overridden keeps query_all fabric-wide so this test exercises cross-switch filtering.
        orchestrator = _build_orchestrator(gen_responses, state="overridden")
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 2

    by_name = {iface["interfaceName"]: iface for iface in result}
    assert set(by_name) == {"port-channel501", "port-channel601"}

    # switchIp is injected by the base query_all
    assert by_name["port-channel501"]["switchIp"] == "192.168.1.1"
    assert by_name["port-channel601"]["switchIp"] == "192.168.1.2"

    # Filtered out: trunkPoHost (port-channel502) and ethernet trunkHost (Ethernet1/1)
    assert "port-channel502" not in by_name
    assert "Ethernet1/1" not in by_name

    # method_name is used for clearer pytest failure messages; keep as a sanity reference
    assert method_name.endswith("00400")


def test_port_channel_access_orchestrator_00410() -> None:
    """
    # Summary

    Verify `query_all` returns an empty list when no switch reports any accessPoHost port-channel.

    ## Test

    - Switch returns only non-port-channel and non-accessPoHost port-channel interfaces
    - Result is an empty list

    ## Classes and Methods

    - PortChannelAccessInterfaceOrchestrator._managed_policy_types()
    - PortChannelBaseOrchestrator.query_all()
    """

    def responses():
        yield responses_pc_access("test_query_all_no_match_00410a")
        yield responses_pc_access("test_query_all_no_match_00410b")
        yield responses_pc_access("test_query_all_no_match_00410c")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        # state=overridden keeps query_all fabric-wide so every switch is scanned.
        orchestrator = _build_orchestrator(gen_responses, state="overridden")
        result = orchestrator.query_all()

    assert result == []


def test_port_channel_access_orchestrator_00420() -> None:
    """
    # Summary

    Verify `query_all` raises `RuntimeError` when the fabric does not exist.

    ## Test

    - Fabric summary returns 404
    - query_all raises RuntimeError with "Query all failed" (wrapping the inner "Fabric ... not found")

    ## Classes and Methods

    - PortChannelBaseOrchestrator.query_all()
    - FabricContext.validate_for_mutation()
    """

    def responses():
        yield responses_pc_access("test_query_all_fabric_not_found_00420a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses, fabric_name="missing_fabric")

    with pytest.raises(RuntimeError, match=r"Query all failed.*missing_fabric"):
        orchestrator.query_all()


def test_port_channel_access_orchestrator_00430() -> None:
    """
    # Summary

    Verify `query_all` returns an empty list when a switch's interfaces endpoint returns no body
    (the `not_found_ok=True` branch in `PortChannelBaseOrchestrator.query_all`).

    ## Test

    - Switch's interface list returns 404 (treated as no interfaces present)
    - query_all skips the switch and yields []

    ## Classes and Methods

    - PortChannelBaseOrchestrator.query_all()
    """

    def responses():
        yield responses_pc_access("test_query_all_switch_404_00430a")
        yield responses_pc_access("test_query_all_switch_404_00430b")
        yield responses_pc_access("test_query_all_switch_404_00430c")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        # state=overridden keeps query_all fabric-wide so the 404 switch is still visited and skipped.
        orchestrator = _build_orchestrator(gen_responses, state="overridden")
        result = orchestrator.query_all()

    assert result == []


def test_port_channel_access_orchestrator_00440() -> None:
    """
    # Summary

    Verify `query_all` scopes its per-switch interface-list fan-out to switches named in the user config when
    `state` is not `overridden`, rather than querying every switch in the fabric.

    ## Test

    - Fabric has two switches (192.168.1.1, 192.168.1.2), but config names only 192.168.1.1
    - state is `merged` (non-overridden), so `_switches_to_query` returns only the config switch
    - Only the config switch's interfaces are fetched; the second switch is never queried (the response
      generator yields exactly three responses — summary, switch list, switch-1 interfaces — and would raise
      if a second per-switch GET were issued)
    - Result contains only the accessPoHost port-channel on the config switch

    ## Classes and Methods

    - PortChannelBaseOrchestrator._switches_to_query()
    - PortChannelBaseOrchestrator.query_all()
    """

    def responses():
        yield responses_pc_access("test_query_all_config_scoped_00440a")
        yield responses_pc_access("test_query_all_config_scoped_00440b")
        yield responses_pc_access("test_query_all_config_scoped_00440c")

    gen_responses = ResponseGenerator(responses())

    config = [{"switch_ip": "192.168.1.1", "interface_name": "port-channel501"}]

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses, state="merged", config=config)
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["interfaceName"] == "port-channel501"
    assert result[0]["switchIp"] == "192.168.1.1"


# =============================================================================
# Test: create
# =============================================================================


def test_port_channel_access_orchestrator_00200() -> None:
    """
    # Summary

    Verify `create` resolves the switch IP, wraps the payload in `{"interfaces": [...]}`, injects `switchId`,
    emits the hardcoded `policyType`, and queues a deploy.

    ## Test

    - First `_resolve_switch_id` triggers a switches-list fetch
    - POST is issued against `/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces`
    - Request body is `{"interfaces": [{...payload..., "switchId": "FDO11111AAA"}]}`
    - Payload carries `policyType: accessPoHost` and omits `switchIp`
    - `_pending_deploys` contains a single `(interface_name, switch_id)` pair

    ## Classes and Methods

    - PortChannelBaseOrchestrator.create()
    - NDBaseInterfaceOrchestrator._resolve_switch_id()
    - NDBaseInterfaceOrchestrator._queue_deploy()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_pc_model()

    with does_not_raise():
        instance.create(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces"
    assert rest_send.verb == HttpVerbEnum.POST.value
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert "interfaces" in body
    assert len(body["interfaces"]) == 1
    payload_item = body["interfaces"][0]
    assert payload_item["interfaceName"] == "port-channel501"
    assert payload_item["interfaceType"] == "portChannel"
    assert payload_item["switchId"] == "FDO11111AAA"
    assert "switchIp" not in payload_item
    assert payload_item["configData"]["networkOS"]["policy"]["policyType"] == "accessPoHost"
    assert instance._pending_deploys == [("port-channel501", "FDO11111AAA")]


def test_port_channel_access_orchestrator_00210() -> None:
    """
    # Summary

    Verify `create` wraps a `_request` failure in `RuntimeError` mentioning the identifier.

    ## Test

    - switches-list returns 200
    - POST returns 500
    - `RuntimeError` matches `Create failed for .*port-channel501`
    - No deploy is queued

    ## Classes and Methods

    - PortChannelBaseOrchestrator.create()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_pc_model()

    match = r"Create failed for .*port-channel501"
    with pytest.raises(RuntimeError, match=match):
        instance.create(model)

    assert instance._pending_deploys == []


def test_port_channel_access_orchestrator_00220() -> None:
    """
    # Summary

    Verify `create` wraps an unknown-switch-IP `RuntimeError` from `_resolve_switch_id`.

    ## Test

    - switches-list returns a different IP than the model's `switch_ip`
    - `create` re-raises as `RuntimeError` matching `Create failed for .*port-channel501.*No switch found with fabricManagementIp '192\\.168\\.99\\.99'`
    - No deploy is queued

    ## Classes and Methods

    - PortChannelBaseOrchestrator.create()
    - NDBaseInterfaceOrchestrator._resolve_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_pc_model(switch_ip="192.168.99.99")

    match = r"Create failed for .*port-channel501.*No switch found with fabricManagementIp '192\.168\.99\.99'"
    with pytest.raises(RuntimeError, match=match):
        instance.create(model)

    assert instance._pending_deploys == []


# =============================================================================
# Test: update
# =============================================================================


def test_port_channel_access_orchestrator_00300() -> None:
    """
    # Summary

    Verify `update` issues a PUT against the per-interface URL, injects `switchId` into the payload, and queues a deploy.

    ## Test

    - switches-list fetched on first switch_id resolution
    - PUT is issued against `/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces/port-channel501`
    - `switchId` is present in the payload; `switchIp` is not
    - `_pending_deploys` contains the `(port-channel501, FDO11111AAA)` pair

    ## Classes and Methods

    - PortChannelBaseOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_pc_model()

    with does_not_raise():
        instance.update(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces/port-channel501"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert body["interfaceName"] == "port-channel501"
    assert body["switchId"] == "FDO11111AAA"
    assert "switchIp" not in body
    assert instance._pending_deploys == [("port-channel501", "FDO11111AAA")]


def test_port_channel_access_orchestrator_00310() -> None:
    """
    # Summary

    Verify `update` wraps a `_request` failure in `RuntimeError` mentioning the identifier.

    ## Test

    - PUT returns 500
    - `RuntimeError` matches `Update failed for .*port-channel501`
    - No deploy is queued

    ## Classes and Methods

    - PortChannelBaseOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_pc_model()

    match = r"Update failed for .*port-channel501"
    with pytest.raises(RuntimeError, match=match):
        instance.update(model)

    assert instance._pending_deploys == []


# =============================================================================
# Test: delete
# =============================================================================


def test_port_channel_access_orchestrator_00320() -> None:
    """
    # Summary

    Verify `delete` queues a remove + deploy without making any API call beyond the switches-list fetch.

    ## Test

    - Only the switches-list response is consumed (one HTTP call to resolve switch_id)
    - `_pending_removes` contains `(port-channel501, FDO11111AAA)`
    - `_pending_deploys` contains `(port-channel501, FDO11111AAA)`
    - `delete` returns None

    ## Classes and Methods

    - PortChannelBaseOrchestrator.delete()
    - NDBaseInterfaceOrchestrator._queue_remove()
    - NDBaseInterfaceOrchestrator._queue_deploy()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_pc_model(include_config=False)

    with does_not_raise():
        result = instance.delete(model)

    assert result is None
    assert instance._pending_removes == [("port-channel501", "FDO11111AAA")]
    assert instance._pending_deploys == [("port-channel501", "FDO11111AAA")]


def test_port_channel_access_orchestrator_00330() -> None:
    """
    # Summary

    Verify `delete` propagates the raw `RuntimeError` from `_resolve_switch_id` when the IP is unknown.

    Unlike `create`/`update`, `delete` does not wrap exceptions, so the underlying
    `No switch found with fabricManagementIp ...` message surfaces directly.

    ## Test

    - switches-list returns a different IP
    - `RuntimeError` matches `No switch found with fabricManagementIp '192\\.168\\.99\\.99'`
    - No queues are populated

    ## Classes and Methods

    - PortChannelBaseOrchestrator.delete()
    - NDBaseInterfaceOrchestrator._resolve_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_pc_model(switch_ip="192.168.99.99", include_config=False)

    match = r"No switch found with fabricManagementIp '192\.168\.99\.99'"
    with pytest.raises(RuntimeError, match=match):
        instance.delete(model)

    assert instance._pending_removes == []
    assert instance._pending_deploys == []


# =============================================================================
# Test: create_bulk
# =============================================================================


def test_port_channel_access_orchestrator_00500() -> None:
    """
    # Summary

    Verify `create_bulk` groups interfaces by switch and issues one POST per switch with the per-switch subset
    wrapped in `{"interfaces": [...]}`.

    ## Test

    - Three port-channels across two switches: port-channel501/502 on switch A, port-channel601 on switch B
    - Two POSTs are issued (one per switch)
    - All three pairs are queued in `_pending_deploys`

    ## Classes and Methods

    - PortChannelBaseOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")
        yield responses_pc_access(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    models = [
        _build_pc_model(switch_ip="192.168.1.1", interface_name="port-channel501"),
        _build_pc_model(switch_ip="192.168.1.1", interface_name="port-channel502"),
        _build_pc_model(switch_ip="192.168.1.2", interface_name="port-channel601"),
    ]

    with does_not_raise():
        instance.create_bulk(models)

    assert rest_send.path in (
        "/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces",
        "/api/v1/manage/fabrics/fabric_1/switches/FDO22222BBB/interfaces",
    )
    assert rest_send.verb == HttpVerbEnum.POST.value
    assert sorted(instance._pending_deploys) == sorted(
        [
            ("port-channel501", "FDO11111AAA"),
            ("port-channel502", "FDO11111AAA"),
            ("port-channel601", "FDO22222BBB"),
        ]
    )


def test_port_channel_access_orchestrator_00510() -> None:
    """
    # Summary

    Verify `create_bulk` wraps a per-switch `_request` failure in `RuntimeError` matching `Bulk create failed`.

    ## Test

    - switches-list succeeds
    - First per-switch POST succeeds, second returns 500
    - `RuntimeError` matches `Bulk create failed`

    ## Classes and Methods

    - PortChannelBaseOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")
        yield responses_pc_access(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    models = [
        _build_pc_model(switch_ip="192.168.1.1", interface_name="port-channel501"),
        _build_pc_model(switch_ip="192.168.1.2", interface_name="port-channel601"),
    ]

    match = r"Bulk create failed"
    with pytest.raises(RuntimeError, match=match):
        instance.create_bulk(models)


def test_port_channel_access_orchestrator_00520() -> None:
    """
    # Summary

    Verify `create_bulk` works with a single interface on a single switch (degenerate case).

    ## Test

    - One port-channel on switch A
    - One POST is issued
    - `_pending_deploys` contains a single pair

    ## Classes and Methods

    - PortChannelBaseOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    models = [_build_pc_model(interface_name="port-channel501")]

    with does_not_raise():
        instance.create_bulk(models)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces"
    assert instance._pending_deploys == [("port-channel501", "FDO11111AAA")]


# =============================================================================
# Test: delete_bulk
# =============================================================================


def test_port_channel_access_orchestrator_00600() -> None:
    """
    # Summary

    Verify `delete_bulk` queues remove + deploy entries for each instance without issuing any API call beyond the
    switches-list fetch.

    ## Test

    - Two port-channels on two switches
    - Only switches-list response is consumed
    - `_pending_removes` and `_pending_deploys` each contain both pairs
    - `delete_bulk` returns None

    ## Classes and Methods

    - PortChannelBaseOrchestrator.delete_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    models = [
        _build_pc_model(switch_ip="192.168.1.1", interface_name="port-channel501", include_config=False),
        _build_pc_model(switch_ip="192.168.1.2", interface_name="port-channel601", include_config=False),
    ]

    with does_not_raise():
        result = instance.delete_bulk(models)

    assert result is None
    expected = [("port-channel501", "FDO11111AAA"), ("port-channel601", "FDO22222BBB")]
    assert sorted(instance._pending_removes) == sorted(expected)
    assert sorted(instance._pending_deploys) == sorted(expected)


# =============================================================================
# Test: query_one
# =============================================================================


def test_port_channel_access_orchestrator_00700() -> None:
    """
    # Summary

    Verify `query_one` issues a GET against the per-interface URL and returns the DATA dict.

    ## Test

    - switches-list fetched on first switch_id resolution
    - GET hits `/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces/port-channel501`
    - Returned DATA matches the fixture (accessPoHost port-channel)

    ## Classes and Methods

    - PortChannelBaseOrchestrator.query_one()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_pc_model(include_config=False)

    with does_not_raise():
        result = instance.query_one(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces/port-channel501"
    assert rest_send.verb == HttpVerbEnum.GET.value
    assert result["interfaceName"] == "port-channel501"
    assert result["interfaceType"] == "portChannel"
    assert result["configData"]["networkOS"]["policy"]["policyType"] == "accessPoHost"


def test_port_channel_access_orchestrator_00710() -> None:
    """
    # Summary

    Verify `query_one` wraps a `_request` failure in `RuntimeError` mentioning the identifier.

    ## Test

    - switches-list succeeds, GET returns 500
    - `RuntimeError` matches `Query failed for .*port-channel501`

    ## Classes and Methods

    - PortChannelBaseOrchestrator.query_one()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_pc_model(include_config=False)

    match = r"Query failed for .*port-channel501"
    with pytest.raises(RuntimeError, match=match):
        instance.query_one(model)


# =============================================================================
# Test: deploy queue de-duplication
# =============================================================================


def test_port_channel_access_orchestrator_00800() -> None:
    """
    # Summary

    Verify that calling `create` twice for the same `(interface_name, switch_id)` does not queue a duplicate deploy entry.

    ## Test

    - Two consecutive `create` calls with identical model
    - Both POSTs succeed (response generator consumes both responses)
    - `_pending_deploys` contains exactly one entry

    ## Classes and Methods

    - PortChannelBaseOrchestrator.create()
    - NDBaseInterfaceOrchestrator._queue_deploy()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")
        yield responses_pc_access(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_pc_model()

    with does_not_raise():
        instance.create(model)
        instance.create(model)

    assert instance._pending_deploys == [("port-channel501", "FDO11111AAA")]
