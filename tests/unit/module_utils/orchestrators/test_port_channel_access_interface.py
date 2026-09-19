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
    check_mode: bool = False,
) -> RestSend:
    """Build a RestSend wired to the file-based Sender and the real ResponseHandler.

    `state` and `config` populate `rest_send.params` so `query_all`'s `_switches_to_query` scoping
    (fabric-wide for `overridden`, config-scoped otherwise) can be exercised. `check_mode` drives
    `rest_send.check_mode` so the member-availability preflight's check-mode behavior can be exercised.
    """
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    params: dict = {"check_mode": check_mode, "fabric_name": fabric_name}
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
    ports: list[str] | None = None,
) -> PortChannelAccessInterfaceModel:
    """Build a minimal `PortChannelAccessInterfaceModel` instance for CRUD tests. `ports` defaults to `["Ethernet1/1"]`."""
    kwargs: dict = {"switch_ip": switch_ip, "interface_name": interface_name}
    if include_config:
        kwargs["config_data"] = PortChannelAccessConfigDataModel(
            network_os=PortChannelAccessNetworkOSModel(
                policy=PortChannelAccessPolicyModel(
                    admin_state=True, access_vlan=100, port_channel_mode="active", ports=ports if ports is not None else ["Ethernet1/1"]
                ),
            ),
        )
    return PortChannelAccessInterfaceModel(**kwargs)


def _build_xe_pc_model(
    interface_name: str = "port-channel101", ports: list[str] | None = None, switch_ip: str = "192.168.1.1"
) -> PortChannelAccessInterfaceModel:
    """Build an IOS-XE `iosXeAccessPoHost` model (members default to `["GigabitEthernet1/0/2"]`)."""
    return PortChannelAccessInterfaceModel.from_config(
        {
            "switch_ip": switch_ip,
            "interface_name": interface_name,
            "config_data": {
                "network_os": {
                    "network_os_type": "ios-xe",
                    "policy": {"access_vlan": 100, "ports": ports if ports is not None else ["GigabitEthernet1/0/2"]},
                }
            },
        }
    )


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

    Verify `_managed_policy_types` covers both the NX-OS `accessPoHost` and the IOS-XE `iosXeAccessPoHost` API values
    (issue #536).

    ## Test

    - Returned set contains exactly "accessPoHost" and "iosXeAccessPoHost"

    ## Classes and Methods

    - PortChannelAccessInterfaceOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    assert orchestrator._managed_policy_types() == {"accessPoHost", "iosXeAccessPoHost"}


def test_port_channel_access_orchestrator_00110() -> None:
    """
    # Summary

    Verify `_managed_policy_types` returns a set (supports set membership for `in` checks) containing both the
    NX-OS `accessPoHost` and the IOS-XE `iosXeAccessPoHost` API values.

    ## Test

    - Return type is set
    - Both "accessPoHost" and "iosXeAccessPoHost" are members

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
    assert "iosXeAccessPoHost" in result


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


def test_port_channel_access_orchestrator_00340() -> None:
    """
    # Summary

    Verify `delete` of an IOS-XE port-channel queues the switch-canonical spelling `Port-channel<N>` for both the remove and the
    deploy, so the controller generates `no interface Port-channel<N>` (workaround: xe-port-channel-remove-leaves-switch-interface).

    ## Test

    - Model is an `ios-xe` `iosXeAccessPoHost` named `port-channel101` (the lowercase identifier ND echoes)
    - `_pending_removes` contains `(Port-channel101, FDO11111AAA)`
    - `_pending_deploys` contains `(Port-channel101, FDO11111AAA)` (same pair identity as the remove queue, for the finalizer)

    ## Classes and Methods

    - PortChannelBaseOrchestrator.delete()
    - PortChannelBaseOrchestrator._delete_side_name()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    model = _build_xe_pc_model(interface_name="port-channel101")

    with does_not_raise():
        result = instance.delete(model)

    assert result is None
    assert instance._pending_removes == [("Port-channel101", "FDO11111AAA")]
    assert instance._pending_deploys == [("Port-channel101", "FDO11111AAA")]


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


def test_port_channel_access_orchestrator_00610() -> None:
    """
    # Summary

    Verify `delete_bulk` canonicalizes only the IOS-XE port-channels: an NX-OS port-channel keeps its lowercase name while an
    `ios-xe` one is queued as `Port-channel<N>` (workaround: xe-port-channel-remove-leaves-switch-interface).

    ## Test

    - NX-OS `port-channel501` on switch A and IOS-XE `port-channel101` on switch B
    - `_pending_removes` and `_pending_deploys` each contain `(port-channel501, FDO11111AAA)` and `(Port-channel101, FDO22222BBB)`

    ## Classes and Methods

    - PortChannelBaseOrchestrator.delete_bulk()
    - PortChannelBaseOrchestrator._delete_side_name()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    models = [
        _build_pc_model(switch_ip="192.168.1.1", interface_name="port-channel501", include_config=False),
        _build_xe_pc_model(switch_ip="192.168.1.2", interface_name="port-channel101"),
    ]

    with does_not_raise():
        result = instance.delete_bulk(models)

    assert result is None
    expected = [("port-channel501", "FDO11111AAA"), ("Port-channel101", "FDO22222BBB")]
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


# =============================================================================
# Test: preflight -- member-already-in-use (issue #369)
#
# Shared inventory for switch FDO11111AAA (see fixture TEST_NOTES): port-channel501 (accessPoHost) owns
# Ethernet1/1, port-channel502 (trunkPoHost) owns Ethernet1/3, port-channel500 (vpcPeerlinkPo, a type this
# orchestrator does NOT manage) owns Ethernet1/2, Ethernet1/35 is a free trunkHost, and Ethernet1/36 carries
# an accessPoMember policy type with no owning port-channel record. Every operData.portChannelId is -1
# (owners are intent-only), which is exactly why membership must be read from intent rather than operData.
# =============================================================================


def _preflight_orchestrator(method_name: str, check_mode: bool = False) -> PortChannelAccessInterfaceOrchestrator:
    """Build an orchestrator whose responses are the switches list (a) then the member-conflict inventory (b)."""

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")

    rest_send = _build_rest_send(ResponseGenerator(responses()), state="merged", check_mode=check_mode)
    return PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)


def test_port_channel_access_orchestrator_00900() -> None:
    """
    # Summary

    Verify `preflight` passes when every proposed member is free (case (a) in issue #369).

    ## Test

    - Proposed port-channel701 claims Ethernet1/35, whose intent policyType is trunkHost and which no port-channel record lists
    - `preflight` does not raise

    ## Classes and Methods

    - PortChannelBaseOrchestrator.preflight()
    - PortChannelBaseOrchestrator._validate_members_available()
    """
    method_name = inspect.stack()[0][3]
    instance = _preflight_orchestrator(method_name)
    model = _build_pc_model(interface_name="port-channel701", ports=["Ethernet1/35"])

    with does_not_raise():
        instance.preflight([model])


def test_port_channel_access_orchestrator_00910() -> None:
    """
    # Summary

    Verify `preflight` rejects members owned by a different port-channel, naming each member and its current owner,
    and aggregates every offender into one message (case (b) in issue #369).

    ## Test

    - Proposed port-channel702 claims Ethernet1/1 (owned by port-channel501/accessPoHost) and Ethernet1/3 (owned by port-channel502/trunkPoHost)
    - `preflight` raises RuntimeError naming both members and both owners

    ## Classes and Methods

    - PortChannelBaseOrchestrator.preflight()
    - PortChannelBaseOrchestrator._validate_members_available()
    """
    method_name = inspect.stack()[0][3]
    instance = _preflight_orchestrator(method_name)
    model = _build_pc_model(interface_name="port-channel702", ports=["Ethernet1/1", "Ethernet1/3"])

    with pytest.raises(RuntimeError) as exc_info:
        instance.preflight([model])

    message = str(exc_info.value)
    assert "port-channel702" in message
    assert "Ethernet1/1" in message and "port-channel501" in message
    assert "Ethernet1/3" in message and "port-channel502" in message
    assert "192.168.1.1" in message


def test_port_channel_access_orchestrator_00920() -> None:
    """
    # Summary

    Verify `preflight` reads membership from the unfiltered inventory: a member owned by a port-channel of a policy type this
    orchestrator does not manage (vpcPeerlinkPo) is still a conflict (case (c) in issue #369).

    ## Test

    - Proposed port-channel702 claims Ethernet1/2 (owned by port-channel500/vpcPeerlinkPo, which query_all would filter out)
    - `preflight` raises RuntimeError naming Ethernet1/2 and port-channel500

    ## Classes and Methods

    - PortChannelBaseOrchestrator.preflight()
    - PortChannelBaseOrchestrator._validate_members_available()
    """
    method_name = inspect.stack()[0][3]
    instance = _preflight_orchestrator(method_name)
    model = _build_pc_model(interface_name="port-channel702", ports=["Ethernet1/2"])

    with pytest.raises(RuntimeError, match=r"Ethernet1/2.*port-channel500"):
        instance.preflight([model])


def test_port_channel_access_orchestrator_00930() -> None:
    """
    # Summary

    Verify `preflight` allows a member already owned by the port-channel under management, so an idempotent re-apply of
    `merged` passes (case (d) in issue #369). Member names are compared case-insensitively.

    ## Test

    - Proposed port-channel501 claims ethernet1/1, which port-channel501 already owns in intent
    - `preflight` does not raise

    ## Classes and Methods

    - PortChannelBaseOrchestrator.preflight()
    - PortChannelBaseOrchestrator._validate_members_available()
    """
    method_name = inspect.stack()[0][3]
    instance = _preflight_orchestrator(method_name)
    model = _build_pc_model(interface_name="port-channel501", ports=["ethernet1/1"])

    with does_not_raise():
        instance.preflight([model])


def test_port_channel_access_orchestrator_00940() -> None:
    """
    # Summary

    Verify `preflight` hard-fails on a member conflict even in check mode (case (e) in issue #369). Unlike the capability
    preflight, which downgrades to a warning in check mode, membership comes from the standard interfaces GET.

    ## Test

    - rest_send.check_mode is True
    - Proposed port-channel702 claims Ethernet1/1 (owned by port-channel501)
    - `preflight` raises RuntimeError

    ## Classes and Methods

    - PortChannelBaseOrchestrator.preflight()
    - PortChannelBaseOrchestrator._validate_members_available()
    """
    method_name = inspect.stack()[0][3]
    instance = _preflight_orchestrator(method_name, check_mode=True)
    assert instance.rest_send.check_mode is True
    model = _build_pc_model(interface_name="port-channel702", ports=["Ethernet1/1"])

    with pytest.raises(RuntimeError, match=r"Ethernet1/1.*port-channel501"):
        instance.preflight([model])


def test_port_channel_access_orchestrator_00950() -> None:
    """
    # Summary

    Verify `preflight` rejects two proposed port-channels on the same switch that both claim the same free member. ND would
    accept the first create and reject the second with the same opaque 500, so the conflict is caught before any write.

    ## Test

    - Proposed port-channel701 and port-channel702 both claim Ethernet1/35 (free in ND)
    - `preflight` raises RuntimeError naming Ethernet1/35 and both port-channels

    ## Classes and Methods

    - PortChannelBaseOrchestrator.preflight()
    - PortChannelBaseOrchestrator._validate_members_available()
    """
    method_name = inspect.stack()[0][3]
    instance = _preflight_orchestrator(method_name)
    first = _build_pc_model(interface_name="port-channel701", ports=["Ethernet1/35"])
    second = _build_pc_model(interface_name="port-channel702", ports=["Ethernet1/35"])

    with pytest.raises(RuntimeError) as exc_info:
        instance.preflight([first, second])

    message = str(exc_info.value)
    assert "Ethernet1/35" in message
    assert "port-channel701" in message and "port-channel702" in message


def test_port_channel_access_orchestrator_00960() -> None:
    """
    # Summary

    Verify `preflight` issues no additional request after `query_all` has already fetched the switch's interfaces: both
    read the shared `_switch_interfaces` cache (CLAUDE.md performance rule -- fetch each resource at most once per run).

    ## Test

    - `query_all` (state merged, config scoped to 192.168.1.1) consumes summary (a), switches (b), interfaces (c)
    - No further responses are queued; the response generator is exhausted
    - `preflight` for a free member does not raise (an extra GET would exhaust the generator and raise)
    - `_switch_interfaces_cache` holds the unfiltered inventory for FDO11111AAA

    ## Classes and Methods

    - PortChannelBaseOrchestrator.query_all()
    - PortChannelBaseOrchestrator.preflight()
    - NDBaseInterfaceOrchestrator._switch_interfaces()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")
        yield responses_pc_access(f"{method_name}c")

    config = [{"switch_ip": "192.168.1.1", "interface_name": "port-channel701"}]
    instance = _build_orchestrator(ResponseGenerator(responses()), state="merged", config=config)

    with does_not_raise():
        result = instance.query_all()
        instance.preflight([_build_pc_model(interface_name="port-channel701", ports=["Ethernet1/35"])])

    # query_all still returns only the managed accessPoHost port-channels...
    assert [iface["interfaceName"] for iface in result] == ["port-channel501"]
    # ...while the cache retains the unfiltered inventory the preflight reads.
    assert set(instance._switch_interfaces_cache) == {"FDO11111AAA"}
    assert "ethernet1/2" in instance._switch_interfaces_cache["FDO11111AAA"]
    assert "port-channel500" in instance._switch_interfaces_cache["FDO11111AAA"]


def test_port_channel_access_orchestrator_00970() -> None:
    """
    # Summary

    Verify `preflight` rejects a member whose intent policyType ends in `Member` even when no port-channel record on the
    switch lists it, reporting the owner as unknown rather than treating the member as free.

    ## Test

    - Proposed port-channel702 claims Ethernet1/36 (policyType accessPoMember, listed by no port-channel record)
    - `preflight` raises RuntimeError naming Ethernet1/36 and its accessPoMember policy type

    ## Classes and Methods

    - PortChannelBaseOrchestrator.preflight()
    - PortChannelBaseOrchestrator._validate_members_available()
    """
    method_name = inspect.stack()[0][3]
    instance = _preflight_orchestrator(method_name)
    model = _build_pc_model(interface_name="port-channel702", ports=["Ethernet1/36"])

    with pytest.raises(RuntimeError, match=r"Ethernet1/36.*accessPoMember"):
        instance.preflight([model])


# =============================================================================
# Test: create_bulk -- grouped by (switch, policyType) (issue #409); IOS-XE managed types (issue #536)
# =============================================================================


def test_port_channel_access_orchestrator_01000() -> None:
    """
    # Summary

    Verify `_managed_policy_types` now covers both the NX-OS and the IOS-XE access port-channel types.

    ## Test

    - Returns exactly `{"accessPoHost", "iosXeAccessPoHost"}`

    ## Classes and Methods

    - PortChannelAccessInterfaceOrchestrator._managed_policy_types()
    """
    orchestrator = _build_orchestrator(ResponseGenerator(iter(())))
    assert orchestrator._managed_policy_types() == {"accessPoHost", "iosXeAccessPoHost"}


def test_port_channel_access_orchestrator_01010() -> None:
    """
    # Summary

    Verify `create_bulk` groups by `(switch, policyType)` (issue #409): an NX-OS and an IOS-XE port-channel on the same switch produce two
    POSTs, the IOS-XE body carries `Port-channel101`, and both interfaces are deploy-queued under their lowercase names.

    ## Test

    - Responses: switches list, POST (NX group), POST (XE group)
    - `len(rest_send.responses) == 3`
    - Last committed body is the XE group with `interfaceName == "Port-channel101"` and `policyType == "iosXeAccessPoHost"`
    - `_pending_deploys == [("port-channel501", sw), ("port-channel101", sw)]`

    ## Classes and Methods

    - PortChannelBaseOrchestrator.create_bulk()
    - NDBaseInterfaceOrchestrator.bulk_create_groups()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")
        yield responses_pc_access(f"{method_name}c")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    with does_not_raise():
        instance.create_bulk([_build_pc_model(), _build_xe_pc_model()])
    assert len(rest_send.responses) == 3
    body = rest_send.committed_payload
    assert [item["interfaceName"] for item in body["interfaces"]] == ["Port-channel101"]
    assert body["interfaces"][0]["configData"]["networkOS"]["policy"]["policyType"] == "iosXeAccessPoHost"
    assert instance._pending_deploys == [("port-channel501", "FDO11111AAA"), ("port-channel101", "FDO11111AAA")]


def test_port_channel_access_orchestrator_01020() -> None:
    """
    # Summary

    Verify a failing second group leaves the first group's deploys queued (partial-success bookkeeping) and raises `Bulk create failed`.

    ## Test

    - Responses: switches list, POST 207 success (NX group), POST 500 (XE group)
    - `RuntimeError` matches `Bulk create failed`
    - `_pending_deploys == [("port-channel501", sw)]` only

    ## Classes and Methods

    - PortChannelBaseOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")
        yield responses_pc_access(f"{method_name}c")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    with pytest.raises(RuntimeError, match=r"Bulk create failed"):
        instance.create_bulk([_build_pc_model(), _build_xe_pc_model()])
    assert instance._pending_deploys == [("port-channel501", "FDO11111AAA")]


def test_port_channel_access_orchestrator_01030() -> None:
    """
    # Summary

    Verify a mixed HTTP 207 inside one `(switch, policyType)` group still deploy-queues the item the controller accepted (PR #570
    review): the accepted sibling's intent IS on the controller, so the failure-path finalizer must ship it. ND echoes the canonical
    `Port-channel101` against the module's lowercase identifier, and the queued pair keeps the lowercase identifier.

    ## Test

    - Responses: switches list, POST 207 (`Port-channel101` `success`, `Port-channel102` `failed`)
    - Both items are `iosXeAccessPoHost`, so they share one POST
    - `RuntimeError` matches `Bulk create failed` and names the accepted item
    - `_pending_deploys == [("port-channel101", sw)]` only

    ## Classes and Methods

    - PortChannelBaseOrchestrator.create_bulk()
    - NDBaseInterfaceOrchestrator._post_bulk_create_group()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    models = [
        _build_xe_pc_model(interface_name="port-channel101", ports=["GigabitEthernet1/0/2"]),
        _build_xe_pc_model(interface_name="port-channel102", ports=["GigabitEthernet1/0/3"]),
    ]
    with pytest.raises(RuntimeError, match=r"Bulk create failed.*accepted \['port-channel101'\] from the same request"):
        instance.create_bulk(models)
    assert len(rest_send.responses) == 2
    assert instance._pending_deploys == [("port-channel101", "FDO11111AAA")]


# =============================================================================
# Test: preflight -- IOS-XE member-mode mismatch (issues #536/#537)
#
# Shared inventory for switch FDO11111AAA (see the 01100b fixture TEST_NOTES): GigabitEthernet1/0/2 is an
# iosXeTrunkHost, GigabitEthernet1/0/3 is a free iosXeAccess, GigabitEthernet1/0/4 is an iosXeAccessPoMember
# already owned by port-channel101, GigabitEthernet1/0/5 is an iosXeAccessPoMember owned by port-channel102,
# and Ethernet1/1 is an unrelated NX-OS trunkHost. GigabitEthernet1/0/9 does not exist on the switch.
# =============================================================================


@pytest.mark.parametrize(
    "ports, match",
    [
        (["GigabitEthernet1/0/2"], r"member=GigabitEthernet1/0/2, current policy=iosXeTrunkHost, required=iosXeAccess.*nd_interface_ethernet_access"),
        (["GigabitEthernet1/0/9"], r"member=GigabitEthernet1/0/9, current policy=absent from the switch inventory"),
    ],
)
def test_port_channel_access_orchestrator_01100(ports, match) -> None:
    """
    # Summary

    Verify the IOS-XE member-mode preflight refuses an `iosXeAccessPoHost` whose member is a trunk host or absent from the inventory,
    before any write and in check mode.

    # workaround: xe-port-channel-member-mode-mismatch

    ## Test

    - Responses: switches list, interfaces list for the switch
    - `preflight` raises `RuntimeError` matching `match`; no POST was sent (`len(rest_send.responses) == 2`)

    ## Classes and Methods

    - PortChannelBaseOrchestrator._validate_xe_member_modes()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")

    rest_send = _build_rest_send(ResponseGenerator(responses()), check_mode=True)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    with pytest.raises(RuntimeError, match=match):
        instance.preflight([_build_xe_pc_model(ports=ports)])
    assert len(rest_send.responses) == 2


def test_port_channel_access_orchestrator_01110() -> None:
    """
    # Summary

    Verify the preflight accepts a fresh `iosXeAccess` member and an `iosXeAccessPoMember` already owned by the same port-channel
    (idempotent re-apply), and skips NX-OS models entirely.

    ## Test

    - `port-channel101` with members Gi1/0/3 (iosXeAccess) and Gi1/0/4 (member of Port-channel101) passes
    - An NX-OS model naming Ethernet1/1 passes without consulting member policy types

    ## Classes and Methods

    - PortChannelBaseOrchestrator._validate_xe_member_modes()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")

    instance = PortChannelAccessInterfaceOrchestrator(rest_send=_build_rest_send(ResponseGenerator(responses())))
    with does_not_raise():
        instance.preflight([_build_xe_pc_model(ports=["GigabitEthernet1/0/3", "GigabitEthernet1/0/4"]), _build_pc_model(ports=["Ethernet1/1"])])


def test_port_channel_access_orchestrator_01120() -> None:
    """
    # Summary

    Verify a member owned by ANOTHER port-channel is reported by the existing member-availability preflight first (its message names the
    current owner), so the mode preflight never masks the ownership conflict.

    ## Test

    - `port-channel101` naming Gi1/0/5 (member of port-channel102) raises `already in use ... current owner=port-channel102`

    ## Classes and Methods

    - PortChannelBaseOrchestrator._validate_members_available()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")

    instance = PortChannelAccessInterfaceOrchestrator(rest_send=_build_rest_send(ResponseGenerator(responses())))
    with pytest.raises(RuntimeError, match=r"already in use.*current owner=port-channel102"):
        instance.preflight([_build_xe_pc_model(ports=["GigabitEthernet1/0/5"])])


# =============================================================================
# Test: query_all -- policy-less rediscovered IOS-XE port-channels (PR #570 review)
#
# Shared inventory shape for switch FDO11111AAA (see the 01200c fixture TEST_NOTES): port-channel101 is a managed
# iosXeAccessPoHost; Port-channel111 and Port-channel113 are rediscovered records with no `policy` key; Port-channel112
# carries an explicit `policy: null`; port-channel900 carries `configData: null`.
# =============================================================================


def _query_all_policy_less(method_name: str, state: str, config: list[dict]) -> tuple[PortChannelAccessInterfaceOrchestrator, list[dict]]:
    """Run `query_all` against the three-response policy-less inventory; return the orchestrator and the records it kept."""

    def responses():
        yield responses_pc_access(f"{method_name}a")
        yield responses_pc_access(f"{method_name}b")
        yield responses_pc_access(f"{method_name}c")

    rest_send = _build_rest_send(ResponseGenerator(responses()), state=state, config=config)
    instance = PortChannelAccessInterfaceOrchestrator(rest_send=rest_send)
    with does_not_raise():
        result = instance.query_all()
    return instance, result


def _query_all_names(method_name: str, state: str, config: list[dict]) -> list[str]:
    """Return the interface names `query_all` kept from the policy-less inventory."""
    return [iface["interfaceName"] for iface in _query_all_policy_less(method_name, state, config)[1]]


def test_port_channel_access_orchestrator_01200() -> None:
    """
    # Summary

    Verify an explicit `state: deleted` sees the policy-less IOS-XE port-channels it names, so the rediscovered orphan of an early
    removal can reach the canonical remove, and that an explicit `policy: null` or `configData: null` no longer raises.

    ## Test

    - `state: deleted` naming port-channel111 (record has no `policy` key) and port-channel112 (record has `policy: null`)
    - `query_all` returns the managed port-channel101 plus Port-channel111 and Port-channel112
    - Port-channel113 (policy-less, not named) and port-channel900 (`configData: null`) are left out

    ## Classes and Methods

    - PortChannelBaseOrchestrator.query_all()
    """
    config = [{"switch_ip": "192.168.1.1", "interface_name": name} for name in ("port-channel111", "Port-Channel112")]
    names = _query_all_names(inspect.stack()[0][3], "deleted", config)
    assert names == ["port-channel101", "Port-channel111", "Port-channel112"]


def test_port_channel_access_orchestrator_01210() -> None:
    """
    # Summary

    Verify `state: overridden` never sees a policy-less record: the module cannot prove it owns an interface with no policy, so a
    fabric-wide override must not delete it.

    ## Test

    - `state: overridden` with a config naming only port-channel101
    - `query_all` returns port-channel101 only

    ## Classes and Methods

    - PortChannelBaseOrchestrator.query_all()
    """
    config = [{"switch_ip": "192.168.1.1", "interface_name": "port-channel101"}]
    assert _query_all_names(inspect.stack()[0][3], "overridden", config) == ["port-channel101"]


def test_port_channel_access_orchestrator_01220() -> None:
    """
    # Summary

    Verify only `state: deleted` sees a named policy-less record: under `state: merged` it stays filtered, so the create path is
    unchanged.

    ## Test

    - `state: merged` naming port-channel111
    - `query_all` returns port-channel101 only

    ## Classes and Methods

    - PortChannelBaseOrchestrator.query_all()
    """
    config = [{"switch_ip": "192.168.1.1", "interface_name": "port-channel111"}]
    assert _query_all_names(inspect.stack()[0][3], "merged", config) == ["port-channel101"]


def test_port_channel_access_orchestrator_01230() -> None:
    """
    # Summary

    Verify the policy-less rediscovered IOS-XE record `query_all` keeps for an explicit delete parses into the model, that deleting
    it queues the switch-canonical name on both delete-side queues, and that the shared inventory cache is left untouched.

    ## Test

    - `state: deleted` naming port-channel111; `query_all` keeps the record for `Port-channel111`
    - `from_response` succeeds although the wire record carries `mode: unknown`; the identifier is the lowercase `port-channel111`
    - `delete` queues `("Port-channel111", sw)` for remove and deploy
    - The cached inventory record still carries `mode: unknown`

    ## Classes and Methods

    - PortChannelBaseOrchestrator.query_all()
    - PortChannelAccessInterfaceModel.from_response()
    - PortChannelBaseOrchestrator.delete()
    """
    config = [{"switch_ip": "192.168.1.1", "interface_name": "port-channel111"}]
    instance, result = _query_all_policy_less(inspect.stack()[0][3], "deleted", config)
    record = next(iface for iface in result if iface["interfaceName"] == "Port-channel111")

    with does_not_raise():
        model = PortChannelAccessInterfaceModel.from_response(record)
        instance.delete(model)

    assert model.interface_name == "port-channel111"
    assert instance._pending_removes == [("Port-channel111", "FDO11111AAA")]
    assert instance._pending_deploys == [("Port-channel111", "FDO11111AAA")]
    cached = next(iface for iface in instance._switch_interfaces("FDO11111AAA").values() if iface["interfaceName"] == "Port-channel111")
    assert cached["configData"]["mode"] == "unknown"
