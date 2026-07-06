# pylint: disable=unused-import
# pylint: disable=redefined-outer-name
# pylint: disable=protected-access
# pylint: disable=unused-argument
# pylint: disable=unused-variable
# pylint: disable=invalid-name
# pylint: disable=line-too-long
# pylint: disable=too-many-lines

"""Unit tests for SubinterfaceUnmanagedInterfaceOrchestrator."""

from __future__ import annotations

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.subinterface_unmanaged_interface import SubinterfaceUnmanagedInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.subinterface_unmanaged_interface import (
    SubinterfaceUnmanagedInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_subinterface_unmanaged_interface(key: str):
    """Load fixture data for test_subinterface_unmanaged_interface tests."""
    return load_fixture("test_subinterface_unmanaged_interface")[key]


def _build_rest_send(
    gen_responses: ResponseGenerator,
    state: str | None = None,
    config: list[dict] | None = None,
) -> RestSend:
    """Build a `RestSend` wired to a file-based `Sender` and `ResponseHandler`.

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

    params: dict = {"check_mode": False, "fabric_name": "fabric_1"}
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


# =============================================================================
# Test: _raise_on_multi_status_failures
# =============================================================================


@pytest.mark.parametrize(
    "payload, expected_raise",
    [
        ({"results": [{"name": "Ethernet1/3.20", "status": "success", "message": "ok"}]}, False),
        ({"results": [{"name": "Ethernet1/3.20", "status": "failed", "message": "parent not routed"}]}, True),
        ({"results": [{"name": "Ethernet1/3.20", "status": "error", "message": "validation"}]}, True),
        ({"results": [{"name": "Ethernet1/3.20", "status": "Failed", "message": "parent not routed"}]}, True),
        ({"results": [{"name": "Ethernet1/3.20", "status": " ERROR ", "message": "validation"}]}, True),
        ({"results": [{"name": "Ethernet1/3.20", "status": None, "message": "no status key"}]}, False),
        ({"results": []}, False),
        ({}, False),
        (None, False),
        ("not a dict", False),
    ],
    ids=[
        "success",
        "failed-raises",
        "error-raises",
        "failed-mixed-case-raises",
        "error-padded-uppercase-raises",
        "none-status-no-raise",
        "empty-results",
        "missing-results",
        "none-input",
        "non-dict-input",
    ],
)
def test_subinterface_unmanaged_interface_00010(payload, expected_raise) -> None:
    """
    # Summary

    Verify `_raise_on_multi_status_failures` behavior across the matrix.

    ## Test

    - Various 207-body shapes are passed
    - `RuntimeError` is raised iff any item carries `status` of `"failed"`/`"error"` (case-insensitive, whitespace-tolerant)

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator._raise_on_multi_status_failures()
    """
    if expected_raise:
        with pytest.raises(RuntimeError, match=r"ND rejected"):
            SubinterfaceUnmanagedInterfaceOrchestrator._raise_on_multi_status_failures(payload)
    else:
        with does_not_raise():
            SubinterfaceUnmanagedInterfaceOrchestrator._raise_on_multi_status_failures(payload)


# =============================================================================
# Test: create
# =============================================================================


def test_subinterface_unmanaged_interface_00100(monkeypatch) -> None:
    """
    # Summary

    Verify `create` resolves the switch IP, wraps the payload in `{"interfaces": [...]}`, injects `switchId`, and queues a deploy.

    ## Test

    - First call to `_resolve_switch_id` triggers switches-list fetch
    - POST is issued against `/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces`
    - Request body is `{"interfaces": [{...payload..., "switchId": "FDO12345ABC"}]}`
    - `_pending_deploys` contains a single `(interface_name, switch_id)` pair
    - Result carries `results[0].status == "success"`

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.create()
    - NDBaseInterfaceOrchestrator._resolve_switch_id()
    - NDBaseInterfaceOrchestrator._queue_deploy()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")
        yield responses_subinterface_unmanaged_interface(f"{method_name}b")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send, fabric_name="fabric_1", params={"state": "merged"})
    model = SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.151", interface_name="Ethernet1/3.20")

    with does_not_raise():
        result = orchestrator.create(model)

    assert result["results"][0]["status"] == "success"
    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces"
    assert rest_send.verb == HttpVerbEnum.POST.value
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert "interfaces" in body
    assert len(body["interfaces"]) == 1
    payload_item = body["interfaces"][0]
    assert payload_item["interfaceName"] == "Ethernet1/3.20"
    assert payload_item["interfaceType"] == "subInterface"
    assert payload_item["switchId"] == "FDO12345ABC"
    assert "switchIp" not in payload_item
    assert ("Ethernet1/3.20", "FDO12345ABC") in orchestrator._pending_deploys


def test_subinterface_unmanaged_interface_00101(monkeypatch) -> None:
    """
    # Summary

    Verify `create` raises when the 207 response carries `status: failed`.

    ## Test

    - POST returns 207 with `results[0].status = "failed"`
    - `_raise_on_multi_status_failures` raises; `create` wraps it in a `RuntimeError` matching `Create failed.*ND rejected`

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.create()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")
        yield responses_subinterface_unmanaged_interface(f"{method_name}b")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send, fabric_name="fabric_1", params={"state": "merged"})
    model = SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.151", interface_name="Ethernet1/3.20")

    with pytest.raises(RuntimeError, match=r"Create failed.*ND rejected"):
        orchestrator.create(model)

    assert orchestrator._pending_deploys == []


def test_subinterface_unmanaged_interface_00102(monkeypatch) -> None:
    """
    # Summary

    Verify `create` wraps a `_request` failure (non-2xx) in `RuntimeError` mentioning the identifier.

    ## Test

    - switches-list returns 200
    - POST returns 500
    - `RuntimeError` matches `Create failed for .*Ethernet1/3.20`
    - No deploy is queued

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.create()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")
        yield responses_subinterface_unmanaged_interface(f"{method_name}b")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send, fabric_name="fabric_1", params={"state": "merged"})
    model = SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.151", interface_name="Ethernet1/3.20")

    match = r"Create failed for .*Ethernet1/3\.20"
    with pytest.raises(RuntimeError, match=match):
        orchestrator.create(model)

    assert orchestrator._pending_deploys == []


# =============================================================================
# Test: update
# =============================================================================


def test_subinterface_unmanaged_interface_00200(monkeypatch) -> None:
    """
    # Summary

    Verify `update` issues a PUT against the per-interface URL, injects `switchId` into the payload, and queues a deploy.

    ## Test

    - switches-list fetched on first switch_id resolution
    - PUT is issued against `/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces/Ethernet1%2F3.20`
    - `switchId` is present in the payload
    - `_pending_deploys` contains the `(Ethernet1/3.20, FDO12345ABC)` pair

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")
        yield responses_subinterface_unmanaged_interface(f"{method_name}b")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send, fabric_name="fabric_1", params={"state": "merged"})
    model = SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.151", interface_name="Ethernet1/3.20")

    with does_not_raise():
        orchestrator.update(model)

    assert rest_send.verb == HttpVerbEnum.PUT.value
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert body["interfaceName"] == "Ethernet1/3.20"
    assert body["switchId"] == "FDO12345ABC"
    assert "switchIp" not in body
    assert ("Ethernet1/3.20", "FDO12345ABC") in orchestrator._pending_deploys


def test_subinterface_unmanaged_interface_00201(monkeypatch) -> None:
    """
    # Summary

    Verify `update` wraps a `_request` failure in `RuntimeError` mentioning the identifier.

    ## Test

    - PUT returns 500
    - `RuntimeError` matches `Update failed for .*Ethernet1/3.20`
    - No deploy is queued

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")
        yield responses_subinterface_unmanaged_interface(f"{method_name}b")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send, fabric_name="fabric_1", params={"state": "merged"})
    model = SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.151", interface_name="Ethernet1/3.20")

    match = r"Update failed for .*Ethernet1/3\.20"
    with pytest.raises(RuntimeError, match=match):
        orchestrator.update(model)

    assert orchestrator._pending_deploys == []


# =============================================================================
# Test: delete
# =============================================================================


def test_subinterface_unmanaged_interface_00300(monkeypatch) -> None:
    """
    # Summary

    Verify `delete` queues a remove + deploy without making any API call beyond the switches-list fetch.

    ## Test

    - Only the switches-list response is consumed (one HTTP call to resolve switch_id)
    - `_pending_removes` contains `(Ethernet1/3.20, FDO12345ABC)`
    - `_pending_deploys` contains `(Ethernet1/3.20, FDO12345ABC)`
    - `delete` returns None

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.delete()
    - NDBaseInterfaceOrchestrator._queue_remove()
    - NDBaseInterfaceOrchestrator._queue_deploy()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send, fabric_name="fabric_1", params={"state": "deleted"})
    model = SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.151", interface_name="Ethernet1/3.20")

    with does_not_raise():
        result = orchestrator.delete(model)

    assert result is None
    assert ("Ethernet1/3.20", "FDO12345ABC") in orchestrator._pending_removes
    assert ("Ethernet1/3.20", "FDO12345ABC") in orchestrator._pending_deploys


def test_subinterface_unmanaged_interface_00301(monkeypatch) -> None:
    """
    # Summary

    Verify `delete` propagates the raw `RuntimeError` from `_resolve_switch_id` when the IP is unknown.

    ## Test

    - switches-list returns a different IP
    - `RuntimeError` matches `No switch found with fabricManagementIp '192\\.168\\.12\\.151'`
    - No queues are populated

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.delete()
    - NDBaseInterfaceOrchestrator._resolve_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send, fabric_name="fabric_1", params={"state": "deleted"})
    model = SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.151", interface_name="Ethernet1/3.20")

    match = r"No switch found with fabricManagementIp '192\.168\.12\.151'"
    with pytest.raises(RuntimeError, match=match):
        orchestrator.delete(model)

    assert orchestrator._pending_removes == []
    assert orchestrator._pending_deploys == []


# =============================================================================
# Test: create_bulk
# =============================================================================


def test_subinterface_unmanaged_interface_00400(monkeypatch) -> None:
    """
    # Summary

    Verify `create_bulk` groups interfaces by switch and issues one POST per switch with the per-switch subset
    wrapped in `{"interfaces": [...]}`.

    ## Test

    - Three interfaces split across two switches: Ethernet1/3.20 + Ethernet1/3.21 on switch A, Ethernet1/3.20 on switch B
    - Two POSTs are issued (one per switch)
    - All three pairs are queued in `_pending_deploys`

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")
        yield responses_subinterface_unmanaged_interface(f"{method_name}b")
        yield responses_subinterface_unmanaged_interface(f"{method_name}c")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send, fabric_name="fabric_1", params={"state": "merged"})
    models = [
        SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.151", interface_name="Ethernet1/3.20"),
        SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.151", interface_name="Ethernet1/3.21"),
        SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.152", interface_name="Ethernet1/3.20"),
    ]

    with does_not_raise():
        orchestrator.create_bulk(models)

    assert rest_send.path in (
        "/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces",
        "/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABD/interfaces",
    )
    assert rest_send.verb == HttpVerbEnum.POST.value
    assert sorted(orchestrator._pending_deploys) == sorted(
        [
            ("Ethernet1/3.20", "FDO12345ABC"),
            ("Ethernet1/3.21", "FDO12345ABC"),
            ("Ethernet1/3.20", "FDO12345ABD"),
        ]
    )


def test_subinterface_unmanaged_interface_00401(monkeypatch) -> None:
    """
    # Summary

    Verify `create_bulk` wraps a per-switch `_request` failure in `RuntimeError` matching `Bulk create failed`.

    ## Test

    - switches-list succeeds
    - First per-switch POST succeeds, second returns 500
    - `RuntimeError` matches `Bulk create failed`

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")
        yield responses_subinterface_unmanaged_interface(f"{method_name}b")
        yield responses_subinterface_unmanaged_interface(f"{method_name}c")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send, fabric_name="fabric_1", params={"state": "merged"})
    models = [
        SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.151", interface_name="Ethernet1/3.20"),
        SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.152", interface_name="Ethernet1/3.20"),
    ]

    match = r"Bulk create failed"
    with pytest.raises(RuntimeError, match=match):
        orchestrator.create_bulk(models)


# =============================================================================
# Test: delete_bulk
# =============================================================================


def test_subinterface_unmanaged_interface_00500(monkeypatch) -> None:
    """
    # Summary

    Verify `delete_bulk` queues remove + deploy entries for each instance without issuing any API call beyond the
    switches-list fetch.

    ## Test

    - Two interfaces on two switches
    - Only switches-list response is consumed
    - `_pending_removes` and `_pending_deploys` each contain both pairs
    - `delete_bulk` returns None

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.delete_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send, fabric_name="fabric_1", params={"state": "deleted"})
    models = [
        SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.151", interface_name="Ethernet1/3.20"),
        SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.152", interface_name="Ethernet1/3.20"),
    ]

    with does_not_raise():
        result = orchestrator.delete_bulk(models)

    assert result is None
    expected = [("Ethernet1/3.20", "FDO12345ABC"), ("Ethernet1/3.20", "FDO12345ABD")]
    assert sorted(orchestrator._pending_removes) == sorted(expected)
    assert sorted(orchestrator._pending_deploys) == sorted(expected)


# =============================================================================
# Test: query_one
# =============================================================================


def test_subinterface_unmanaged_interface_00600(monkeypatch) -> None:
    """
    # Summary

    Verify `query_one` issues a GET against the per-interface URL and returns the DATA dict.

    ## Test

    - switches-list fetched on first switch_id resolution
    - GET hits `/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces/Ethernet1%2F3.20`
    - Returned DATA matches the fixture (policyType: monitorSubinterface)

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.query_one()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")
        yield responses_subinterface_unmanaged_interface(f"{method_name}b")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send, fabric_name="fabric_1", params={"state": "merged"})
    model = SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.151", interface_name="Ethernet1/3.20")

    with does_not_raise():
        result = orchestrator.query_one(model)

    assert rest_send.verb == HttpVerbEnum.GET.value
    assert result["interfaceName"] == "Ethernet1/3.20"
    assert result["interfaceType"] == "subInterface"
    assert result["configData"]["networkOS"]["policy"]["policyType"] == "monitorSubinterface"


def test_subinterface_unmanaged_interface_00601(monkeypatch) -> None:
    """
    # Summary

    Verify `query_one` wraps a `_request` failure in `RuntimeError` mentioning the identifier.

    ## Test

    - switches-list succeeds, GET returns 500
    - `RuntimeError` matches `Query failed for .*Ethernet1/3.20`

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.query_one()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")
        yield responses_subinterface_unmanaged_interface(f"{method_name}b")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send, fabric_name="fabric_1", params={"state": "merged"})
    model = SubinterfaceUnmanagedInterfaceModel(switch_ip="192.168.12.151", interface_name="Ethernet1/3.20")

    match = r"Query failed for .*Ethernet1/3\.20"
    with pytest.raises(RuntimeError, match=match):
        orchestrator.query_one(model)


# =============================================================================
# Test: query_all
# =============================================================================


def test_subinterface_unmanaged_interface_00700(monkeypatch) -> None:
    """
    # Summary

    Verify `query_all` validates prerequisites, iterates all switches in the fabric (`state: overridden` is
    fabric-wide per `_switches_to_query`), filters for `monitorSubinterface` policyType, and enriches each
    result with `switchIp`.

    ## Test

    - state is `overridden`, so `_switches_to_query` returns the full switch map
    - Fabric summary fetched once (validate_prerequisites)
    - Switches-list fetched once (switch_map)
    - Switch A returns a mix: one managed subinterface (policyType=subinterface) + one unmanaged (policyType=monitorSubinterface)
    - Switch B returns only a managed subinterface
    - Result contains only the unmanaged entry from switch A, enriched with `switchIp`

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.query_all()
    - NDBaseInterfaceOrchestrator._switches_to_query()
    - NDBaseInterfaceOrchestrator.validate_prerequisites()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")
        yield responses_subinterface_unmanaged_interface(f"{method_name}b")
        yield responses_subinterface_unmanaged_interface(f"{method_name}c")
        yield responses_subinterface_unmanaged_interface(f"{method_name}d")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen, state="overridden")

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["interfaceName"] == "Ethernet1/3.20"
    assert result[0]["configData"]["networkOS"]["policy"]["policyType"] == "monitorSubinterface"
    assert result[0]["switchIp"] == "192.168.12.151"
    # Verify the managed entry was excluded
    assert all(item["configData"]["networkOS"]["policy"]["policyType"] == "monitorSubinterface" for item in result)


def test_subinterface_unmanaged_interface_00701(monkeypatch) -> None:
    """
    # Summary

    Verify `query_all` returns an empty list when the fabric has no switches.

    ## Test

    - Fabric summary returns valid (local, default)
    - Switches list returns no switches
    - `query_all` returns []
    - No per-switch interface fetches occur

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")
        yield responses_subinterface_unmanaged_interface(f"{method_name}b")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send, fabric_name="fabric_1", params={"state": "merged"})

    with does_not_raise():
        result = orchestrator.query_all()

    assert result == []


def test_subinterface_unmanaged_interface_00702(monkeypatch) -> None:
    """
    # Summary

    Verify `query_all` surfaces a `RuntimeError` (wrapped as `Query all failed: ...`) when the fabric is in
    deployment-freeze mode.

    ## Test

    - Fabric summary returns `fabricStatus: frozen`
    - `query_all` raises `RuntimeError` with `Query all failed.*deployment freeze`
    - No per-switch fetches occur

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.query_all()
    - NDBaseInterfaceOrchestrator.validate_prerequisites()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send, fabric_name="fabric_1", params={"state": "merged"})

    match = r"Query all failed.*deployment freeze"
    with pytest.raises(RuntimeError, match=match):
        orchestrator.query_all()


def test_subinterface_unmanaged_interface_00703(monkeypatch) -> None:
    """
    # Summary

    Verify `query_all` returns an empty list when no switch has any subInterface entries.

    ## Test

    - state is `overridden`, so the switch's interfaces are fetched (fabric-wide scope)
    - One switch with only ethernet interfaces
    - `query_all` returns []

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")
        yield responses_subinterface_unmanaged_interface(f"{method_name}b")
        yield responses_subinterface_unmanaged_interface(f"{method_name}c")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen, state="overridden")

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = orchestrator.query_all()

    assert result == []


def test_subinterface_unmanaged_interface_00704(monkeypatch) -> None:
    """
    # Summary

    Verify `query_all` skips a switch whose interface-list DATA is a non-dict (e.g. ND returns a bare JSON array
    instead of `{"interfaces": [...]}`) instead of raising `AttributeError` on `.get()`.

    ## Test

    - state is `overridden`, so the switch's interfaces are fetched (fabric-wide scope)
    - Fabric summary returns valid (local, default)
    - Switches list returns one switch
    - That switch's interfaces GET returns a bare list as DATA
    - `query_all` returns [] without raising

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceOrchestrator.query_all()
    - NDBaseInterfaceOrchestrator._switch_interfaces()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")
        yield responses_subinterface_unmanaged_interface(f"{method_name}b")
        yield responses_subinterface_unmanaged_interface(f"{method_name}c")

    gen = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen, state="overridden")

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = orchestrator.query_all()

    assert result == []


def test_subinterface_unmanaged_interface_00705(monkeypatch) -> None:
    """
    # Summary

    Verify `query_all` scopes its per-switch interface-list fan-out to switches named in the user config when
    `state` is not `overridden`, rather than querying every switch in the fabric.

    ## Test

    - Fabric has two switches (192.168.12.151, 192.168.12.152), but config names only 192.168.12.151
    - state is `merged` (non-overridden), so `_switches_to_query` returns only the config switch
    - Only the config switch's interfaces are fetched; the second switch is never queried (the response
      generator yields exactly three responses — summary, switch list, switch-1 interfaces — and would raise
      if a second per-switch GET were issued)
    - Result contains only the unmanaged subinterface on the config switch

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator._switches_to_query()
    - SubinterfaceUnmanagedInterfaceOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_subinterface_unmanaged_interface(f"{method_name}a")
        yield responses_subinterface_unmanaged_interface(f"{method_name}b")
        yield responses_subinterface_unmanaged_interface(f"{method_name}c")

    gen = ResponseGenerator(responses())

    config = [{"switch_ip": "192.168.12.151", "interface_name": "Ethernet1/3.20"}]
    rest_send = _build_rest_send(gen, state="merged", config=config)

    orchestrator = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["interfaceName"] == "Ethernet1/3.20"
    assert result[0]["switchIp"] == "192.168.12.151"
