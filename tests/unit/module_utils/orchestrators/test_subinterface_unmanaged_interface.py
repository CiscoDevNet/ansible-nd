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


def _build_rest_send(gen_responses: ResponseGenerator) -> RestSend:
    """Build a `RestSend` wired to a file-based `Sender` and `ResponseHandler`."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    rest_send = RestSend({"check_mode": False, "fabric_name": "fabric_1"})
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
        ({"results": []}, False),
        ({}, False),
        (None, False),
        ("not a dict", False),
    ],
    ids=["success", "failed-raises", "error-raises", "empty-results", "missing-results", "none-input", "non-dict-input"],
)
def test_subinterface_unmanaged_interface_00010(payload, expected_raise) -> None:
    """
    # Summary

    Verify `_raise_on_multi_status_failures` behavior across the matrix.

    ## Test

    - Various 207-body shapes are passed
    - `RuntimeError` is raised iff any item carries `status` in `("failed", "error")`

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
