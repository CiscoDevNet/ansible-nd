# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `NDBaseInterfaceOrchestrator`.

Verifies the shared interface-orchestrator infrastructure: lazy `FabricContext`, switch IP-to-serial
resolution, fabric pre-flight validation, capability-preflight gating, endpoint configuration,
deploy/remove queue de-duplication, and bulk `deploy_pending` / `remove_pending` flush against the
`interfaceActions/deploy` and `interfaceActions/remove` endpoints.

Uses `_StubInterfaceOrchestrator`, a minimal concrete subclass, to satisfy `NDBaseOrchestrator`'s
Pydantic field requirements without coupling these tests to any per-feature orchestrator.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,too-many-lines
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import inspect
from types import SimpleNamespace

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import FinalizationContext
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.retry_policy import RestRetryPolicy
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


class _StubInterfaceOrchestrator(NDBaseInterfaceOrchestrator):
    """Minimal concrete subclass used only to instantiate `NDBaseInterfaceOrchestrator` for tests.

    The endpoint values below satisfy `NDBaseOrchestrator`'s Pydantic field requirements; tests in
    this file exercise methods on `NDBaseInterfaceOrchestrator` that do not reference any of them
    (the `interfaceActions/deploy` and `interfaceActions/remove` endpoints used by `deploy_pending`
    and `remove_pending` are instantiated internally by `_deploy_interfaces` / `_remove_interfaces`).
    """

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet


class _StubOptedInOrchestrator(_StubInterfaceOrchestrator):
    """Stub that opts in to capability preflight via `interface_type` but omits `interface_mode`.

    Used to verify `validate_switches_capable` raises a clear error for a half-configured subclass.
    """

    interface_type = "loopback"


class _StubCapableOrchestrator(_StubInterfaceOrchestrator):
    """Stub that fully opts in to capability preflight via both `interface_type` and `interface_mode`.

    Used to drive `validate_switches_capable` through the resolution + capability-endpoint code path.
    """

    interface_type = "loopback"
    interface_mode = "managed"


def responses_base_interface(key: str):
    """Load fixture data for test_base_interface tests."""
    return load_fixture("test_base_interface")[key]


def _build_rest_send(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1") -> RestSend:
    """Build a `RestSend` wired to a file-based `Sender` and `ResponseHandler`."""
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


# =============================================================================
# Test: initialization
# =============================================================================


def test_base_interface_00010() -> None:
    """
    # Summary

    Verify `NDBaseInterfaceOrchestrator` initializes with empty queues, `deploy=True`, and no `FabricContext`.

    ## Test

    - `_pending_deploys` and `_pending_removes` start empty
    - `deploy` defaults to False
    - `_fabric_context` is None before first access

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.__init__()
    - NDBaseInterfaceOrchestrator.model_post_init()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    assert instance._pending_deploys == []
    assert instance._pending_removes == []
    assert instance.deploy is False
    assert instance._fabric_context is None


def test_base_interface_00020() -> None:
    """
    # Summary

    Verify `fabric_name` is read from `rest_send.params["fabric_name"]`.

    ## Test

    - `instance.fabric_name` returns the value set on `rest_send.params`

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.fabric_name
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, fabric_name="my_fabric")
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    assert instance.fabric_name == "my_fabric"


# =============================================================================
# Test: fabric_context property (lazy)
# =============================================================================


def test_base_interface_00100() -> None:
    """
    # Summary

    Verify `fabric_context` is lazily constructed on first access, cached, and bound to the right `fabric_name`.

    ## Test

    - Before first access, `_fabric_context` is None
    - First access returns a `FabricContext` and stores it
    - Second access returns the same instance (no rebuild)
    - The constructed context's `fabric_name` matches the orchestrator's

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.fabric_context
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    assert instance._fabric_context is None
    first = instance.fabric_context
    second = instance.fabric_context

    assert isinstance(first, FabricContext)
    assert first is second
    assert first.fabric_name == "fabric_1"


# =============================================================================
# Test: _resolve_switch_id
# =============================================================================


def test_base_interface_00200() -> None:
    """
    # Summary

    Verify `_resolve_switch_id` returns the `switchId` for a known management IP via the cached `FabricContext`.

    ## Test

    - Switches-list endpoint returns a switch with `fabricManagementIp=192.168.12.151`
    - `_resolve_switch_id("192.168.12.151")` returns `"FDO12345ABC"`

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator._resolve_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        switch_id = instance._resolve_switch_id("192.168.12.151")

    assert switch_id == "FDO12345ABC"


def test_base_interface_00210() -> None:
    """
    # Summary

    Verify `_resolve_switch_id` raises `RuntimeError` when the IP is not in the fabric.

    ## Test

    - Switches-list returns a different IP
    - `_resolve_switch_id("192.168.12.151")` raises `RuntimeError` containing the IP and fabric name

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator._resolve_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    match = r"No switch found with fabricManagementIp '192\.168\.12\.151' in fabric 'fabric_1'"
    with pytest.raises(RuntimeError, match=match):
        instance._resolve_switch_id("192.168.12.151")


# =============================================================================
# Test: validate_prerequisites
# =============================================================================


def test_base_interface_00300() -> None:
    """
    # Summary

    Verify `validate_prerequisites` is a no-op when the fabric exists, is local, and is not frozen.

    ## Test

    - Summary returns 200 with `local: true` and `fabricStatus: default`
    - `validate_prerequisites` does not raise

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.validate_prerequisites()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.validate_prerequisites()


def test_base_interface_00310() -> None:
    """
    # Summary

    Verify `validate_prerequisites` raises `RuntimeError` when the fabric does not exist.

    ## Test

    - Summary returns 404
    - `validate_prerequisites` raises `RuntimeError` matching `Fabric 'missing_fabric' not found`

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.validate_prerequisites()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, fabric_name="missing_fabric")
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    match = r"Fabric 'missing_fabric' not found"
    with pytest.raises(RuntimeError, match=match):
        instance.validate_prerequisites()


def test_base_interface_00320() -> None:
    """
    # Summary

    Verify `validate_prerequisites` raises `RuntimeError` when the fabric is in deployment freeze mode.

    ## Test

    - Summary returns 200 with `fabricStatus: frozen`
    - `validate_prerequisites` raises `RuntimeError` matching `deployment freeze mode`

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.validate_prerequisites()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    match = r"Fabric 'fabric_1' is in deployment freeze mode"
    with pytest.raises(RuntimeError, match=match):
        instance.validate_prerequisites()


# =============================================================================
# Test: _configure_endpoint
# =============================================================================


def test_base_interface_00400() -> None:
    """
    # Summary

    Verify `_configure_endpoint` sets `fabric_name` and `switch_sn` on an endpoint instance and returns it.

    ## Test

    - Endpoint instance is mutated with the orchestrator's `fabric_name` and the supplied `switch_sn`
    - The returned object is the same instance that was passed in
    - The resulting `path` reflects both values

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator._configure_endpoint()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    endpoint = EpManageInterfacesPost()
    configured = instance._configure_endpoint(endpoint, switch_sn="FDO12345ABC")

    assert configured is endpoint
    assert endpoint.fabric_name == "fabric_1"
    assert endpoint.switch_sn == "FDO12345ABC"
    assert endpoint.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces"


# =============================================================================
# Test: _queue_deploy / _queue_remove
# =============================================================================


def test_base_interface_00500() -> None:
    """
    # Summary

    Verify `_queue_deploy` appends a new `(interface_name, switch_id)` pair.

    ## Test

    - Two distinct pairs are queued
    - `_pending_deploys` contains both, in the order they were queued

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator._queue_deploy()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    instance._queue_deploy("loopback10", "FDO12345ABC")
    instance._queue_deploy("loopback20", "FDO12345ABD")

    assert instance._pending_deploys == [
        ("loopback10", "FDO12345ABC"),
        ("loopback20", "FDO12345ABD"),
    ]


def test_base_interface_00510() -> None:
    """
    # Summary

    Verify `_queue_deploy` de-duplicates identical pairs (idempotent across repeated queueing).

    ## Test

    - Same pair queued three times
    - `_pending_deploys` contains exactly one entry

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator._queue_deploy()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    instance._queue_deploy("loopback10", "FDO12345ABC")
    instance._queue_deploy("loopback10", "FDO12345ABC")
    instance._queue_deploy("loopback10", "FDO12345ABC")

    assert instance._pending_deploys == [("loopback10", "FDO12345ABC")]


def test_base_interface_00520() -> None:
    """
    # Summary

    Verify `_queue_remove` appends a new `(interface_name, switch_id)` pair.

    ## Test

    - Two distinct pairs are queued
    - `_pending_removes` contains both, in the order they were queued

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator._queue_remove()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    instance._queue_remove("loopback10", "FDO12345ABC")
    instance._queue_remove("loopback20", "FDO12345ABD")

    assert instance._pending_removes == [
        ("loopback10", "FDO12345ABC"),
        ("loopback20", "FDO12345ABD"),
    ]


def test_base_interface_00530() -> None:
    """
    # Summary

    Verify `_queue_remove` de-duplicates identical pairs.

    ## Test

    - Same pair queued three times
    - `_pending_removes` contains exactly one entry

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator._queue_remove()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    instance._queue_remove("loopback10", "FDO12345ABC")
    instance._queue_remove("loopback10", "FDO12345ABC")
    instance._queue_remove("loopback10", "FDO12345ABC")

    assert instance._pending_removes == [("loopback10", "FDO12345ABC")]


# =============================================================================
# Test: deploy_pending
# =============================================================================


def test_base_interface_00600() -> None:
    """
    # Summary

    Verify `deploy_pending` returns None without making any API call when the queue is empty.

    ## Test

    - Queue is empty
    - `deploy_pending` returns None
    - Response generator is not consumed (no fixture queued)

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.deploy_pending()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.deploy_pending()

    assert result is None


def test_base_interface_00610() -> None:
    """
    # Summary

    Verify `deploy_pending` returns None when `deploy=False`, even if the queue is non-empty.

    ## Test

    - Queue contains one pair
    - `deploy` set to False
    - `deploy_pending` returns None and does NOT clear the queue (semantically, the work is just deferred)

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.deploy_pending()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)
    instance.deploy = False
    instance._queue_deploy("loopback10", "FDO12345ABC")

    with does_not_raise():
        result = instance.deploy_pending()

    assert result is None
    assert instance._pending_deploys == [("loopback10", "FDO12345ABC")]


def test_base_interface_00620() -> None:
    """
    # Summary

    Verify `deploy_pending` POSTs to `interfaceActions/deploy` with the queued pairs and clears the queue on success.

    ## Test

    - `deploy` is enabled (it defaults to False)
    - Two pairs are queued
    - POST is issued to `/api/v1/manage/fabrics/fabric_1/interfaceActions/deploy`
    - Request body is `{"interfaces": [{"interfaceName": ..., "switchId": ...}, ...]}` in queue order
    - On success, `_pending_deploys` is cleared

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.deploy_pending()
    - NDBaseInterfaceOrchestrator._deploy_interfaces()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)
    instance.deploy = True
    instance._queue_deploy("loopback10", "FDO12345ABC")
    instance._queue_deploy("loopback20", "FDO12345ABD")

    with does_not_raise():
        instance.deploy_pending()

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/interfaceActions/deploy"
    assert rest_send.verb == HttpVerbEnum.POST.value
    body = rest_send.committed_payload
    assert body == {
        "interfaces": [
            {"interfaceName": "loopback10", "switchId": "FDO12345ABC"},
            {"interfaceName": "loopback20", "switchId": "FDO12345ABD"},
        ]
    }
    assert instance._pending_deploys == []


def test_base_interface_00630() -> None:
    """
    # Summary

    Verify `deploy_pending` wraps an API failure in `RuntimeError` and does NOT clear the queue.

    ## Test

    - `deploy` is enabled (it defaults to False)
    - One pair queued
    - POST returns 500
    - `RuntimeError` matches `Bulk deploy failed`
    - `_pending_deploys` still contains the original entry (so a retry could pick up where we left off)

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.deploy_pending()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)
    instance.deploy = True
    instance._queue_deploy("loopback10", "FDO12345ABC")

    match = r"Bulk deploy failed"
    with pytest.raises(RuntimeError, match=match):
        instance.deploy_pending()

    assert instance._pending_deploys == [("loopback10", "FDO12345ABC")]


# =============================================================================
# Test: deploy_accepted_mutations
# =============================================================================


def test_base_interface_00640() -> None:
    """
    # Summary

    Verify `deploy_accepted_mutations` deploys only the queued pairs whose mutation was already accepted, excluding pairs still
    present in `_pending_removes` (their removal intent never reached the controller), and removes the deployed pairs from
    `_pending_deploys` while leaving the delete-queued pair and the remove queue untouched.

    ## Test

    - `deploy` is enabled (it defaults to False)
    - Two mutation-backed pairs are queued for deploy; a third pair is queued for BOTH deploy and remove (delete path)
    - POST is issued to `/api/v1/manage/fabrics/fabric_1/interfaceActions/deploy` with only the two mutation-backed pairs
    - The returned list names the two deployed pairs
    - `_pending_deploys` retains only the delete-queued pair; `_pending_removes` is untouched

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.deploy_accepted_mutations()
    - NDBaseInterfaceOrchestrator._deploy_interfaces()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)
    instance.deploy = True
    instance._queue_deploy("loopback10", "FDO12345ABC")
    instance._queue_deploy("loopback20", "FDO12345ABD")
    instance._queue_remove("loopback30", "FDO12345ABC")
    instance._queue_deploy("loopback30", "FDO12345ABC")

    with does_not_raise():
        result = instance.deploy_accepted_mutations()

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/interfaceActions/deploy"
    assert rest_send.verb == HttpVerbEnum.POST.value
    body = rest_send.committed_payload
    assert body == {
        "interfaces": [
            {"interfaceName": "loopback10", "switchId": "FDO12345ABC"},
            {"interfaceName": "loopback20", "switchId": "FDO12345ABD"},
        ]
    }
    assert result == [("loopback10", "FDO12345ABC"), ("loopback20", "FDO12345ABD")]
    assert instance._pending_deploys == [("loopback30", "FDO12345ABC")]
    assert instance._pending_removes == [("loopback30", "FDO12345ABC")]


def test_base_interface_00650() -> None:
    """
    # Summary

    Verify `deploy_accepted_mutations` returns an empty list without any API call when `deploy` is False, even with
    mutation-backed pairs queued. Staged intent is the documented contract for `deploy: false`, so the failure path must not
    deploy either.

    ## Test

    - `deploy` is False (the default)
    - One mutation-backed pair is queued
    - No API call is made (the response generator is never consulted)
    - The returned list is empty and the queue is untouched

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.deploy_accepted_mutations()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)
    instance._queue_deploy("loopback10", "FDO12345ABC")

    with does_not_raise():
        result = instance.deploy_accepted_mutations()

    assert result == []
    assert instance._pending_deploys == [("loopback10", "FDO12345ABC")]


def test_base_interface_00660() -> None:
    """
    # Summary

    Verify `deploy_accepted_mutations` returns an empty list without any API call when every queued deploy pair is also queued
    for removal (delete path only): no removal intent was sent, so there is nothing accepted to finalize.

    ## Test

    - `deploy` is enabled
    - One pair is queued for BOTH deploy and remove
    - No API call is made
    - The returned list is empty and both queues are untouched

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.deploy_accepted_mutations()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)
    instance.deploy = True
    instance._queue_remove("loopback30", "FDO12345ABC")
    instance._queue_deploy("loopback30", "FDO12345ABC")

    with does_not_raise():
        result = instance.deploy_accepted_mutations()

    assert result == []
    assert instance._pending_deploys == [("loopback30", "FDO12345ABC")]
    assert instance._pending_removes == [("loopback30", "FDO12345ABC")]


def test_base_interface_00670() -> None:
    """
    # Summary

    Verify `deploy_accepted_mutations` wraps an API failure in `RuntimeError` matching `Failure-path deploy failed` and does
    NOT clear the queue.

    ## Test

    - `deploy` is enabled
    - One mutation-backed pair is queued
    - POST returns 500
    - `RuntimeError` matches `Failure-path deploy failed`
    - `_pending_deploys` still contains the original entry

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.deploy_accepted_mutations()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)
    instance.deploy = True
    instance._queue_deploy("loopback10", "FDO12345ABC")

    match = r"Failure-path deploy failed"
    with pytest.raises(RuntimeError, match=match):
        instance.deploy_accepted_mutations()

    assert instance._pending_deploys == [("loopback10", "FDO12345ABC")]


# =============================================================================
# Test: remove_pending
# =============================================================================


def test_base_interface_00700() -> None:
    """
    # Summary

    Verify `remove_pending` returns None without making any API call when the queue is empty.

    ## Test

    - Queue is empty
    - `remove_pending` returns None
    - Response generator is not consumed

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.remove_pending()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.remove_pending()

    assert result is None


def test_base_interface_00710() -> None:
    """
    # Summary

    Verify `remove_pending` POSTs to `interfaceActions/remove` with the queued pairs and clears the queue on success.

    ## Test

    - Two pairs are queued
    - POST is issued to `/api/v1/manage/fabrics/fabric_1/interfaceActions/remove`
    - Request body is `{"interfaces": [{"interfaceName": ..., "switchId": ...}, ...]}`
    - On success, `_pending_removes` is cleared

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.remove_pending()
    - NDBaseInterfaceOrchestrator._remove_interfaces()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)
    instance._queue_remove("loopback10", "FDO12345ABC")
    instance._queue_remove("loopback20", "FDO12345ABD")

    with does_not_raise():
        instance.remove_pending()

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/interfaceActions/remove"
    assert rest_send.verb == HttpVerbEnum.POST.value
    body = rest_send.committed_payload
    assert body == {
        "interfaces": [
            {"interfaceName": "loopback10", "switchId": "FDO12345ABC"},
            {"interfaceName": "loopback20", "switchId": "FDO12345ABD"},
        ]
    }
    assert instance._pending_removes == []


def test_base_interface_00720() -> None:
    """
    # Summary

    Verify `remove_pending` wraps an API failure in `RuntimeError` and does NOT clear the queue.

    ## Test

    - One pair queued
    - POST returns 500
    - `RuntimeError` matches `Bulk remove failed`
    - `_pending_removes` still contains the original entry

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.remove_pending()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)
    instance._queue_remove("loopback10", "FDO12345ABC")

    match = r"Bulk remove failed"
    with pytest.raises(RuntimeError, match=match):
        instance.remove_pending()

    assert instance._pending_removes == [("loopback10", "FDO12345ABC")]


# =============================================================================
# Test: validate_switches_capable
# =============================================================================


def test_base_interface_00800() -> None:
    """
    # Summary

    Verify `validate_switches_capable` is a no-op when `interface_type` is `""` (the opted-out base default).

    ## Test

    - `_StubInterfaceOrchestrator` leaves `interface_type` as `""`
    - `validate_switches_capable` returns without resolving switches or raising, even for a non-empty input

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.validate_switches_capable()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.validate_switches_capable([SimpleNamespace(switch_ip="192.168.12.151")])


def test_base_interface_00810() -> None:
    """
    # Summary

    Verify `validate_switches_capable` raises a clear `RuntimeError` when a subclass sets `interface_type` but leaves `interface_mode` empty.

    ## Test

    - `_StubOptedInOrchestrator` sets `interface_type` but inherits the empty `interface_mode`
    - `validate_switches_capable` raises `RuntimeError` naming the class and both ClassVars

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.validate_switches_capable()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubOptedInOrchestrator(rest_send=rest_send)

    match = r"_StubOptedInOrchestrator sets interface_type but not interface_mode"
    with pytest.raises(RuntimeError, match=match):
        instance.validate_switches_capable([SimpleNamespace(switch_ip="192.168.12.151")])


def test_base_interface_00820() -> None:
    """
    # Summary

    Verify `validate_switches_capable` aggregates multiple unresolvable `switch_ip` values into a single `RuntimeError`
    (issue #301), so one typo cannot mask resolution or capability problems on the remaining entries.

    ## Test

    - Switches inventory contains only `192.168.12.151`
    - Three model_instances are passed: the valid IP and two distinct unknown IPs
    - `validate_switches_capable` raises `RuntimeError` naming BOTH unknown IPs in a single message
    - The capability endpoint is NOT contacted (no second fixture consumed)

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.validate_switches_capable()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubCapableOrchestrator(rest_send=rest_send)

    model_instances = [
        SimpleNamespace(switch_ip="192.168.12.151"),
        SimpleNamespace(switch_ip="10.1.1.99"),
        SimpleNamespace(switch_ip="10.1.1.100"),
    ]
    match = r"Cannot resolve switch_ip to switchId in fabric 'fabric_1' for: 10\.1\.1\.100, 10\.1\.1\.99"
    with pytest.raises(RuntimeError, match=match):
        instance.validate_switches_capable(model_instances)


def test_base_interface_00830() -> None:
    """
    # Summary

    Verify `validate_switches_capable` downgrades a capability endpoint failure to a warning in `--check` mode
    (issue #302), so dry-runs stay green when the unpublished `capableSwitches` endpoint is unavailable.

    ## Test

    - `rest_send.check_mode` is True
    - Switches inventory resolves the one target IP to `FDO12345ABC`
    - `capableSwitches` GET returns 404 -> `InterfaceCapabilityPreflight._query_get` raises `RuntimeError`
    - `validate_switches_capable` does NOT raise
    - A warning containing `Capability preflight skipped in check mode` is recorded on the mock module

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.validate_switches_capable()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")
        yield responses_base_interface(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    rest_send.check_mode = True
    instance = _StubCapableOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.validate_switches_capable([SimpleNamespace(switch_ip="192.168.12.151")])

    warnings = rest_send.sender.ansible_module.warnings
    assert len(warnings) == 1
    assert "Capability preflight skipped in check mode" in warnings[0]


def test_base_interface_00840() -> None:
    """
    # Summary

    Verify `validate_switches_capable` downgrades a capability MISMATCH (offending switch) to a warning in `--check`
    mode (issue #302), so dry-runs still surface the information without failing the run.

    ## Test

    - `rest_send.check_mode` is True
    - Switches inventory resolves the target IP to `FDO12345ABC`
    - `capableSwitches` returns 200 with an empty `switches` list -> `validate` raises with offender details
    - `validate_switches_capable` does NOT raise
    - A warning is recorded mentioning the offending `switchId`

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.validate_switches_capable()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")
        yield responses_base_interface(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    rest_send.check_mode = True
    instance = _StubCapableOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.validate_switches_capable([SimpleNamespace(switch_ip="192.168.12.151")])

    warnings = rest_send.sender.ansible_module.warnings
    assert len(warnings) == 1
    assert "Capability preflight skipped in check mode" in warnings[0]
    assert "FDO12345ABC" in warnings[0]


def test_base_interface_00850() -> None:
    """
    # Summary

    Verify `validate_switches_capable` still raises a capability mismatch OUTSIDE `--check` mode (issue #302 regression
    guard): the softening behavior must be gated on `check_mode`.

    ## Test

    - `rest_send.check_mode` is False
    - Switches inventory resolves the target IP
    - `capableSwitches` returns 200 with an empty `switches` list
    - `validate_switches_capable` raises `RuntimeError` naming the offending `switchId`
    - No warning is recorded

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.validate_switches_capable()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")
        yield responses_base_interface(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubCapableOrchestrator(rest_send=rest_send)

    match = r"not capable of hosting interface_type='loopback' mode='managed'"
    with pytest.raises(RuntimeError, match=match):
        instance.validate_switches_capable([SimpleNamespace(switch_ip="192.168.12.151")])

    assert rest_send.sender.ansible_module.warnings == []


def test_base_interface_00860() -> None:
    """
    # Summary

    Verify `preflight` delegates to `validate_switches_capable`. `NDStateMachine` calls `preflight` (the generic
    pre-mutation hook) rather than `validate_switches_capable` directly, so this guards the interface override that
    wires the two together.

    ## Test

    - `rest_send.check_mode` is True
    - Switches inventory resolves the target IP to `FDO12345ABC`
    - `capableSwitches` returns 200 with an empty `switches` list (the target is incapable)
    - `preflight` does NOT raise (check-mode softening, inherited from `validate_switches_capable`)
    - A warning mentioning the offending `switchId` is recorded -> proves `preflight` routed through `validate_switches_capable`

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.preflight()
    - NDBaseInterfaceOrchestrator.validate_switches_capable()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_base_interface(f"{method_name}a")
        yield responses_base_interface(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    rest_send.check_mode = True
    instance = _StubCapableOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.preflight([SimpleNamespace(switch_ip="192.168.12.151")])

    warnings = rest_send.sender.ansible_module.warnings
    assert len(warnings) == 1
    assert "Capability preflight skipped in check mode" in warnings[0]
    assert "FDO12345ABC" in warnings[0]


# =============================================================================
# Test: preflight_create() policy-required-on-create guard (issue #350)
# =============================================================================


def _iface_model(switch_ip: str, interface_name: str, *, policy: bool = True, config_data: bool = True, network_os: bool = True):
    """Build a lightweight stand-in for an interface model instance for `preflight_create` tests.

    `preflight_create` reads `config_data` -> `network_os` -> `policy` via `getattr`, so a `SimpleNamespace`
    faithfully exercises the traversal without coupling these tests to any per-feature Pydantic model. Set
    `config_data=False` for an identifier-only item, or `policy=False` for a `config_data` with no policy.
    """
    if not config_data:
        config_data_obj = None
    else:
        network_os_obj = SimpleNamespace(policy=(SimpleNamespace() if policy else None)) if network_os else None
        config_data_obj = SimpleNamespace(network_os=network_os_obj)
    return SimpleNamespace(switch_ip=switch_ip, interface_name=interface_name, config_data=config_data_obj)


def test_base_interface_00900() -> None:
    """
    # Summary

    Verify `preflight_create` does not raise when every create item carries a policy.

    ## Test

    - Two items each have `config_data.network_os.policy` set
    - `preflight_create` does not raise

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.preflight_create()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    items = [_iface_model("192.168.12.151", "loopback100"), _iface_model("192.168.12.152", "loopback101")]
    with does_not_raise():
        instance.preflight_create(items)


def test_base_interface_00910() -> None:
    """
    # Summary

    Verify `preflight_create` raises `RuntimeError` for a create item with no `config_data` at all, naming the
    offending `switch_ip`, `interface_name`, and the fabric.

    ## Test

    - One item has `config_data` of None (identifier only)
    - `preflight_create` raises `RuntimeError` naming the switch_ip, interface_name, and fabric_1

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.preflight_create()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    match = r"without a policy.*fabric 'fabric_1'.*switch_ip=192\.168\.12\.151, interface_name=loopback100"
    with pytest.raises(RuntimeError, match=match):
        instance.preflight_create([_iface_model("192.168.12.151", "loopback100", config_data=False)])


def test_base_interface_00920() -> None:
    """
    # Summary

    Verify `preflight_create` raises when `config_data` is present but `policy` is None (the `config_data`-without-policy
    case, distinct from no `config_data` at all).

    ## Test

    - One item has `config_data.network_os` present but `policy` is None
    - `preflight_create` raises `RuntimeError` naming the offending interface

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.preflight_create()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    match = r"switch_ip=192\.168\.12\.151, interface_name=Vlan100"
    with pytest.raises(RuntimeError, match=match):
        instance.preflight_create([_iface_model("192.168.12.151", "Vlan100", policy=False)])


def test_base_interface_00930() -> None:
    """
    # Summary

    Verify `preflight_create` aggregates multiple offenders into a single `RuntimeError` naming each.

    ## Test

    - Two items both lack a policy
    - `preflight_create` raises one `RuntimeError` naming both interface_names

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.preflight_create()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    items = [
        _iface_model("192.168.12.151", "loopback100", config_data=False),
        _iface_model("192.168.12.152", "loopback101", policy=False),
    ]
    with pytest.raises(RuntimeError) as exc_info:
        instance.preflight_create(items)
    message = str(exc_info.value)
    assert "interface_name=loopback100" in message
    assert "interface_name=loopback101" in message


def test_base_interface_00940() -> None:
    """
    # Summary

    Verify `preflight_create` names only the policy-less offender and not the valid sibling in a mixed batch.

    ## Test

    - One item has a policy, one does not
    - `preflight_create` raises `RuntimeError` naming the offender only

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.preflight_create()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    items = [
        _iface_model("192.168.12.151", "loopback_ok"),
        _iface_model("192.168.12.152", "loopback_bad", config_data=False),
    ]
    with pytest.raises(RuntimeError) as exc_info:
        instance.preflight_create(items)
    message = str(exc_info.value)
    assert "interface_name=loopback_bad" in message
    assert "loopback_ok" not in message


def test_base_interface_00950() -> None:
    """
    # Summary

    Verify `preflight_create` is a no-op for an empty create set (the common case where a state run produces only updates).

    ## Test

    - `preflight_create([])` does not raise

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.preflight_create()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.preflight_create([])


def test_base_interface_00960() -> None:
    """
    # Summary

    Verify `preflight_create` still raises in `--check` mode. The guard is a deterministic input-validation error with no
    API dependency, so it fails fast in a dry-run rather than downgrading to a warning like the capability preflight.

    ## Test

    - `rest_send.check_mode` is True
    - A policy-less create item still raises `RuntimeError`

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.preflight_create()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    rest_send.check_mode = True
    instance = _StubInterfaceOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=r"without a policy"):
        instance.preflight_create([_iface_model("192.168.12.151", "loopback100", config_data=False)])


def test_base_interface_01000_query_final_state_invalidates_interface_cache(monkeypatch) -> None:
    """Final-state readback must not reuse the initialization-time interface inventory."""

    def responses():
        yield {}

    instance = _StubInterfaceOrchestrator(rest_send=_build_rest_send(ResponseGenerator(responses())))
    instance._switch_interfaces_cache = {"SERIAL1": {"ethernet1/1": {"description": "stale"}}}
    cache_seen_by_query = []

    def query_all(self, model_instance=None, **kwargs):
        cache_seen_by_query.append(dict(self._switch_interfaces_cache))
        return []

    monkeypatch.setattr(_StubInterfaceOrchestrator, "query_all", query_all)
    context = FinalizationContext(state="merged")
    policy = RestRetryPolicy(attempts=2, interval=0)

    assert instance.query_final_state(context, policy) == []
    assert cache_seen_by_query == [{}]
