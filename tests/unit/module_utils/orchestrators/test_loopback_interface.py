# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `LoopbackInterfaceOrchestrator`.

Verifies that the orchestrator drives `RestSend` correctly for loopback CRUD operations,
injects `switchId` into payloads, wraps create payloads in the `interfaces` array, defers
deploys for bulk execution, and filters `query_all` results to user-managed loopbacks only
(`interfaceType: loopback` AND `policyType: loopback`).

Scope: methods defined in `loopback_interface.py` only. Inherited `deploy_pending` and
`remove_pending` belong in a separate `test_base_interface.py`.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,too-many-lines
# pylint: disable=assignment-from-no-return,use-implicit-booleaness-not-comparison

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import inspect
from types import SimpleNamespace

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import (
    LoopbackConfigDataModel,
    LoopbackInterfaceModel,
    LoopbackNetworkOSModel,
    LoopbackPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.loopback_interface import LoopbackInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_loopback_interface(key: str):
    """Load fixture data for test_loopback_interface tests."""
    return load_fixture("test_loopback_interface")[key]


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


def _build_loopback_model(
    switch_ip: str = "192.168.12.151",
    interface_name: str = "loopback10",
    include_config: bool = True,
) -> LoopbackInterfaceModel:
    """Build a minimal `LoopbackInterfaceModel` instance for tests."""
    kwargs: dict = {"switch_ip": switch_ip, "interface_name": interface_name}
    if include_config:
        kwargs["config_data"] = LoopbackConfigDataModel(
            network_os=LoopbackNetworkOSModel(
                policy=LoopbackPolicyModel(admin_state=True, ip="10.1.1.1/32"),
            ),
        )
    return LoopbackInterfaceModel(**kwargs)


# =============================================================================
# Test: initialization
# =============================================================================


def test_loopback_interface_00010() -> None:
    """
    # Summary

    Verify `LoopbackInterfaceOrchestrator` instantiates without HTTP and exposes the expected ClassVars and empty queues.

    ## Test

    - `model_class` is `LoopbackInterfaceModel`
    - `supports_bulk_create` and `supports_bulk_delete` are True
    - `_pending_deploys` and `_pending_removes` start empty
    - `deploy` defaults to True

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.__init__()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    assert instance.model_class is LoopbackInterfaceModel
    assert instance.supports_bulk_create is True
    assert instance.supports_bulk_delete is True
    assert instance._pending_deploys == []
    assert instance._pending_removes == []
    assert instance.deploy is True


def test_loopback_interface_00020() -> None:
    """
    # Summary

    Verify `fabric_name` is read from `rest_send.params`.

    ## Test

    - Orchestrator is constructed with a `RestSend` whose params include `fabric_name: fabric_1`
    - `instance.fabric_name` returns `"fabric_1"`

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.fabric_name (inherited, but exercised through this subclass)
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    assert instance.fabric_name == "fabric_1"


# =============================================================================
# Test: create
# =============================================================================


def test_loopback_interface_00100() -> None:
    """
    # Summary

    Verify `create` resolves the switch IP, wraps the payload in `{"interfaces": [...]}`, injects `switchId`, and queues a deploy.

    ## Test

    - First call to `_resolve_switch_id` triggers switches-list fetch
    - POST is issued against `/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces`
    - Request body is `{"interfaces": [{...payload..., "switchId": "FDO12345ABC"}]}`
    - `_pending_deploys` contains a single `(interface_name, switch_id)` pair

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create()
    - NDBaseInterfaceOrchestrator._resolve_switch_id()
    - NDBaseInterfaceOrchestrator._queue_deploy()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    model = _build_loopback_model()

    with does_not_raise():
        instance.create(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces"
    assert rest_send.verb == HttpVerbEnum.POST.value
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert "interfaces" in body
    assert len(body["interfaces"]) == 1
    payload_item = body["interfaces"][0]
    assert payload_item["interfaceName"] == "loopback10"
    assert payload_item["interfaceType"] == "loopback"
    assert payload_item["switchId"] == "FDO12345ABC"
    assert "switchIp" not in payload_item
    assert instance._pending_deploys == [("loopback10", "FDO12345ABC")]


def test_loopback_interface_00110() -> None:
    """
    # Summary

    Verify `create` wraps a `_request` failure in `RuntimeError` mentioning the identifier.

    ## Test

    - switches-list returns 200
    - POST returns 500
    - `RuntimeError` is raised; message matches `Create failed for .*loopback10`
    - No deploy is queued

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    model = _build_loopback_model()

    match = r"Create failed for .*loopback10"
    with pytest.raises(RuntimeError, match=match):
        instance.create(model)

    assert instance._pending_deploys == []


def test_loopback_interface_00120() -> None:
    """
    # Summary

    Verify `create` wraps an unknown-switch-IP `RuntimeError` raised by `_resolve_switch_id`.

    Capability preflight now runs centrally in `NDStateMachine` (not inside `create`), so an unresolvable
    `switch_ip` reaching `create` directly surfaces the raw `_resolve_switch_id` failure, wrapped by `create`.

    ## Test

    - switches-list returns a different IP than the model's `switch_ip`
    - `_resolve_switch_id` raises; `create` re-raises as `RuntimeError` matching `Create failed for .*loopback10`

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create()
    - NDBaseInterfaceOrchestrator._resolve_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    model = _build_loopback_model(switch_ip="192.168.12.151")

    match = r"Create failed for .*loopback10.*No switch found with fabricManagementIp '192\.168\.12\.151'"
    with pytest.raises(RuntimeError, match=match):
        instance.create(model)

    assert instance._pending_deploys == []


# =============================================================================
# Test: update
# =============================================================================


def test_loopback_interface_00200() -> None:
    """
    # Summary

    Verify `update` issues a PUT against the per-interface URL, injects `switchId` into the payload, and queues a deploy.

    ## Test

    - switches-list is fetched on first switch_id resolution
    - PUT is issued against `/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces/loopback10`
    - `switchId` is present in the payload
    - `_pending_deploys` contains the `(loopback10, FDO12345ABC)` pair

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    model = _build_loopback_model()

    with does_not_raise():
        instance.update(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces/loopback10"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert body["interfaceName"] == "loopback10"
    assert body["switchId"] == "FDO12345ABC"
    assert "switchIp" not in body
    assert instance._pending_deploys == [("loopback10", "FDO12345ABC")]


def test_loopback_interface_00210() -> None:
    """
    # Summary

    Verify `update` wraps a `_request` failure in `RuntimeError` mentioning the identifier.

    ## Test

    - PUT returns 500
    - `RuntimeError` matches `Update failed for .*loopback10`
    - No deploy is queued

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    model = _build_loopback_model()

    match = r"Update failed for .*loopback10"
    with pytest.raises(RuntimeError, match=match):
        instance.update(model)

    assert instance._pending_deploys == []


# =============================================================================
# Test: delete
# =============================================================================


def test_loopback_interface_00300() -> None:
    """
    # Summary

    Verify `delete` queues a remove + deploy without making any API call beyond the switches-list fetch.

    ## Test

    - Only the switches-list response is consumed (one HTTP call to resolve switch_id)
    - `_pending_removes` contains `(loopback10, FDO12345ABC)`
    - `_pending_deploys` contains `(loopback10, FDO12345ABC)`
    - `delete` returns None

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.delete()
    - NDBaseInterfaceOrchestrator._queue_remove()
    - NDBaseInterfaceOrchestrator._queue_deploy()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    model = _build_loopback_model(include_config=False)

    with does_not_raise():
        result = instance.delete(model)

    assert result is None
    assert instance._pending_removes == [("loopback10", "FDO12345ABC")]
    assert instance._pending_deploys == [("loopback10", "FDO12345ABC")]


def test_loopback_interface_00310() -> None:
    """
    # Summary

    Verify `delete` propagates the raw `RuntimeError` from `_resolve_switch_id` when the IP is unknown.

    Unlike `create`/`update`, `delete` does not wrap exceptions, so the underlying `No switch found with fabricManagementIp ...`
    message surfaces directly.

    ## Test

    - switches-list returns a different IP
    - `RuntimeError` matches `No switch found with fabricManagementIp '192\\.168\\.12\\.151'`
    - No queues are populated

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.delete()
    - NDBaseInterfaceOrchestrator._resolve_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    model = _build_loopback_model(switch_ip="192.168.12.151", include_config=False)

    match = r"No switch found with fabricManagementIp '192\.168\.12\.151'"
    with pytest.raises(RuntimeError, match=match):
        instance.delete(model)

    assert instance._pending_removes == []
    assert instance._pending_deploys == []


# =============================================================================
# Test: create_bulk
# =============================================================================


def test_loopback_interface_00400() -> None:
    """
    # Summary

    Verify `create_bulk` groups interfaces by switch and issues one POST per switch with the per-switch subset wrapped in `{"interfaces": [...]}`.

    ## Test

    - Three interfaces split across two switches: loopback10/loopback11 on switch A, loopback20 on switch B
    - Two POSTs are issued (one per switch)
    - All three pairs are queued in `_pending_deploys`

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")
        yield responses_loopback_interface(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    models = [
        _build_loopback_model(switch_ip="192.168.12.151", interface_name="loopback10"),
        _build_loopback_model(switch_ip="192.168.12.151", interface_name="loopback11"),
        _build_loopback_model(switch_ip="192.168.12.152", interface_name="loopback20"),
    ]

    with does_not_raise():
        instance.create_bulk(models)

    # Both POSTs ran (response generator would StopIteration otherwise).
    # Last call's state is captured on rest_send.
    assert rest_send.path in (
        "/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces",
        "/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABD/interfaces",
    )
    assert rest_send.verb == HttpVerbEnum.POST.value
    assert sorted(instance._pending_deploys) == sorted(
        [
            ("loopback10", "FDO12345ABC"),
            ("loopback11", "FDO12345ABC"),
            ("loopback20", "FDO12345ABD"),
        ]
    )


def test_loopback_interface_00410() -> None:
    """
    # Summary

    Verify `create_bulk` wraps a per-switch `_request` failure in `RuntimeError` matching `Bulk create failed`.

    ## Test

    - switches-list succeeds
    - First per-switch POST succeeds, second returns 500
    - `RuntimeError` matches `Bulk create failed`

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")
        yield responses_loopback_interface(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    models = [
        _build_loopback_model(switch_ip="192.168.12.151", interface_name="loopback10"),
        _build_loopback_model(switch_ip="192.168.12.152", interface_name="loopback20"),
    ]

    match = r"Bulk create failed"
    with pytest.raises(RuntimeError, match=match):
        instance.create_bulk(models)


def test_loopback_interface_00420() -> None:
    """
    # Summary

    Verify `create_bulk` works with a single interface on a single switch (degenerate case).

    ## Test

    - One interface on switch A
    - One POST is issued
    - `_pending_deploys` contains a single pair

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    models = [_build_loopback_model(interface_name="loopback10")]

    with does_not_raise():
        instance.create_bulk(models)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces"
    assert instance._pending_deploys == [("loopback10", "FDO12345ABC")]


# =============================================================================
# Test: delete_bulk
# =============================================================================


def test_loopback_interface_00500() -> None:
    """
    # Summary

    Verify `delete_bulk` queues remove + deploy entries for each instance without issuing any API call beyond the switches-list fetch.

    ## Test

    - Two interfaces on two switches
    - Only switches-list response is consumed
    - `_pending_removes` and `_pending_deploys` each contain both pairs
    - `delete_bulk` returns None

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.delete_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    models = [
        _build_loopback_model(
            switch_ip="192.168.12.151",
            interface_name="loopback10",
            include_config=False,
        ),
        _build_loopback_model(
            switch_ip="192.168.12.152",
            interface_name="loopback20",
            include_config=False,
        ),
    ]

    with does_not_raise():
        result = instance.delete_bulk(models)

    assert result is None
    expected = [("loopback10", "FDO12345ABC"), ("loopback20", "FDO12345ABD")]
    assert sorted(instance._pending_removes) == sorted(expected)
    assert sorted(instance._pending_deploys) == sorted(expected)


# =============================================================================
# Test: query_one
# =============================================================================


def test_loopback_interface_00600() -> None:
    """
    # Summary

    Verify `query_one` issues a GET against the per-interface URL and returns the DATA dict.

    ## Test

    - switches-list fetched on first switch_id resolution
    - GET hits `/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces/loopback10`
    - Returned DATA matches the fixture

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.query_one()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    model = _build_loopback_model(include_config=False)

    with does_not_raise():
        result = instance.query_one(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces/loopback10"
    assert rest_send.verb == HttpVerbEnum.GET.value
    assert result["interfaceName"] == "loopback10"
    assert result["interfaceType"] == "loopback"
    assert result["configData"]["networkOS"]["policy"]["policyType"] == "loopback"


def test_loopback_interface_00610() -> None:
    """
    # Summary

    Verify `query_one` wraps a `_request` failure in `RuntimeError` mentioning the identifier.

    ## Test

    - switches-list succeeds, GET returns 500
    - `RuntimeError` matches `Query failed for .*loopback10`

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.query_one()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    model = _build_loopback_model(include_config=False)

    match = r"Query failed for .*loopback10"
    with pytest.raises(RuntimeError, match=match):
        instance.query_one(model)


# =============================================================================
# Test: query_all
# =============================================================================


def test_loopback_interface_00700() -> None:
    """
    # Summary

    Verify `query_all` validates prerequisites, iterates all switches in the fabric (`state: overridden` is fabric-wide
    per `_switches_to_query`), filters interfaces to `policyType: loopback`, and enriches each result with `switchIp`.

    ## Test

    - state is `overridden`, so `_switches_to_query` returns the full switch map
    - Fabric summary fetched once (validate_prerequisites)
    - Switches-list fetched once (switch_map)
    - Per-switch interfaces fetched (two switches in fixture)
    - Result contains only the user-managed loopback from each switch (system underlayLoopback and ethernet entries are filtered out)
    - Each result item has `switchIp` set to the source switch's IP

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.query_all()
    - NDBaseInterfaceOrchestrator._switches_to_query()
    - NDBaseInterfaceOrchestrator.validate_prerequisites()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")
        yield responses_loopback_interface(f"{method_name}c")
        yield responses_loopback_interface(f"{method_name}d")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, state="overridden")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert isinstance(result, list)
    assert len(result) == 2
    by_name = {item["interfaceName"]: item for item in result}
    assert by_name["loopback10"]["switchIp"] == "192.168.12.151"
    assert by_name["loopback20"]["switchIp"] == "192.168.12.152"
    # Filter verification: no underlayLoopback, no ethernet
    assert all(item["interfaceType"] == "loopback" for item in result)
    assert all(item["configData"]["networkOS"]["policy"]["policyType"] == "loopback" for item in result)


def test_loopback_interface_00710() -> None:
    """
    # Summary

    Verify `query_all` excludes interfaces whose `interfaceType` is not `loopback`.

    ## Test

    - state is `overridden`, so the switch's interfaces are fetched (fabric-wide scope)
    - Switch's interfaces list contains only ethernet entries
    - `query_all` returns an empty list

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")
        yield responses_loopback_interface(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, state="overridden")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert result == []


def test_loopback_interface_00720() -> None:
    """
    # Summary

    Verify `query_all` excludes loopback interfaces whose `policyType` is not `loopback` (e.g. `underlayLoopback`).

    ## Test

    - state is `overridden`, so the switch's interfaces are fetched (fabric-wide scope)
    - Switch's interfaces list contains only `policyType: underlayLoopback` entries (Loopback0/Loopback1 system loopbacks)
    - `query_all` returns an empty list

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")
        yield responses_loopback_interface(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, state="overridden")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert result == []


def test_loopback_interface_00730() -> None:
    """
    # Summary

    Verify `query_all` surfaces a `RuntimeError` (wrapped as `Query all failed: ...`) when the fabric is in deployment freeze mode.

    ## Test

    - Fabric summary returns `fabricStatus: frozen`
    - `query_all` raises `RuntimeError` with `Query all failed.*deployment freeze`
    - No per-switch fetches occur (the response generator is only seeded with the summary response)

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.query_all()
    - NDBaseInterfaceOrchestrator.validate_prerequisites()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    match = r"Query all failed.*deployment freeze"
    with pytest.raises(RuntimeError, match=match):
        instance.query_all()


def test_loopback_interface_00740() -> None:
    """
    # Summary

    Verify `query_all` returns an empty list when the fabric has no switches.

    ## Test

    - Fabric summary returns valid (local, default)
    - Switches list returns no switches
    - `query_all` returns []
    - No per-switch interface fetches occur

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert result == []


def test_loopback_interface_00750() -> None:
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
    - Result contains only the user-managed loopback on the config switch

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator._switches_to_query()
    - LoopbackInterfaceOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")
        yield responses_loopback_interface(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())

    config = [{"switch_ip": "192.168.12.151", "interface_name": "loopback10"}]

    with does_not_raise():
        rest_send = _build_rest_send(gen_responses, state="merged", config=config)
        instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
        result = instance.query_all()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["interfaceName"] == "loopback10"
    assert result[0]["switchIp"] == "192.168.12.151"


@pytest.mark.parametrize(
    ("filters", "expected"),
    [
        (
            [],
            {
                "192.0.2.10": (
                    "SERIAL-A",
                    {"interfaceType:loopback AND policyType:loopback"},
                ),
                "192.0.2.11": (
                    "SERIAL-B",
                    {"interfaceType:loopback AND policyType:loopback"},
                ),
            },
        ),
        (
            [{"switch_ip": "192.0.2.10"}],
            {
                "192.0.2.10": (
                    "SERIAL-A",
                    {"interfaceType:loopback AND policyType:loopback"},
                )
            },
        ),
        (
            [{"interface_name": "loopback101"}],
            {
                "192.0.2.10": (
                    "SERIAL-A",
                    {"interfaceType:loopback AND policyType:loopback AND interfaceName:loopback101"},
                ),
                "192.0.2.11": (
                    "SERIAL-B",
                    {"interfaceType:loopback AND policyType:loopback AND interfaceName:loopback101"},
                ),
            },
        ),
        (
            [{"switch_ip": "192.0.2.10", "interface_name": "loopback101"}],
            {
                "192.0.2.10": (
                    "SERIAL-A",
                    {"interfaceType:loopback AND policyType:loopback AND interfaceName:loopback101"},
                )
            },
        ),
        (
            [{"switch_ip": "192.0.2.10"}, {"interface_name": "loopback101"}],
            {
                # The broad switch filter supersedes the narrower name query.
                "192.0.2.10": (
                    "SERIAL-A",
                    {"interfaceType:loopback AND policyType:loopback"},
                ),
                "192.0.2.11": (
                    "SERIAL-B",
                    {"interfaceType:loopback AND policyType:loopback AND interfaceName:loopback101"},
                ),
            },
        ),
        (
            [{"config_data": {"network_os": {"policy": {"description": "local-only"}}}}],
            {
                "192.0.2.10": (
                    "SERIAL-A",
                    {"interfaceType:loopback AND policyType:loopback"},
                ),
                "192.0.2.11": (
                    "SERIAL-B",
                    {"interfaceType:loopback AND policyType:loopback"},
                ),
            },
        ),
    ],
)
def test_loopback_interface_00760(filters, expected) -> None:
    """Verify gathered query planning routes switches and builds safe Lucene expressions."""

    def responses():
        yield {}

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    instance._fabric_context = SimpleNamespace(  # pylint: disable=protected-access
        fabric_name="test_fabric",
        switch_map={
            "192.0.2.10": "SERIAL-A",
            "192.0.2.11": "SERIAL-B",
        },
    )

    assert instance._build_gathered_query_plan(filters) == expected


def test_loopback_interface_00765() -> None:
    """Verify unknown switch_ip in a gathered filter raises ValueError."""

    def responses():
        yield {}

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    instance._fabric_context = SimpleNamespace(  # pylint: disable=protected-access
        fabric_name="test_fabric",
        switch_map={
            "192.0.2.10": "SERIAL-A",
            "192.0.2.11": "SERIAL-B",
        },
    )

    with pytest.raises(ValueError, match="does not exist in fabric"):
        instance._build_gathered_query_plan([{"switch_ip": "192.0.2.99", "interface_name": "loopback101"}])


def test_loopback_interface_00767() -> None:
    """Verify total request budget collapses fabric-wide expressions on large fabrics."""

    def responses():
        yield {}

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    large_switch_map = {f"192.0.2.{i}": f"SERIAL-{i}" for i in range(150)}
    instance._fabric_context = SimpleNamespace(
        fabric_name="large_fabric",
        switch_map=large_switch_map,
    )

    filters = [
        {"interface_name": "loopback100"},
        {"interface_name": "loopback101"},
        {"interface_name": "loopback102"},
    ]
    plan = instance._build_gathered_query_plan(filters)

    base = "interfaceType:loopback AND policyType:loopback"
    for switch_ip in large_switch_map:
        assert plan[switch_ip][1] == {base}


def test_loopback_interface_00770(monkeypatch) -> None:
    """Verify an exact gathered filter uses the list endpoint with encoded Lucene parameters."""

    def responses():
        yield {}

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    instance._fabric_context = SimpleNamespace(fabric_name="test_fabric", switch_map={"192.0.2.10": "SERIAL-A"})
    requested_paths = []

    monkeypatch.setattr(LoopbackInterfaceOrchestrator, "validate_prerequisites", lambda self: None)

    def fake_request(self, path, verb, **kwargs):
        requested_paths.append(path)
        return {
            "interfaces": [
                {
                    "interfaceName": "loopback101",
                    "interfaceType": "loopback",
                    "configData": {
                        "networkOS": {
                            "policy": {
                                "policyType": "loopback",
                            }
                        }
                    },
                }
            ],
            "meta": {"counts": {"remaining": 0}},
        }

    monkeypatch.setattr(LoopbackInterfaceOrchestrator, "_request", fake_request)

    assert instance.query_all(gathered_filters=[{"switch_ip": "192.0.2.10", "interface_name": "loopback101"}]) == [
        {
            "switchIp": "192.0.2.10",
            "interfaceName": "loopback101",
            "interfaceType": "loopback",
            "configData": {
                "networkOS": {
                    "policy": {
                        "policyType": "loopback",
                    }
                }
            },
        }
    ]
    path, query = requested_paths[0].split("?", 1)
    assert path == "/api/v1/manage/fabrics/fabric_1/switches/SERIAL-A/interfaces"
    assert set(query.split("&")) == {
        "configOnly=false",
        "filter=interfaceType:loopback%20AND%20policyType:loopback%20AND%20interfaceName:loopback101",
        "max=500",
        "offset=0",
    }


def test_loopback_interface_00780(monkeypatch) -> None:
    """Verify Lucene candidates outside this module's policy scope are still excluded locally."""

    def responses():
        yield {}

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    instance._fabric_context = SimpleNamespace(fabric_name="test_fabric", switch_map={"192.0.2.10": "SERIAL-A"})

    monkeypatch.setattr(LoopbackInterfaceOrchestrator, "validate_prerequisites", lambda self: None)
    monkeypatch.setattr(
        LoopbackInterfaceOrchestrator,
        "_request",
        lambda self, path, verb, **kwargs: {
            "interfaces": [
                {
                    "interfaceName": "loopback0",
                    "interfaceType": "loopback",
                    "configData": {"networkOS": {"policy": {"policyType": "underlayLoopback"}}},
                }
            ],
            "meta": {"counts": {"remaining": 0}},
        },
    )

    assert instance.query_all(gathered_filters=[{"interface_name": "loopback0"}]) == []


def test_loopback_interface_00790(monkeypatch) -> None:
    """Verify responses from separate OR expressions are unioned and deduplicated."""

    def responses():
        yield {}

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    duplicate = {
        "interfaceName": "loopback101",
        "interfaceType": "loopback",
        "configData": {"networkOS": {"policy": {"policyType": "loopback"}}},
    }
    requested_paths = []

    monkeypatch.setattr(LoopbackInterfaceOrchestrator, "validate_prerequisites", lambda self: None)
    monkeypatch.setattr(
        LoopbackInterfaceOrchestrator,
        "_build_gathered_query_plan",
        lambda self, filters: {
            "192.0.2.10": ("SERIAL-A", {"expression-one", "expression-two"}),
        },
    )

    def fake_request(self, path, verb, **kwargs):
        requested_paths.append(path)
        return {"interfaces": [duplicate], "meta": {"counts": {"remaining": 0}}}

    monkeypatch.setattr(LoopbackInterfaceOrchestrator, "_request", fake_request)

    result = instance.query_all(gathered_filters=[{"interface_name": "loopback101"}])

    assert len(requested_paths) == 2
    assert result == [{"switchIp": "192.0.2.10", **duplicate}]


def test_loopback_interface_00795(monkeypatch) -> None:
    """Verify Lucene list pagination advances offsets and collects all pages."""

    def responses():
        yield {}

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    requested_paths = []
    pages = iter(
        [
            {
                "interfaces": [
                    {
                        "interfaceName": "loopback101",
                        "interfaceType": "loopback",
                        "configData": {"networkOS": {"policy": {"policyType": "loopback"}}},
                    }
                ],
                "meta": {"counts": {"remaining": "1"}},
            },
            {
                "interfaces": [
                    {
                        "interfaceName": "loopback102",
                        "interfaceType": "loopback",
                        "configData": {"networkOS": {"policy": {"policyType": "loopback"}}},
                    }
                ],
                "meta": {"counts": {"remaining": 0}},
            },
        ]
    )

    def fake_request(self, path, verb, **kwargs):
        requested_paths.append(path)
        return next(pages)

    monkeypatch.setattr(LoopbackInterfaceOrchestrator, "_request", fake_request)

    result = instance._query_interfaces_with_lucene("SERIAL-A", "interfaceType:loopback")

    assert [item["interfaceName"] for item in result] == ["loopback101", "loopback102"]
    assert "offset=0" in requested_paths[0]
    assert "offset=1" in requested_paths[1]


# =============================================================================
# Test: deploy queue de-duplication
# =============================================================================


def test_loopback_interface_00800() -> None:
    """
    # Summary

    Verify that calling `create` twice for the same `(interface_name, switch_id)` does not queue a duplicate deploy entry.

    ## Test

    - Two consecutive `create` calls with identical model
    - Both POSTs succeed (separately verified by response generator consuming both responses)
    - `_pending_deploys` contains exactly one entry

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create()
    - NDBaseInterfaceOrchestrator._queue_deploy()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")
        yield responses_loopback_interface(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    model = _build_loopback_model()

    with does_not_raise():
        instance.create(model)
        instance.create(model)

    assert instance._pending_deploys == [("loopback10", "FDO12345ABC")]
