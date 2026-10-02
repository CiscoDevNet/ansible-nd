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

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import (
    IpfmLoopbackPolicyModel,
    LoopbackConfigDataModel,
    LoopbackInterfaceModel,
    MplsLoopbackPolicyModel,
    NexusLoopbackNetworkOSModel,
    NexusLoopbackPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import BulkCreateGroupKey, BulkCreateItem
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


def _build_loopback_model(switch_ip: str = "192.168.12.151", interface_name: str = "loopback10", include_config: bool = True) -> LoopbackInterfaceModel:
    """Build a minimal `LoopbackInterfaceModel` instance for tests."""
    kwargs: dict = {"switch_ip": switch_ip, "interface_name": interface_name}
    if include_config:
        kwargs["config_data"] = LoopbackConfigDataModel(
            network_os=NexusLoopbackNetworkOSModel(
                network_os_type="nx-os",
                policy=NexusLoopbackPolicyModel(policy_type="loopback", admin_state=True, ip="10.1.1.1/32"),
            ),
        )
    return LoopbackInterfaceModel(**kwargs)


def _build_mpls_loopback_model(switch_ip: str = "192.168.12.151", interface_name: str = "loopback30") -> LoopbackInterfaceModel:
    """Build a minimal `LoopbackInterfaceModel` instance with an `mplsLoopback` policy, for the two-request create and handoff preflight tests."""
    return LoopbackInterfaceModel(
        switch_ip=switch_ip,
        interface_name=interface_name,
        config_data=LoopbackConfigDataModel(
            network_os=NexusLoopbackNetworkOSModel(
                network_os_type="nx-os",
                policy=MplsLoopbackPolicyModel(policy_type="mplsLoopback", admin_state=True, ip="10.3.3.1/32"),
            ),
        ),
    )


def _build_ipfm_loopback_model(switch_ip: str = "192.168.12.151", interface_name: str = "loopback201") -> LoopbackInterfaceModel:
    """Build a minimal `LoopbackInterfaceModel` instance with an `ipfmLoopback` policy, for policy-type-grouping tests."""
    return LoopbackInterfaceModel(
        switch_ip=switch_ip,
        interface_name=interface_name,
        config_data=LoopbackConfigDataModel(
            network_os=NexusLoopbackNetworkOSModel(
                network_os_type="nx-os",
                policy=IpfmLoopbackPolicyModel(policy_type="ipfmLoopback", admin_state=True, ip="10.2.2.1/32"),
            ),
        ),
    )


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
    - `deploy` defaults to False

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
    assert instance.deploy is False


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


def test_loopback_interface_00130() -> None:
    """
    # Summary

    Verify `create` raises `RuntimeError` when the create response's `DATA.results[]` contains a failed item, even
    though the HTTP-level request itself succeeded (207 multi-status). Lab-verified 2026-07-18: ND can return a
    per-item failure while the top-level status looks benign. The per-item scan lives centrally in
    `NdV1Strategy.is_success` (PR #398), which `_request` consults, so the failure surfaces through `_request`.

    ## Test

    - switches-list succeeds
    - POST returns 207 with a single `results[]` item whose `status` is `"failed"`
    - `RuntimeError` matches `Create failed`
    - No deploy is queued

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create()
    - NdV1Strategy.is_success()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    model = _build_loopback_model()

    match = r"Create failed"
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


def test_loopback_interface_00430() -> None:
    """
    # Summary

    Verify `create_bulk` groups interfaces by `(switch_id, policy_type)`, not by switch alone. ND rejects an
    `interfaces[]` array that mixes `policyType` values in a single bulk create (207 with a single failed item;
    nothing created), even though both interfaces here target the same switch (bug-tracker vault:
    `bulk-interface-create-rejects-mixed-policy-types`).

    ## Test

    - Two interfaces on the SAME switch with DIFFERENT policy types: loopback10 (`policyType: loopback`) and
      loopback30 (`policyType: ipfmLoopback`)
    - TWO POSTs are issued (one per policy-type group), each with a single-item `interfaces` array - proven by
      `rest_send.responses` containing exactly 3 entries (switches-list + 2 POSTs; a combined single POST would
      leave one fixture unconsumed and `rest_send.responses` would have only 2 entries) and by the last committed
      payload containing exactly one interface
    - Both interfaces' deploys are queued

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
        _build_ipfm_loopback_model(switch_ip="192.168.12.151", interface_name="loopback30"),
    ]

    with does_not_raise():
        instance.create_bulk(models)

    assert len(rest_send.responses) == 3
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert len(body["interfaces"]) == 1
    assert sorted(instance._pending_deploys) == sorted(
        [
            ("loopback10", "FDO12345ABC"),
            ("loopback30", "FDO12345ABC"),
        ]
    )


def test_loopback_interface_00440() -> None:
    """
    # Summary

    Verify `create_bulk` raises `RuntimeError` and queues no deploys when the create response's `DATA.results[]`
    contains a failed item, using the real lab-verified (2026-07-18) rejection wire shape: HTTP 207 with a single
    `results[]` item whose `status` is `"failed"` and whose `message` names the mixed-policy-type rejection. Nothing
    is created on the controller side in this scenario, so no deploy may be queued (bug-tracker vault:
    `bulk-interface-create-rejects-mixed-policy-types`, `multi-status-207-status-field-inconsistent`). The per-item
    failure is detected centrally by `NdV1Strategy.is_success` (PR #398) and surfaces through `_request`.

    ## Test

    - switches-list succeeds
    - The single POST returns 207 with `DATA.results == [{"name": "loopback206", "status": "failed", "message":
      "Mixed policy types [iosXeLoopback, csrLoopback] are not allowed in bulk interface creation..."}]`
    - `RuntimeError` matches `Bulk create failed.*Mixed policy types`
    - No deploy is queued

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create_bulk()
    - NdV1Strategy.is_success()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    models = [_build_loopback_model(switch_ip="192.168.12.151", interface_name="loopback206")]

    match = r"Bulk create failed.*Mixed policy types"
    with pytest.raises(RuntimeError, match=match):
        instance.create_bulk(models)

    assert instance._pending_deploys == []


def test_loopback_interface_00450() -> None:
    """
    # Summary

    Two-run convergence for a first-group-success / later-group-failure bulk create (PR #403 review). Run 1: the first
    `(switch, policy_type)` group's POST succeeds and its deploy is queued, the second group's POST fails, and `create_bulk`
    raises — then `deploy_accepted_mutations` (the module's failure-path finalizer) deploys the accepted first group so it is
    not stranded staged-but-undeployed. Run 2 (the retry): the first group's interface is already converged, so only the second
    group is created and deployed via the normal `deploy_pending` path. Across the two runs, both interfaces end up deployed.

    ## Test

    - Run 1: loopback10 (`policyType: loopback`) POST succeeds, loopback30 (`policyType: ipfmLoopback`) POST returns 500
    - `create_bulk` raises `RuntimeError` matching `Bulk create failed`; `_pending_deploys` holds only loopback10
    - `deploy_accepted_mutations` POSTs `interfaceActions/deploy` with only loopback10 and clears it from the queue
    - Run 2 (fresh orchestrator, retry): `create_bulk` for loopback30 alone succeeds; `deploy_pending` deploys loopback30

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create_bulk()
    - NDBaseInterfaceOrchestrator.deploy_accepted_mutations()
    - NDBaseInterfaceOrchestrator.deploy_pending()
    """
    method_name = inspect.stack()[0][3]

    def responses_run1():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")
        yield responses_loopback_interface(f"{method_name}c")
        yield responses_loopback_interface(f"{method_name}d")

    rest_send = _build_rest_send(ResponseGenerator(responses_run1()))
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    instance.deploy = True
    models = [
        _build_loopback_model(switch_ip="192.168.12.151", interface_name="loopback10"),
        _build_ipfm_loopback_model(switch_ip="192.168.12.151", interface_name="loopback30"),
    ]

    match = r"Bulk create failed"
    with pytest.raises(RuntimeError, match=match):
        instance.create_bulk(models)

    assert instance._pending_deploys == [("loopback10", "FDO12345ABC")]

    with does_not_raise():
        deployed = instance.deploy_accepted_mutations()

    assert deployed == [("loopback10", "FDO12345ABC")]
    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/interfaceActions/deploy"
    assert rest_send.committed_payload == {"interfaces": [{"interfaceName": "loopback10", "switchId": "FDO12345ABC"}]}
    assert instance._pending_deploys == []

    def responses_run2():
        yield responses_loopback_interface(f"{method_name}e")
        yield responses_loopback_interface(f"{method_name}f")
        yield responses_loopback_interface(f"{method_name}g")

    rest_send_retry = _build_rest_send(ResponseGenerator(responses_run2()))
    instance_retry = LoopbackInterfaceOrchestrator(rest_send=rest_send_retry)
    instance_retry.deploy = True

    with does_not_raise():
        instance_retry.create_bulk([_build_ipfm_loopback_model(switch_ip="192.168.12.151", interface_name="loopback30")])
        instance_retry.deploy_pending()

    assert rest_send_retry.path == "/api/v1/manage/fabrics/fabric_1/interfaceActions/deploy"
    assert rest_send_retry.committed_payload == {"interfaces": [{"interfaceName": "loopback30", "switchId": "FDO12345ABC"}]}
    assert instance_retry._pending_deploys == []


def test_loopback_interface_00460() -> None:
    """
    # Summary

    Verify the failure-path finalizer with a mixed-result 207 as the failing group: the first group's POST succeeds, the second
    group's POST returns HTTP 207 whose `DATA.results[]` mixes a success item and a failed item, and `create_bulk` raises.
    `deploy_accepted_mutations` then deploys the accepted first group AND the item the failing 207 reported as an exact `success`.

    Within-group recovery was originally not attempted here (PR #403 review). It now follows the rule the ethernet orchestrators
    adopted in the PR #550 review and that `_post_bulk_create_group` shares: an exact `success` item IS on the controller, so stranding
    it staged would hide it from a retry (PR #570 review). Every other status stays unqueued (bug-tracker vault:
    `multi-status-207-status-field-inconsistent`).

    ## Test

    - loopback10 (`policyType: loopback`) POST succeeds
    - The ipfmLoopback group (loopback30, loopback31) POST returns 207: loopback30 `success`, loopback31 failed
    - `create_bulk` raises `RuntimeError` matching `Bulk create failed` and names loopback30 as accepted
    - `_pending_deploys` holds loopback10 and loopback30; loopback31 is never queued
    - `deploy_accepted_mutations` deploys exactly those two

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create_bulk()
    - NDBaseInterfaceOrchestrator._post_bulk_create_group()
    - NDBaseInterfaceOrchestrator.deploy_accepted_mutations()
    - NdV1Strategy.is_success()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")
        yield responses_loopback_interface(f"{method_name}b")
        yield responses_loopback_interface(f"{method_name}c")
        yield responses_loopback_interface(f"{method_name}d")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    instance.deploy = True
    models = [
        _build_loopback_model(switch_ip="192.168.12.151", interface_name="loopback10"),
        _build_ipfm_loopback_model(switch_ip="192.168.12.151", interface_name="loopback30"),
        _build_ipfm_loopback_model(switch_ip="192.168.12.151", interface_name="loopback31"),
    ]

    match = r"Bulk create failed.*accepted \['loopback30'\] from the same request"
    with pytest.raises(RuntimeError, match=match):
        instance.create_bulk(models)

    accepted = [("loopback10", "FDO12345ABC"), ("loopback30", "FDO12345ABC")]
    assert instance._pending_deploys == accepted

    with does_not_raise():
        deployed = instance.deploy_accepted_mutations()

    assert deployed == accepted
    assert rest_send.committed_payload == {"interfaces": [{"interfaceName": name, "switchId": switch_id} for name, switch_id in accepted]}
    assert instance._pending_deploys == []


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
        _build_loopback_model(switch_ip="192.168.12.151", interface_name="loopback10", include_config=False),
        _build_loopback_model(switch_ip="192.168.12.152", interface_name="loopback20", include_config=False),
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


def test_loopback_interface_00760() -> None:
    """
    # Summary

    Verify `query_all` returns interfaces of all three managed policy types (`loopback`, `ipfmLoopback`, `mplsLoopback`)
    and excludes `userDefined` and system-provisioned (`underlayLoopback`) interfaces.

    ## Test

    - state is `overridden`, so the switch's interfaces are fetched (fabric-wide scope)
    - Switch's interfaces list contains `loopback`, `ipfmLoopback`, and `mplsLoopback` entries, plus excluded
      `userDefined` and `underlayLoopback` entries
    - `query_all` returns exactly the three managed-type entries

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

    returned = {item["configData"]["networkOS"]["policy"]["policyType"] for item in result}
    assert returned == {"loopback", "ipfmLoopback", "mplsLoopback"}


def test_loopback_interface_00770() -> None:
    """
    # Summary

    Verify `query_all` unions NX-OS and IOS-XE managed loopback policy types (`LoopbackPolicyTypeEnum` |
    `XeLoopbackPolicyTypeEnum`), keeping XE `iosXeLoopback` and XE `csrLoopback` alongside NX `loopback`, and
    excludes `userDefined`.

    ## Test

    - state is `overridden`, so the switch's interfaces are fetched (fabric-wide scope)
    - Switch's interfaces list contains one NX `loopback`, one XE `iosXeLoopback`, one XE `csrLoopback`
      (wire-verified name, lab probe 2026-07-18), and one `userDefined` entry
    - `query_all` returns exactly the three managed-type entries and excludes `userDefined`
    - Each returned item is enriched with `switchIp` set to the source switch's IP

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

    assert len(result) == 3
    returned_policy_types = {item["configData"]["networkOS"]["policy"]["policyType"] for item in result}
    assert returned_policy_types == {"loopback", "iosXeLoopback", "csrLoopback"}
    assert all(item["switchIp"] == "192.168.12.150" for item in result)


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


# =============================================================================
# Test: bulk_create_groups (hoisted to NDBaseInterfaceOrchestrator, issue #409)
# =============================================================================


def test_loopback_interface_01500() -> None:
    """
    # Summary

    Verify `bulk_create_groups` (hoisted to `NDBaseInterfaceOrchestrator`, issue #409) groups by `(switch_id, policy_type)` using the
    shared `BulkCreateGroupKey` / `BulkCreateItem` types and keeps first-seen group order.

    ## Test

    - Two `loopback` models and one `ipfmLoopback` model on the same switch
    - `bulk_create_groups` returns two groups keyed by `BulkCreateGroupKey`
    - Items carry the interface name and a payload with `switchId` injected

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.bulk_create_groups()
    - NDBaseInterfaceOrchestrator._desired_policy_type()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_loopback_interface(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    models = [
        _build_loopback_model(switch_ip="192.168.12.151", interface_name="loopback200"),
        _build_ipfm_loopback_model(switch_ip="192.168.12.151", interface_name="loopback201"),
        _build_loopback_model(switch_ip="192.168.12.151", interface_name="loopback202"),
    ]

    groups = instance.bulk_create_groups(models)

    keys = list(groups)
    assert keys == [
        BulkCreateGroupKey(switch_id="FDO12345ABC", policy_type="loopback"),
        BulkCreateGroupKey(switch_id="FDO12345ABC", policy_type="ipfmLoopback"),
    ]
    assert [item.interface_name for item in groups[keys[0]]] == ["loopback200", "loopback202"]
    assert groups[keys[1]][0].payload["switchId"] == "FDO12345ABC"
    assert isinstance(groups[keys[1]][0], BulkCreateItem)


# =============================================================================
# Test: mplsLoopback two-request create (issue #595)
# =============================================================================

REMOVE_PATH = "/api/v1/manage/fabrics/fabric_1/interfaceActions/remove"
SWITCH_A = "FDO12345ABC"
SWITCH_B = "FDO12345ABD"


def _remove_body(switch_id: str, *names: str) -> dict:
    """Build the `interfaceActions/remove` body the rollback sends for `names` on `switch_id`."""
    return {"interfaces": [{"interfaceName": name, "switchId": switch_id} for name in names]}


def _mpls_rest_send(method_name: str, suffixes: str, **kwargs) -> RestSend:
    """Build a `RestSend` that replays the fixtures `<method_name><suffix>` for each character of `suffixes`, in order."""

    def responses():
        for suffix in suffixes:
            yield responses_loopback_interface(f"{method_name}{suffix}")

    return _build_rest_send(ResponseGenerator(responses()), **kwargs)


def test_loopback_interface_01000() -> None:
    """
    # Summary

    Verify `create_bulk` creates `mplsLoopback` interfaces in two requests: one placeholder POST for the switch, then one PUT per
    interface, queueing each deploy only after its PUT succeeds.

    ## Test

    - Two `mplsLoopback` models on one switch
    - Requests: switches list, one POST (both placeholders), PUT loopback30, PUT loopback31
    - The last request is the PUT for loopback31 and carries `policyType: mplsLoopback`
    - Both deploys are queued in request order; no remove is queued

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create_bulk()
    - LoopbackInterfaceOrchestrator._create_mpls_loopbacks_on_switch()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abcd")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    models = [_build_mpls_loopback_model(interface_name="loopback30"), _build_mpls_loopback_model(interface_name="loopback31")]

    with does_not_raise():
        instance.create_bulk(models)

    assert rest_send.response_count == 4
    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO12345ABC/interfaces/loopback31"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    assert rest_send.committed_payload["configData"]["networkOS"]["policy"]["policyType"] == "mplsLoopback"
    assert rest_send.committed_payload["switchId"] == SWITCH_A
    assert instance._pending_deploys == [("loopback30", SWITCH_A), ("loopback31", SWITCH_A)]
    assert instance._pending_removes == []


def test_loopback_interface_01010() -> None:
    """
    # Summary

    Verify the placeholder is inert: a plain `loopback` policy with `adminState: false` in the `management` VRF and nothing else, so a
    placeholder that were ever deployed would carry no address and no routing configuration.

    ## Test

    - Build the placeholder for an `mplsLoopback` model that has an `ip`
    - The payload holds only the identity, `policyType: loopback`, `adminState: false` and `vrfInterface: management`; the user's `ip` is
      not copied

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._mpls_placeholder_item()
    """

    def responses():
        yield {}

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    item = instance._mpls_placeholder_item(_build_mpls_loopback_model(interface_name="loopback30"), SWITCH_A)

    assert item.interface_name == "loopback30"
    assert item.payload == {
        "interfaceName": "loopback30",
        "interfaceType": "loopback",
        "switchId": SWITCH_A,
        "configData": {
            "mode": "managed",
            "networkOS": {"networkOSType": "nx-os", "policy": {"policyType": "loopback", "adminState": False, "vrfInterface": "management"}},
        },
    }
    assert rest_send.response_count == 0


def test_loopback_interface_01020() -> None:
    """
    # Summary

    Verify a PUT failure part-way through: the interface already converted keeps its queued deploy, every unconverted placeholder is
    removed in one request, and with `deploy` false the failure-path finalizer sends nothing.

    ## Test

    - Three `mplsLoopback` models; placeholder POST accepts all; PUT loopback30 succeeds; PUT loopback31 returns 500
    - One `interfaceActions/remove` is sent for loopback31 and loopback32
    - `RuntimeError` names the removed placeholders and the converted interface
    - `_pending_deploys` holds only loopback30; `_pending_removes` is empty
    - `deploy_accepted_mutations` returns `[]` and sends no request (`deploy` is false)

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create_bulk()
    - LoopbackInterfaceOrchestrator._roll_back_mpls_placeholders()
    - NDBaseInterfaceOrchestrator.deploy_accepted_mutations()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abcde")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    models = [_build_mpls_loopback_model(interface_name=name) for name in ("loopback30", "loopback31", "loopback32")]

    match = r"Bulk create failed: mplsLoopback create failed on switchId FDO12345ABC: .*"
    match += r"Removed the placeholder loopback\(s\) \['loopback31', 'loopback32'\] created for this request\. "
    match += r"\['loopback30'\] were created as mplsLoopback before the failure; their deploy stays queued\."
    with pytest.raises(RuntimeError, match=match):
        instance.create_bulk(models)

    assert rest_send.path == REMOVE_PATH
    assert rest_send.committed_payload == _remove_body(SWITCH_A, "loopback31", "loopback32")
    assert instance._pending_deploys == [("loopback30", SWITCH_A)]
    assert instance._pending_removes == []
    assert rest_send.response_count == 5

    assert instance.deploy_accepted_mutations() == []
    assert rest_send.response_count == 5


def test_loopback_interface_01030() -> None:
    """
    # Summary

    Verify a failed rollback is reported, not hidden: the error names the placeholder left behind and tells the user how to remove it.

    ## Test

    - One `mplsLoopback` model; placeholder POST accepted; PUT returns 500; the remove returns 500
    - `RuntimeError` says the placeholder could not be removed and remains staged
    - Nothing is queued for deploy or remove

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._remove_placeholders()
    - LoopbackInterfaceOrchestrator._roll_back_mpls_placeholders()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abcd")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    match = r"Could not remove the placeholder loopback\(s\) \['loopback30'\] \(.*\); they remain staged as plain loopbacks\. "
    match += r"Remove them with state: deleted\."
    with pytest.raises(RuntimeError, match=match):
        instance.create_bulk([_build_mpls_loopback_model(interface_name="loopback30")])

    assert rest_send.committed_payload == _remove_body(SWITCH_A, "loopback30")
    assert instance._pending_deploys == []
    assert instance._pending_removes == []


def test_loopback_interface_01040() -> None:
    """
    # Summary

    Verify a mixed 207 on the rollback is read per item: the error separates the placeholder the controller removed from the one it
    did not.

    ## Test

    - Two `mplsLoopback` models; placeholder POST accepts both; PUT loopback30 returns 500
    - The remove returns 207: loopback30 `success`, loopback31 `failed`
    - `RuntimeError` reports loopback30 as removed and loopback31 as left behind

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._remove_placeholders()
    - NDBaseInterfaceOrchestrator._accepted_multistatus_pairs()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abcd")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    models = [_build_mpls_loopback_model(interface_name="loopback30"), _build_mpls_loopback_model(interface_name="loopback31")]

    match = r"Removed the placeholder loopback\(s\) \['loopback30'\] created for this request\. "
    match += r"Could not remove the placeholder loopback\(s\) \['loopback31'\]"
    with pytest.raises(RuntimeError, match=match):
        instance.create_bulk(models)

    assert instance._pending_deploys == []


def test_loopback_interface_01050() -> None:
    """
    # Summary

    Verify `_remove_placeholders` does not reconcile against a stale response: when the sender raises before any response is recorded,
    `response_current` still holds the previous remove's all-success 207, and that must not be read as this request's result
    (issue #554 freshness requirement).

    ## Test

    - First call removes loopback30; the remove returns an all-success 207; nothing is left behind
    - The sender is set to raise `ValueError` from `commit`
    - Second call for the same name reports loopback30 as left behind and returns the error; still exactly one response was recorded

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._remove_placeholders()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "a")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        left_behind, error = instance._remove_placeholders(SWITCH_A, ["loopback30"])
    assert left_behind == []
    assert error is None
    assert rest_send.return_code == 207

    rest_send.sender.raise_method = "commit"
    rest_send.sender.raise_exception = ValueError("simulated transport failure")

    left_behind, error = instance._remove_placeholders(SWITCH_A, ["loopback30"])

    assert left_behind == ["loopback30"]
    assert isinstance(error, Exception)
    assert rest_send.response_count == 1


def test_loopback_interface_01060() -> None:
    """
    # Summary

    Verify a mixed 207 on the placeholder POST: no PUT is sent, the accepted placeholder is removed, and nothing is queued.

    ## Test

    - Two `mplsLoopback` models; placeholder POST returns 207: loopback30 `success`, loopback31 `failed`
    - Requests: switches list, POST, remove (no PUT)
    - The remove names only loopback30
    - Nothing is queued for deploy

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._create_mpls_loopbacks_on_switch()
    - NDBaseInterfaceOrchestrator._send_bulk_create_group()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abc")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    models = [_build_mpls_loopback_model(interface_name="loopback30"), _build_mpls_loopback_model(interface_name="loopback31")]

    match = r"mplsLoopback create failed on switchId FDO12345ABC: .*Removed the placeholder loopback\(s\) \['loopback30'\]"
    with pytest.raises(RuntimeError, match=match):
        instance.create_bulk(models)

    assert rest_send.response_count == 3
    assert rest_send.committed_payload == _remove_body(SWITCH_A, "loopback30")
    assert instance._pending_deploys == []


def test_loopback_interface_01070() -> None:
    """
    # Summary

    Verify nothing is removed when the placeholder POST created nothing: the rollback may only remove interfaces this request created,
    never an interface that already existed under the same name.

    ## Test

    - Two `mplsLoopback` models; placeholder POST returns 207 with both items `failed`
    - Requests: switches list and the POST only; no remove is sent
    - `RuntimeError` is raised and claims no removed placeholder
    - Nothing is queued

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._create_mpls_loopbacks_on_switch()
    - LoopbackInterfaceOrchestrator._remove_placeholders()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "ab")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    models = [_build_mpls_loopback_model(interface_name="loopback30"), _build_mpls_loopback_model(interface_name="loopback31")]

    with pytest.raises(RuntimeError, match=r"mplsLoopback create failed on switchId FDO12345ABC") as exc_info:
        instance.create_bulk(models)

    assert "Removed the placeholder" not in str(exc_info.value)
    assert "Could not remove" not in str(exc_info.value)
    assert rest_send.response_count == 2
    assert instance._pending_deploys == []
    assert instance._pending_removes == []


def test_loopback_interface_01080() -> None:
    """
    # Summary

    Verify the flat-500 partial commit (ND 4.2.1) is rolled back too: a placeholder the failed POST still created is found by the
    inventory re-read and removed.

    ## Test

    - The switch inventory is cached first (loopback10 only)
    - Two `mplsLoopback` models; placeholder POST returns a flat 500
    - The inventory re-read shows loopback30 now exists and loopback31 does not
    - One remove is sent for loopback30 only

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._create_mpls_loopbacks_on_switch()
    - NDBaseInterfaceOrchestrator._created_despite_failure()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abcde")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    instance._switch_interfaces(SWITCH_A)
    models = [_build_mpls_loopback_model(interface_name="loopback30"), _build_mpls_loopback_model(interface_name="loopback31")]

    match = r"Removed the placeholder loopback\(s\) \['loopback30'\] created for this request\."
    with pytest.raises(RuntimeError, match=match):
        instance.create_bulk(models)

    assert rest_send.committed_payload == _remove_body(SWITCH_A, "loopback30")
    assert instance._pending_deploys == []


def test_loopback_interface_01090() -> None:
    """
    # Summary

    Verify a task mixing plain `loopback` and `mplsLoopback` on one switch still sends one POST per group and handles the plain group
    first.

    ## Test

    - Models in input order: loopback10 (plain), loopback30 (mpls), loopback11 (plain)
    - Requests: switches list, plain POST (loopback10 and loopback11), placeholder POST (loopback30), PUT loopback30
    - Deploy order is loopback10, loopback11, loopback30: the plain group was queued before the mpls conversion finished

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abcd")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    models = [
        _build_loopback_model(interface_name="loopback10"),
        _build_mpls_loopback_model(interface_name="loopback30"),
        _build_loopback_model(interface_name="loopback11"),
    ]

    with does_not_raise():
        instance.create_bulk(models)

    assert rest_send.response_count == 4
    assert instance._pending_deploys == [("loopback10", SWITCH_A), ("loopback11", SWITCH_A), ("loopback30", SWITCH_A)]


def test_loopback_interface_01100() -> None:
    """
    # Summary

    Verify the single-item `create` sends an `mplsLoopback` through the same two-request sequence.

    ## Test

    - `create` is called with one `mplsLoopback` model
    - Requests: switches list, placeholder POST, PUT
    - The deploy is queued once

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abc")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.create(_build_mpls_loopback_model(interface_name="loopback30"))

    assert rest_send.response_count == 3
    assert rest_send.verb == HttpVerbEnum.PUT.value
    assert instance._pending_deploys == [("loopback30", SWITCH_A)]


def test_loopback_interface_01110() -> None:
    """
    # Summary

    Verify a failure on the second switch leaves the first switch alone: its converted interface keeps its queued deploy and the
    rollback names only the second switch.

    ## Test

    - One `mplsLoopback` model per switch (A then B), both named loopback30
    - Switch A: placeholder POST and PUT succeed
    - Switch B: placeholder POST succeeds, PUT returns 500, the remove succeeds
    - The remove body names loopback30 on switch B only
    - `_pending_deploys` holds loopback30 on switch A only

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._create_mpls_loopbacks()
    - LoopbackInterfaceOrchestrator._roll_back_mpls_placeholders()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abcdef")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    models = [
        _build_mpls_loopback_model(switch_ip="192.168.12.151", interface_name="loopback30"),
        _build_mpls_loopback_model(switch_ip="192.168.12.152", interface_name="loopback30"),
    ]

    with pytest.raises(RuntimeError, match=r"mplsLoopback create failed on switchId FDO12345ABD"):
        instance.create_bulk(models)

    assert rest_send.committed_payload == _remove_body(SWITCH_B, "loopback30")
    assert instance._pending_deploys == [("loopback30", SWITCH_A)]


def test_loopback_interface_01120() -> None:
    """
    # Summary

    Verify the failure-path finalizer cannot ship a placeholder: after a failed conversion with `deploy` true it deploys only the
    interface that was converted.

    ## Test

    - Two `mplsLoopback` models; PUT loopback30 succeeds; PUT loopback31 returns 500; loopback31 is removed
    - `deploy_accepted_mutations` sends one `interfaceActions/deploy` naming loopback30 only

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.create_bulk()
    - NDBaseInterfaceOrchestrator.deploy_accepted_mutations()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abcdef")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    instance.deploy = True
    models = [_build_mpls_loopback_model(interface_name="loopback30"), _build_mpls_loopback_model(interface_name="loopback31")]

    with pytest.raises(RuntimeError, match=r"Bulk create failed"):
        instance.create_bulk(models)

    with does_not_raise():
        deployed = instance.deploy_accepted_mutations()

    assert deployed == [("loopback30", SWITCH_A)]
    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/interfaceActions/deploy"
    assert rest_send.committed_payload == {"interfaces": [{"interfaceName": "loopback30", "switchId": SWITCH_A}]}


# =============================================================================
# Test: MPLS Handoff preflight (issue #595)
# =============================================================================

HANDOFF_OFF = (
    r"MPLS Handoff is disabled on fabric 'fabric_1'; mplsLoopback requires it for loopback30 \(192\.168\.12\.151\)\. "
    r"Enable mpls_handoff with the fabric's nd_manage_fabric_\* module and retry\. No changes were made\."
)


def test_loopback_interface_00900() -> None:
    """
    # Summary

    Verify the handoff preflight refuses a new `mplsLoopback` when MPLS Handoff is disabled, in check mode too, naming the interface
    and the fix.

    ## Test

    - Check mode is on
    - loopback30 (`mplsLoopback`) is proposed and absent from the switch inventory
    - Fabric details report `management.mplsHandoff: false`
    - `RuntimeError` names the fabric, the interface, its switch IP, and the owning module

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._check_mpls_handoff()
    - FabricContext.fabric_details
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abc")
    rest_send.check_mode = True
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=HANDOFF_OFF):
        instance._check_mpls_handoff([_build_mpls_loopback_model(interface_name="loopback30")])

    assert rest_send.response_count == 3


def test_loopback_interface_00910() -> None:
    """
    # Summary

    Verify the handoff preflight passes when MPLS Handoff is enabled.

    ## Test

    - loopback30 (`mplsLoopback`) is proposed and absent from the switch inventory
    - Fabric details report `management.mplsHandoff: true`
    - No exception
    - Three requests were sent: switches list, switch inventory, fabric details

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._check_mpls_handoff()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abc")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance._check_mpls_handoff([_build_mpls_loopback_model(interface_name="loopback30")])

    assert rest_send.response_count == 3


def test_loopback_interface_00920() -> None:
    """
    # Summary

    Verify the handoff preflight gives no verdict when the fabric body has no `mplsHandoff` key: with no evidence the check is skipped
    and ND answers the write.

    ## Test

    - loopback30 (`mplsLoopback`) is proposed and absent from the switch inventory
    - Fabric details `management` carries no `mplsHandoff` key
    - No exception
    - Three requests were sent: switches list, switch inventory, fabric details

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._check_mpls_handoff()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abc")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance._check_mpls_handoff([_build_mpls_loopback_model(interface_name="loopback30")])

    assert rest_send.response_count == 3


def test_loopback_interface_00930() -> None:
    """
    # Summary

    Verify the handoff preflight costs no fabric details request when every proposed `mplsLoopback` already is one on the controller.

    ## Test

    - loopback30 (`mplsLoopback`) is proposed and the switch inventory already shows it as `mplsLoopback`
    - Requests: switches list and the switch inventory only (a third request would exhaust the fixtures and fail)
    - No exception

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._check_mpls_handoff()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "ab")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance._check_mpls_handoff([_build_mpls_loopback_model(interface_name="loopback30")])

    assert rest_send.response_count == 2


def test_loopback_interface_00940() -> None:
    """
    # Summary

    Verify the handoff preflight also covers a policy-type transition: an existing plain `loopback` proposed as `mplsLoopback`.

    ## Test

    - loopback30 (`mplsLoopback`) is proposed; the switch inventory shows it as a plain `loopback`
    - Fabric details report `management.mplsHandoff: false`
    - `RuntimeError` names the interface

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._check_mpls_handoff()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abc")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=HANDOFF_OFF):
        instance._check_mpls_handoff([_build_mpls_loopback_model(interface_name="loopback30")])


def test_loopback_interface_00950() -> None:
    """
    # Summary

    Verify the handoff preflight sends nothing when no `mplsLoopback` is proposed.

    ## Test

    - Only a plain `loopback` model and an identifier-only model are proposed
    - No request is sent and no exception is raised

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._check_mpls_handoff()
    """

    def responses():
        yield {}

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)
    models = [_build_loopback_model(interface_name="loopback10"), _build_loopback_model(interface_name="loopback11", include_config=False)]

    with does_not_raise():
        instance._check_mpls_handoff(models)

    assert rest_send.response_count == 0


def test_loopback_interface_00960() -> None:
    """
    # Summary

    Verify `preflight` runs the shared interface preflight and then the handoff check, in check mode, which is how `NDStateMachine`
    reaches it before any mutation.

    ## Test

    - Check mode is on
    - Requests: switches list, capableSwitches (the switch is capable), switch inventory, fabric details (`mplsHandoff: false`)
    - `RuntimeError` is the handoff message, raised only after the capability preflight passed

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator.preflight()
    - NDBaseInterfaceOrchestrator.preflight()
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abcd")
    rest_send.check_mode = True
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=HANDOFF_OFF):
        instance.preflight([_build_mpls_loopback_model(interface_name="loopback30")])

    assert rest_send.response_count == 4


def test_loopback_interface_00970() -> None:
    """
    # Summary

    Verify a failed fabric details request fails the preflight instead of silently skipping the check.

    ## Test

    - loopback30 (`mplsLoopback`) is proposed and absent from the switch inventory
    - The fabric details GET returns 500
    - `RuntimeError` names the failed request

    ## Classes and Methods

    - LoopbackInterfaceOrchestrator._check_mpls_handoff()
    - FabricContext.fabric_details
    """
    method_name = inspect.stack()[0][3]
    rest_send = _mpls_rest_send(method_name, "abc")
    instance = LoopbackInterfaceOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=r"GET /api/v1/manage/fabrics/fabric_1 failed"):
        instance._check_mpls_handoff([_build_mpls_loopback_model(interface_name="loopback30")])
