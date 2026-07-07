# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `VpcInterfaceBaseOrchestrator`.

`VpcInterfaceBaseOrchestrator` is an abstract base shared by every vPC interface module (access, trunk-host, ...).
The concrete per-type orchestrators and models live on the branches stacked above this one, so these tests exercise
the base directly through `_StubVpcOrchestrator` / `_StubVpcInterfaceModel` -- minimal concrete subclasses that
bind `model_class` and `_managed_policy_types` without coupling to any per-feature module.

Coverage (per PR #334 review):
- `_resolve_peer_switch_id`: success, per-instance caching, missing-pair, and missing-`peerSwitchId`.
- `_inject_peer_switch_id`: injection into `configData.networkOS.policy`, and no-op when no policy is present.
- `create` / `update`: `switchId` + `peerSwitchId` injection, endpoint path/verb, deploy queuing, error wrapping.
- `delete`: per-interface DELETE path construction, deploy queuing (no bulk remove), error wrapping.
- `create_bulk`: per-switch grouping with a single peer lookup per primary switch (cache).
- `query_one`: per-interface GET path construction and error wrapping.
- `query_all`: fabric validation, `interfaceType`/`policyType` filtering, `switchIp` enrichment, per-peer dedup,
  and an explicit request-count lock (2 + one GET per switch) for the fabric-wide scan flagged in review.

Uses the file-based `Sender` from `tests/unit/module_utils/sender_file.py` injected into a real `RestSend`.
Responses are read from `tests/unit/module_utils/fixtures/fixture_data/test_vpc_interface_base.json`.
"""

# pylint: disable=disallowed-name
# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-few-public-methods
# pylint: disable=too-many-lines
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

import inspect
from typing import ClassVar, Literal, Type

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDelete,
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_interface_base import VpcInterfaceBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

# =============================================================================
# Stub model + orchestrator: minimal concrete subclasses of the abstract base
# =============================================================================


class _StubVpcPolicyModel(NDNestedModel):
    """Minimal vPC policy block mapping to `configData.networkOS.policy`."""

    policy_type: Literal["accessVpcHost"] = Field(default="accessVpcHost", alias="policyType", frozen=True)
    access_vlan: int | None = Field(default=None, alias="accessVlan")
    peer_switch_id: str | None = Field(default=None, alias="peerSwitchId")


class _StubVpcNetworkOSModel(NDNestedModel):
    """Minimal networkOS container mapping to `configData.networkOS`."""

    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", frozen=True)
    policy: _StubVpcPolicyModel | None = Field(default=None, alias="policy")


class _StubVpcConfigDataModel(NDNestedModel):
    """Minimal config-data container mapping to `configData`."""

    mode: Literal["access"] = Field(default="access", alias="mode", frozen=True)
    network_os: _StubVpcNetworkOSModel = Field(default_factory=_StubVpcNetworkOSModel, alias="networkOS")


class _StubVpcInterfaceModel(NDBaseModel):
    """Minimal vPC interface model: composite identifier, nested config mirroring the ND wire shape."""

    identifiers: ClassVar[list[str] | None] = ["switch_ip", "interface_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "composite"
    payload_exclude_fields: ClassVar[set[str]] = {"switch_ip"}

    switch_ip: str = Field(alias="switchIp")
    interface_name: str = Field(alias="interfaceName")
    interface_type: Literal["vpc"] = Field(default="vpc", alias="interfaceType", frozen=True)
    config_data: _StubVpcConfigDataModel | None = Field(default=None, alias="configData")


class _StubVpcOrchestrator(VpcInterfaceBaseOrchestrator):
    """Concrete subclass binding `model_class` and the managed policy type for the abstract base."""

    model_class: ClassVar[Type[NDBaseModel]] = _StubVpcInterfaceModel

    def _managed_policy_types(self) -> set[str]:
        return {"accessVpcHost"}


# =============================================================================
# Helpers
# =============================================================================


def responses_vpc_base(key: str):
    """Load fixture data for the test_vpc_interface_base.json file."""
    return load_fixture("test_vpc_interface_base")[key]


def _build_rest_send(
    gen_responses: ResponseGenerator,
    fabric_name: str = "fabric_1",
    state: str | None = None,
    config: list[dict] | None = None,
) -> RestSend:
    """Build a `RestSend` wired to the file-based `Sender` and the real `ResponseHandler`.

    `state` and `config` populate `rest_send.params` so `query_all`'s `_switches_to_query` scoping
    (fabric-wide for `overridden`, config-scoped otherwise) and its config-preference dedup can be exercised.
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
) -> _StubVpcOrchestrator:
    """Construct a `_StubVpcOrchestrator` with the file-based `RestSend` injected."""
    rest_send = _build_rest_send(gen_responses, fabric_name=fabric_name, state=state, config=config)
    return _StubVpcOrchestrator(rest_send=rest_send)


def _build_model(
    switch_ip: str = "192.168.1.1",
    interface_name: str = "vpc501",
    include_config: bool = True,
) -> _StubVpcInterfaceModel:
    """Build a minimal `_StubVpcInterfaceModel` instance for CRUD tests."""
    kwargs: dict = {"switch_ip": switch_ip, "interface_name": interface_name}
    if include_config:
        kwargs["config_data"] = _StubVpcConfigDataModel(
            network_os=_StubVpcNetworkOSModel(policy=_StubVpcPolicyModel(access_vlan=100)),
        )
    return _StubVpcInterfaceModel(**kwargs)


# =============================================================================
# Test: ClassVars / endpoint wiring
# =============================================================================


def test_vpc_interface_base_00010() -> None:
    """
    # Summary

    Verify the bulk-support flags: vPC supports bulk create but NOT bulk delete (the `interfaceActions/remove`
    endpoint returns `Invalid Interface` for vPC entries on ND 4.2.1, so delete goes per-interface).

    ## Test

    - `supports_bulk_create` is True
    - `supports_bulk_delete` is False

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator
    """
    assert VpcInterfaceBaseOrchestrator.supports_bulk_create is True
    assert VpcInterfaceBaseOrchestrator.supports_bulk_delete is False


def test_vpc_interface_base_00020() -> None:
    """
    # Summary

    Verify the per-verb endpoint classes are wired to the ND Manage Interfaces endpoints, including the
    per-interface DELETE endpoint added by this PR.

    The `*_endpoint` attributes are Pydantic instance fields (they hold the endpoint *type*), so they are read
    off an instance, not the class.

    ## Test

    - create/update/query_one/query_all endpoints point at the expected `EpManageInterfaces*` classes
    - `delete_endpoint` is the per-interface `EpManageInterfacesDelete`
    - `delete_bulk_endpoint` is None (bulk delete disabled)

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    instance = _build_orchestrator(gen_responses)

    assert instance.create_endpoint is EpManageInterfacesPost
    assert instance.update_endpoint is EpManageInterfacesPut
    assert instance.delete_endpoint is EpManageInterfacesDelete
    assert instance.query_one_endpoint is EpManageInterfacesGet
    assert instance.query_all_endpoint is EpManageInterfacesListGet
    assert instance.delete_bulk_endpoint is None


# =============================================================================
# Test: _managed_policy_types
# =============================================================================


def test_vpc_interface_base_00100() -> None:
    """
    # Summary

    Verify the abstract base raises `NotImplementedError` for `_managed_policy_types` and the concrete stub overrides it.

    ## Test

    - Calling `VpcInterfaceBaseOrchestrator._managed_policy_types` (unbound) raises `NotImplementedError`
    - `_StubVpcOrchestrator._managed_policy_types()` returns `{"accessVpcHost"}`

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator._managed_policy_types()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)

    with pytest.raises(NotImplementedError, match=r"Subclasses must implement _managed_policy_types"):
        VpcInterfaceBaseOrchestrator._managed_policy_types(orchestrator)

    assert orchestrator._managed_policy_types() == {"accessVpcHost"}


# =============================================================================
# Test: _resolve_peer_switch_id
# =============================================================================


def test_vpc_interface_base_00200() -> None:
    """
    # Summary

    Verify `_resolve_peer_switch_id` reads the per-switch `vpcPair` endpoint and returns the peer serial.

    ## Test

    - vpcPair GET returns `peerSwitchId: FDO22222BBB`
    - `_resolve_peer_switch_id` returns `"FDO22222BBB"` and caches it under the primary serial

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator._resolve_peer_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    instance = _build_orchestrator(gen_responses)

    with does_not_raise():
        peer = instance._resolve_peer_switch_id("192.168.1.1", "FDO11111AAA")

    assert peer == "FDO22222BBB"
    assert instance._peer_serial_cache == {"FDO11111AAA": "FDO22222BBB"}


def test_vpc_interface_base_00210() -> None:
    """
    # Summary

    Verify `_resolve_peer_switch_id` caches per primary serial: a second call for the same switch does NOT
    issue another `vpcPair` GET (only one response is provided).

    ## Test

    - First call consumes the single vpcPair response and returns the peer
    - Second call returns the cached peer without consuming another response (generator would be exhausted)

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator._resolve_peer_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    instance = _build_orchestrator(gen_responses)

    with does_not_raise():
        first = instance._resolve_peer_switch_id("192.168.1.1", "FDO11111AAA")
        second = instance._resolve_peer_switch_id("192.168.1.1", "FDO11111AAA")

    assert first == "FDO22222BBB"
    assert second == "FDO22222BBB"


def test_vpc_interface_base_00220() -> None:
    """
    # Summary

    Verify `_resolve_peer_switch_id` raises `RuntimeError` when the switch is not in a vPC pair (vpcPair GET 404).

    ## Test

    - vpcPair GET returns 404 (empty body via `not_found_ok`)
    - `RuntimeError` mentions the switch IP, the serial, and points the user at `nd_manage_vpc_pair`
    - Nothing is cached

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator._resolve_peer_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    instance = _build_orchestrator(gen_responses)

    match = r"Switch 192\.168\.1\.1 \(serial FDO11111AAA\) is not in a vPC pair.*nd_manage_vpc_pair"
    with pytest.raises(RuntimeError, match=match):
        instance._resolve_peer_switch_id("192.168.1.1", "FDO11111AAA")

    assert instance._peer_serial_cache == {}


def test_vpc_interface_base_00230() -> None:
    """
    # Summary

    Verify `_resolve_peer_switch_id` raises `RuntimeError` when the vpcPair record omits `peerSwitchId`.

    ## Test

    - vpcPair GET returns 200 but the body has no `peerSwitchId`
    - `RuntimeError` matches `missing 'peerSwitchId'`
    - Nothing is cached

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator._resolve_peer_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    instance = _build_orchestrator(gen_responses)

    match = r"missing 'peerSwitchId'"
    with pytest.raises(RuntimeError, match=match):
        instance._resolve_peer_switch_id("192.168.1.1", "FDO11111AAA")

    assert instance._peer_serial_cache == {}


# =============================================================================
# Test: _inject_peer_switch_id
# =============================================================================


def test_vpc_interface_base_00300() -> None:
    """
    # Summary

    Verify `_inject_peer_switch_id` sets `peerSwitchId` inside `configData.networkOS.policy`.

    ## Test

    - Payload with a nested policy gets `peerSwitchId` injected
    - The same dict object is returned (in-place mutation)

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator._inject_peer_switch_id()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    instance = _build_orchestrator(gen_responses)

    payload = {"configData": {"networkOS": {"policy": {"policyType": "accessVpcHost"}}}}
    result = instance._inject_peer_switch_id(payload, "FDO22222BBB")

    assert result is payload
    assert payload["configData"]["networkOS"]["policy"]["peerSwitchId"] == "FDO22222BBB"


def test_vpc_interface_base_00310() -> None:
    """
    # Summary

    Verify `_inject_peer_switch_id` raises `RuntimeError` when there is no nested `policy` block to inject into. A
    vPC interface always needs a peer serial, so a policy-less payload is structurally invalid and must fail fast
    rather than be silently sent to ND as a one-sided vPC.

    ## Test

    - Payload with no `policy` key raises `RuntimeError` matching `missing the 'configData.networkOS.policy' block`
    - Payload with no `configData` key raises the same `RuntimeError`

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator._inject_peer_switch_id()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    instance = _build_orchestrator(gen_responses)

    match = r"missing the 'configData\.networkOS\.policy' block"

    no_policy: dict = {"configData": {"networkOS": {}}}
    with pytest.raises(RuntimeError, match=match):
        instance._inject_peer_switch_id(no_policy, "FDO22222BBB")

    no_config: dict = {"interfaceName": "vpc501"}
    with pytest.raises(RuntimeError, match=match):
        instance._inject_peer_switch_id(no_config, "FDO22222BBB")


# =============================================================================
# Test: create
# =============================================================================


def test_vpc_interface_base_00400() -> None:
    """
    # Summary

    Verify `create` resolves the switch and peer serials, injects `switchId` and `peerSwitchId`, wraps the payload
    in `{"interfaces": [...]}`, POSTs to the per-switch interfaces URL, and queues a deploy.

    ## Test

    - POST hits `/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces`
    - Request body is `{"interfaces": [ {...} ]}` with one element
    - The element carries `interfaceType: vpc`, `switchId: FDO11111AAA`, no `switchIp`
    - `configData.networkOS.policy.peerSwitchId` is the resolved peer serial
    - `_pending_deploys` contains the single `(interface_name, switch_id)` pair

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.create()
    - VpcInterfaceBaseOrchestrator._resolve_peer_switch_id()
    - VpcInterfaceBaseOrchestrator._inject_peer_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")
        yield responses_vpc_base(f"{method_name}b")
        yield responses_vpc_base(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubVpcOrchestrator(rest_send=rest_send)
    model = _build_model()

    with does_not_raise():
        instance.create(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces"
    assert rest_send.verb == HttpVerbEnum.POST.value
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert len(body["interfaces"]) == 1
    payload_item = body["interfaces"][0]
    assert payload_item["interfaceName"] == "vpc501"
    assert payload_item["interfaceType"] == "vpc"
    assert payload_item["switchId"] == "FDO11111AAA"
    assert "switchIp" not in payload_item
    assert payload_item["configData"]["networkOS"]["policy"]["peerSwitchId"] == "FDO22222BBB"
    assert instance._pending_deploys == [("vpc501", "FDO11111AAA")]


def test_vpc_interface_base_00410() -> None:
    """
    # Summary

    Verify `create` wraps a `_request` failure in `RuntimeError` and queues no deploy.

    ## Test

    - switches-list and vpcPair succeed; POST returns 500
    - `RuntimeError` matches `Create failed for`
    - `_pending_deploys` stays empty

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.create()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")
        yield responses_vpc_base(f"{method_name}b")
        yield responses_vpc_base(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubVpcOrchestrator(rest_send=rest_send)
    model = _build_model()

    with pytest.raises(RuntimeError, match=r"Create failed for"):
        instance.create(model)

    assert instance._pending_deploys == []


def test_vpc_interface_base_00420() -> None:
    """
    # Summary

    Verify `create` surfaces the not-in-a-vPC-pair error (wrapped as `Create failed`) when the primary switch
    has no vpcPair record.

    ## Test

    - switches-list succeeds; vpcPair GET returns 404
    - `RuntimeError` matches `Create failed for .*is not in a vPC pair`
    - No deploy is queued

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.create()
    - VpcInterfaceBaseOrchestrator._resolve_peer_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")
        yield responses_vpc_base(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubVpcOrchestrator(rest_send=rest_send)
    model = _build_model()

    with pytest.raises(RuntimeError, match=r"Create failed for .*is not in a vPC pair"):
        instance.create(model)

    assert instance._pending_deploys == []


# =============================================================================
# Test: update
# =============================================================================


def test_vpc_interface_base_00500() -> None:
    """
    # Summary

    Verify `update` issues a PUT to the per-interface URL, injects `switchId` + `peerSwitchId`, and queues a deploy.

    ## Test

    - PUT hits `/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces/vpc501`
    - Body carries `switchId`, no `switchIp`, and the injected `peerSwitchId`
    - `_pending_deploys` contains the `(vpc501, FDO11111AAA)` pair

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")
        yield responses_vpc_base(f"{method_name}b")
        yield responses_vpc_base(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubVpcOrchestrator(rest_send=rest_send)
    model = _build_model()

    with does_not_raise():
        instance.update(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces/vpc501"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert body["interfaceName"] == "vpc501"
    assert body["switchId"] == "FDO11111AAA"
    assert "switchIp" not in body
    assert body["configData"]["networkOS"]["policy"]["peerSwitchId"] == "FDO22222BBB"
    assert instance._pending_deploys == [("vpc501", "FDO11111AAA")]


def test_vpc_interface_base_00510() -> None:
    """
    # Summary

    Verify `update` wraps a `_request` failure in `RuntimeError` and queues no deploy.

    ## Test

    - switches-list and vpcPair succeed; PUT returns 500
    - `RuntimeError` matches `Update failed for`
    - `_pending_deploys` stays empty

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")
        yield responses_vpc_base(f"{method_name}b")
        yield responses_vpc_base(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubVpcOrchestrator(rest_send=rest_send)
    model = _build_model()

    with pytest.raises(RuntimeError, match=r"Update failed for"):
        instance.update(model)

    assert instance._pending_deploys == []


# =============================================================================
# Test: delete (per-interface DELETE)
# =============================================================================


def test_vpc_interface_base_00600() -> None:
    """
    # Summary

    Verify `delete` issues a per-interface DELETE (not a bulk remove) and queues a deploy.

    ## Test

    - DELETE hits `/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces/vpc501`
    - The DELETE returns 204
    - `_pending_deploys` contains `(vpc501, FDO11111AAA)`; `_pending_removes` stays empty (bulk remove unused)
    - `delete` returns None

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.delete()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")
        yield responses_vpc_base(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubVpcOrchestrator(rest_send=rest_send)
    model = _build_model(include_config=False)

    with does_not_raise():
        result = instance.delete(model)

    assert result is None
    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces/vpc501"
    assert rest_send.verb == HttpVerbEnum.DELETE.value
    assert instance._pending_deploys == [("vpc501", "FDO11111AAA")]
    assert instance._pending_removes == []


def test_vpc_interface_base_00610() -> None:
    """
    # Summary

    Verify `delete` wraps a DELETE failure in `RuntimeError` and queues no deploy.

    ## Test

    - switches-list succeeds; per-interface DELETE returns 500
    - `RuntimeError` matches `Delete failed for`
    - Both queues stay empty

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.delete()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")
        yield responses_vpc_base(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubVpcOrchestrator(rest_send=rest_send)
    model = _build_model(include_config=False)

    with pytest.raises(RuntimeError, match=r"Delete failed for"):
        instance.delete(model)

    assert instance._pending_deploys == []
    assert instance._pending_removes == []


# =============================================================================
# Test: create_bulk (peer lookup cached per primary switch)
# =============================================================================


def test_vpc_interface_base_00700() -> None:
    """
    # Summary

    Verify `create_bulk` groups interfaces by primary switch and resolves the peer serial only ONCE per primary
    switch (cache), issuing a single POST carrying both interfaces.

    ## Test

    - Two vPC interfaces on the same primary switch (192.168.1.1)
    - Only one switches-list, one vpcPair GET, and one POST are consumed (cache prevents a second peer lookup)
    - Both interfaces carry the injected `peerSwitchId`
    - Both `(interface_name, switch_id)` pairs are queued for deploy

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.create_bulk()
    - VpcInterfaceBaseOrchestrator._resolve_peer_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")
        yield responses_vpc_base(f"{method_name}b")
        yield responses_vpc_base(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubVpcOrchestrator(rest_send=rest_send)
    models = [
        _build_model(interface_name="vpc501"),
        _build_model(interface_name="vpc502"),
    ]

    with does_not_raise():
        instance.create_bulk(models)

    # A single vpcPair lookup served both interfaces on the same primary switch.
    assert instance._peer_serial_cache == {"FDO11111AAA": "FDO22222BBB"}
    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces"
    assert rest_send.verb == HttpVerbEnum.POST.value
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert len(body["interfaces"]) == 2
    for item in body["interfaces"]:
        assert item["switchId"] == "FDO11111AAA"
        assert item["configData"]["networkOS"]["policy"]["peerSwitchId"] == "FDO22222BBB"
    assert sorted(instance._pending_deploys) == sorted([("vpc501", "FDO11111AAA"), ("vpc502", "FDO11111AAA")])


def test_vpc_interface_base_00710() -> None:
    """
    # Summary

    Verify `create_bulk` wraps a per-switch `_request` failure in `RuntimeError` matching `Bulk create failed`.

    ## Test

    - switches-list and vpcPair succeed; the per-switch POST returns 500
    - `RuntimeError` matches `Bulk create failed`

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")
        yield responses_vpc_base(f"{method_name}b")
        yield responses_vpc_base(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubVpcOrchestrator(rest_send=rest_send)
    models = [_build_model(interface_name="vpc501")]

    with pytest.raises(RuntimeError, match=r"Bulk create failed"):
        instance.create_bulk(models)


# =============================================================================
# Test: query_one
# =============================================================================


def test_vpc_interface_base_00800() -> None:
    """
    # Summary

    Verify `query_one` issues a GET against the per-interface URL and returns the DATA dict.

    ## Test

    - GET hits `/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces/vpc501`
    - Returned dict carries the vPC interface (`interfaceType: vpc`, `policyType: accessVpcHost`)

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.query_one()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")
        yield responses_vpc_base(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubVpcOrchestrator(rest_send=rest_send)
    model = _build_model(include_config=False)

    with does_not_raise():
        result = instance.query_one(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/switches/FDO11111AAA/interfaces/vpc501"
    assert rest_send.verb == HttpVerbEnum.GET.value
    assert result["interfaceName"] == "vpc501"
    assert result["interfaceType"] == "vpc"
    assert result["configData"]["networkOS"]["policy"]["policyType"] == "accessVpcHost"


def test_vpc_interface_base_00810() -> None:
    """
    # Summary

    Verify `query_one` wraps a `_request` failure in `RuntimeError` mentioning the identifier.

    ## Test

    - switches-list succeeds; GET returns 500
    - `RuntimeError` matches `Query failed for`

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.query_one()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")
        yield responses_vpc_base(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = _StubVpcOrchestrator(rest_send=rest_send)
    model = _build_model(include_config=False)

    with pytest.raises(RuntimeError, match=r"Query failed for"):
        instance.query_one(model)


# =============================================================================
# Test: query_all (fabric-wide scan, filtering, dedup, request count)
# =============================================================================


def test_vpc_interface_base_00900() -> None:
    """
    # Summary

    Verify `query_all` validates the fabric, scans every switch, filters to vPC interfaces with managed policy
    types, injects `switchIp`, de-duplicates the per-peer copies, and -- per PR #334 review -- issues exactly
    one request per switch plus the fabric summary and switches-list (no N+1 beyond the documented per-switch scan).

    ## Test

    - Switch A returns: managed `accessVpcHost` vpc501, other-policy `trunkVpcHost` vpc502, non-vPC ethernet
    - Switch B returns: the peer-side copy of vpc501
    - Result contains exactly vpc501 (vpc502 and the ethernet are filtered out; the peer copy is deduped)
    - The kept entry carries `switchIp` of the lower-`switchId` peer (192.168.1.1 / FDO11111AAA)
    - Request count is exactly 4: summary + switches-list + one interface GET per switch (locks the scan cost)

    `state=overridden` keeps `query_all` fabric-wide so both peers are scanned and the per-peer dedup is exercised.

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.query_all()
    - VpcInterfaceBaseOrchestrator._managed_policy_types()
    """
    method_name = inspect.stack()[0][3]
    calls: list[str] = []

    def responses():
        for suffix in ("a", "b", "c", "d"):
            calls.append(suffix)
            yield responses_vpc_base(f"{method_name}{suffix}")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        instance = _build_orchestrator(gen_responses, state="overridden")
        result = instance.query_all()

    assert isinstance(result, list)
    assert len(result) == 1
    iface = result[0]
    assert iface["interfaceName"] == "vpc501"
    assert iface["switchIp"] == "192.168.1.1"

    by_name = {entry["interfaceName"] for entry in result}
    assert "vpc502" not in by_name  # other-policy vPC filtered out
    assert "Ethernet1/5" not in by_name  # non-vPC filtered out

    # Request-count lock: 1 summary (validate) + 1 switches-list + 1 GET per switch (2 switches) = 4.
    # This pins the fabric-wide scan cost flagged in review so a regression to N+1 fails the test.
    assert len(calls) == 4


def test_vpc_interface_base_00910() -> None:
    """
    # Summary

    Verify `query_all` skips a managed vPC interface that has no `interfaceName` (it cannot be keyed for dedup).

    ## Test

    - The single switch returns one managed `accessVpcHost` vPC interface with no `interfaceName`
    - `query_all` returns `[]` (the nameless entry is skipped, not raised on)

    `state=overridden` keeps `query_all` fabric-wide so the switch is scanned.

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")
        yield responses_vpc_base(f"{method_name}b")
        yield responses_vpc_base(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        instance = _build_orchestrator(gen_responses, state="overridden")
        result = instance.query_all()

    assert result == []


def test_vpc_interface_base_00930() -> None:
    """
    # Summary

    Verify `query_all` raises `RuntimeError` (wrapping the validation failure) when the fabric does not exist.

    ## Test

    - Fabric summary returns 404
    - `query_all` raises `RuntimeError` matching `Query all failed.*missing_fabric`

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    instance = _build_orchestrator(gen_responses, fabric_name="missing_fabric")

    with pytest.raises(RuntimeError, match=r"Query all failed.*missing_fabric"):
        instance.query_all()


def test_vpc_interface_base_00940() -> None:
    """
    # Summary

    Verify `query_all` skips a switch whose interfaces endpoint returns no body (the `not_found_ok` branch) and
    yields an empty list when no managed vPC interfaces are found.

    ## Test

    - Fabric summary and switches-list succeed (one switch)
    - The switch's interfaces endpoint returns 404 (no body)
    - `query_all` returns `[]`

    `state=overridden` keeps `query_all` fabric-wide so the 404 switch is still visited and skipped.

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")
        yield responses_vpc_base(f"{method_name}b")
        yield responses_vpc_base(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        instance = _build_orchestrator(gen_responses, state="overridden")
        result = instance.query_all()

    assert result == []


def test_vpc_interface_base_00920() -> None:
    """
    # Summary

    Verify `query_all` scopes its per-switch interface-list fan-out to switches named in the user config when
    `state` is not `overridden`, rather than querying every switch in the fabric (CLAUDE.md performance rule).

    ## Test

    - Fabric has two switches (192.168.1.1, 192.168.1.2), but config names only 192.168.1.1
    - state is `merged` (non-overridden), so `_switches_to_query` returns only the config switch
    - Only the config switch's interfaces are fetched; the second switch is never queried (the response generator
      yields exactly three responses — summary, switch list, switch-1 interfaces — and would raise if a second
      per-switch GET were issued)
    - Result contains only the `accessVpcHost` vPC on the config switch, stamped with the config `switchIp`

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator._switches_to_query()
    - VpcInterfaceBaseOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_vpc_base(f"{method_name}a")
        yield responses_vpc_base(f"{method_name}b")
        yield responses_vpc_base(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())

    config = [{"switch_ip": "192.168.1.1", "interface_name": "vpc501"}]

    with does_not_raise():
        instance = _build_orchestrator(gen_responses, state="merged", config=config)
        result = instance.query_all()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["interfaceName"] == "vpc501"
    assert result[0]["switchIp"] == "192.168.1.1"


def test_vpc_interface_base_00950() -> None:
    """
    # Summary

    Verify the per-peer dedup keeps the peer whose `switchIp` the user actually configured, so idempotency holds
    even when the user names the HIGHER-`switchId` peer. A vPC is returned on both peers; without this preference
    the dedup would canonicalize to the lower-`switchId` peer (192.168.1.1) and the existing-state identifier would
    never match a config naming 192.168.1.2, churning a spurious delete + recreate under `overridden`.

    ## Test

    - `state=overridden` so both peers are scanned (192.168.1.1 / FDO11111AAA and 192.168.1.2 / FDO22222BBB)
    - Config names vpc501 on the higher-`switchId` peer 192.168.1.2
    - The deduped entry carries `switchIp` 192.168.1.2 (the configured peer), not the lower-`switchId` default

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.query_all()
    - VpcInterfaceBaseOrchestrator._prefers_candidate()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        for suffix in ("a", "b", "c", "d"):
            yield responses_vpc_base(f"{method_name}{suffix}")

    gen_responses = ResponseGenerator(responses())

    config = [{"switch_ip": "192.168.1.2", "interface_name": "vpc501"}]

    with does_not_raise():
        instance = _build_orchestrator(gen_responses, state="overridden", config=config)
        result = instance.query_all()

    assert len(result) == 1
    assert result[0]["interfaceName"] == "vpc501"
    assert result[0]["switchIp"] == "192.168.1.2"


def test_vpc_interface_base_00960() -> None:
    """
    # Summary

    Verify `query_all` tolerates malformed per-switch bodies without aborting the whole run: a `configData: null`
    interface is filtered out via the null-safe policy-type accessor, and a non-dict interfaces body is skipped via
    the `isinstance(result, dict)` guard. Neither raises `AttributeError`.

    ## Test

    - `state=overridden` so both switches are scanned
    - Switch A returns a vPC interface with `configData: null` (policy type resolves to None → filtered out)
    - Switch B returns a bare list as its DATA body (non-dict → skipped by the isinstance guard)
    - `query_all` returns `[]` rather than raising

    ## Classes and Methods

    - VpcInterfaceBaseOrchestrator.query_all()
    - VpcInterfaceBaseOrchestrator._policy_type()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        for suffix in ("a", "b", "c", "d"):
            yield responses_vpc_base(f"{method_name}{suffix}")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        instance = _build_orchestrator(gen_responses, state="overridden")
        result = instance.query_all()

    assert result == []
