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
- groups create_bulk by (switch, policyType) through the shared `bulk_create_groups` (issue #409)
- keeps the IOS-XE managed policy types in `query_all` and tolerates the policy-less records a Catalyst switch list carries (issue #541)
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
) -> SubinterfaceManagedInterfaceOrchestrator:
    """Construct an orchestrator with the file-based RestSend injected."""
    rest_send = _build_rest_send(gen_responses, fabric_name=fabric_name, state=state, config=config)
    return SubinterfaceManagedInterfaceOrchestrator(rest_send=rest_send)


def _build_model(
    switch_ip: str = "192.168.1.1", interface_name: str = "Ethernet1/3.2", network_os_type: str = "nx-os", **policy_kwargs
) -> SubinterfaceManagedInterfaceModel:
    """Build a SubinterfaceManagedInterfaceModel with optional policy fields populated."""
    config_data = None
    if policy_kwargs:
        config_data = {"mode": "managed", "network_os": {"network_os_type": network_os_type, "policy": policy_kwargs}}
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
# Test: query_all — happy path with filtering
# =============================================================================


def test_subinterface_managed_orchestrator_00400() -> None:
    """
    # Summary

    Verify `query_all` validates the fabric, iterates all switches (`state: overridden` is fabric-wide per
    `_switches_to_query`), filters to interfaceType=subInterface AND managed policyType=subinterface, and
    injects `switchIp` onto each kept interface.

    ## Test

    - state is `overridden`, so `_switches_to_query` returns the full switch map
    - Fabric summary returns 200
    - Two switches in the switch list
    - Switch 1 returns: managed subinterface (kept), ethernet (filtered by interfaceType),
      unmanaged subinterface with policyType=monitorSubinterface (filtered by policyType)
    - Switch 2 returns: managed subinterface (kept)
    - Result contains exactly two subinterfaces with switchIp injected

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.query_all()
    - NDBaseInterfaceOrchestrator._switches_to_query()
    """

    def responses():
        yield responses_subif("test_query_all_happy_path_00400a")
        yield responses_subif("test_query_all_happy_path_00400b")
        yield responses_subif("test_query_all_happy_path_00400c")
        yield responses_subif("test_query_all_happy_path_00400d")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses, state="overridden")
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


def test_subinterface_managed_orchestrator_00440() -> None:
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
    - Result contains only the managed subinterface on the config switch

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator._switches_to_query()
    - SubinterfaceManagedInterfaceOrchestrator.query_all()
    """

    def responses():
        yield responses_subif("test_query_all_config_scoped_00440a")
        yield responses_subif("test_query_all_config_scoped_00440b")
        yield responses_subif("test_query_all_config_scoped_00440c")

    gen_responses = ResponseGenerator(responses())

    config = [{"switch_ip": "192.168.1.1", "interface_name": "Ethernet1/3.2"}]

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses, state="merged", config=config)
        result = orchestrator.query_all()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["interfaceName"] == "Ethernet1/3.2"
    assert result[0]["switchIp"] == "192.168.1.1"


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
    - NdV1Strategy.is_success()
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

    - Enable `deploy` (it defaults to False) and queue one interface manually
    - Call deploy_pending
    - Queue is empty after success

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.deploy_pending()
    """

    def responses():
        yield responses_subif("test_deploy_pending_happy_path_00820a")

    gen_responses = ResponseGenerator(responses())
    orchestrator = _build_orchestrator(gen_responses)
    orchestrator.deploy = True
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


# =============================================================================
# Test: IOS-XE branch (issue #541) — query_all managed set and create_bulk grouping
# =============================================================================


def test_subinterface_managed_orchestrator_00450() -> None:
    """
    # Summary

    Verify `query_all` keeps both IOS-XE managed policy types (`iosXeSubinterface`, `iosXeSubinterfaceShutNoshut`), filters
    `userDefined` and the ND-internal `iosXeInternalSubinterface`, and tolerates the records a Catalyst switch list carries that the
    NX-OS-only filter never saw: a subinterface whose `policy` is `null` and one with no `configData` at all (shapes per the SVI lab
    capture on ND 4.2.1.10, 2026-09-16).

    ## Test

    - state is `overridden`, one Catalyst switch
    - Result contains exactly `GigabitEthernet1/0/2.100` (iosXeSubinterface) and `GigabitEthernet1/0/2.101`
      (iosXeSubinterfaceShutNoshut) with `switchIp` injected
    - `.102` (userDefined), `.103` (iosXeInternalSubinterface), `.104` (policy null), `.105` (no configData) and the routed parent are
      filtered without raising

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.query_all()
    - SubinterfaceManagedInterfaceOrchestrator._managed_policy_types()
    - SubinterfaceManagedInterfaceOrchestrator._policy_type_of()
    """

    def responses():
        yield responses_subif("test_query_all_xe_00450a")
        yield responses_subif("test_query_all_xe_00450b")
        yield responses_subif("test_query_all_xe_00450c")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses, state="overridden")
        result = orchestrator.query_all()

    by_name = {iface["interfaceName"]: iface for iface in result}
    assert set(by_name) == {"GigabitEthernet1/0/2.100", "GigabitEthernet1/0/2.101"}
    assert by_name["GigabitEthernet1/0/2.100"]["switchIp"] == "192.168.12.181"
    assert by_name["GigabitEthernet1/0/2.101"]["configData"]["networkOS"]["policy"]["policyType"] == "iosXeSubinterfaceShutNoshut"


def test_subinterface_managed_orchestrator_00910() -> None:
    """
    # Summary

    Verify `create_bulk` sends one POST per `(switch, policyType)` group (shared `bulk_create_groups`, issue #409): ND rejects an
    `interfaces[]` array that mixes policy types, which a Catalyst carrying both `iosXeSubinterface` and `iosXeSubinterfaceShutNoshut`
    subinterfaces would otherwise produce.

    ## Test

    - Two IOS-XE subinterfaces of different policy types on the Catalyst and one NX-OS subinterface on a Nexus leaf
    - Three POSTs consumed (switch GET + three create responses) and all three interfaces queued for deploy

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.create_bulk()
    - NDBaseInterfaceOrchestrator.bulk_create_groups()
    """

    def responses():
        yield responses_subif("test_create_bulk_grouped_00910a")
        yield responses_subif("test_create_bulk_grouped_00910b")
        yield responses_subif("test_create_bulk_grouped_00910c")
        yield responses_subif("test_create_bulk_grouped_00910d")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        models = [
            _build_model(
                switch_ip="192.168.12.181", interface_name="GigabitEthernet1/0/2.100", network_os_type="ios-xe", vlan_id=100, ip="10.99.100.1", prefix=24
            ),
            _build_model(
                switch_ip="192.168.12.181",
                interface_name="GigabitEthernet1/0/2.101",
                network_os_type="ios-xe",
                policy_type="iosXeSubinterfaceShutNoshut",
                admin_state=False,
            ),
            _build_model(interface_name="Ethernet1/3.2", vlan_id=2, ip="10.20.30.40", prefix=24),
        ]
        results = orchestrator.create_bulk(models)

    assert len(results) == 3
    assert len(orchestrator.rest_send.responses) == 4
    assert ("GigabitEthernet1/0/2.100", "CAT9KV1701") in orchestrator._pending_deploys
    assert ("GigabitEthernet1/0/2.101", "CAT9KV1701") in orchestrator._pending_deploys
    assert ("Ethernet1/3.2", "FDO11111AAA") in orchestrator._pending_deploys


def test_subinterface_managed_orchestrator_00920() -> None:
    """
    # Summary

    Verify the grouping keys `bulk_create_groups` builds for the subinterface model: `policy_type` is read through the model's
    discriminated union for both branches and the group order follows the first model of each group.

    ## Test

    - Same three models as test 00910
    - Keys are `(CAT9KV1701, iosXeSubinterface)`, `(CAT9KV1701, iosXeSubinterfaceShutNoshut)`, `(FDO11111AAA, subinterface)` in that order
    - Each payload carries the injected `switchId` and its `policyType`

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.bulk_create_groups()
    - NDBaseInterfaceOrchestrator._desired_policy_type()
    """

    def responses():
        yield responses_subif("test_bulk_create_groups_00920a")

    gen_responses = ResponseGenerator(responses())

    with does_not_raise():
        orchestrator = _build_orchestrator(gen_responses)
        models = [
            _build_model(
                switch_ip="192.168.12.181", interface_name="GigabitEthernet1/0/2.100", network_os_type="ios-xe", vlan_id=100, ip="10.99.100.1", prefix=24
            ),
            _build_model(
                switch_ip="192.168.12.181",
                interface_name="GigabitEthernet1/0/2.101",
                network_os_type="ios-xe",
                policy_type="iosXeSubinterfaceShutNoshut",
                admin_state=False,
            ),
            _build_model(interface_name="Ethernet1/3.2", vlan_id=2, ip="10.20.30.40", prefix=24),
        ]
        groups = orchestrator.bulk_create_groups(models)

    keys = [(key.switch_id, key.policy_type) for key in groups]
    assert keys == [("CAT9KV1701", "iosXeSubinterface"), ("CAT9KV1701", "iosXeSubinterfaceShutNoshut"), ("FDO11111AAA", "subinterface")]
    for key, items in groups.items():
        for item in items:
            assert item.payload["switchId"] == key.switch_id
            assert item.payload["configData"]["networkOS"]["policy"]["policyType"] == key.policy_type


def test_subinterface_managed_orchestrator_00930() -> None:
    """
    # Summary

    Verify a mixed HTTP 207 inside one `(switch, policyType)` group still deploy-queues the subinterface the controller accepted: the
    accepted sibling's intent IS on the controller, so the failure-path finalizer must ship it. The match is case-insensitive and the
    queued pair keeps the module's identifier.

    ## Test

    - Two `iosXeSubinterface` subinterfaces on the Catalyst share one POST
    - POST returns 207: the `.100` subinterface `success` (echoed in a different case), the `.101` subinterface `failed`
    - `RuntimeError` matches `Bulk create failed` and names the accepted subinterface
    - `_pending_deploys` holds only the `.100` subinterface

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.create_bulk()
    - NDBaseInterfaceOrchestrator._post_bulk_create_group()
    """

    def responses():
        yield responses_subif("test_subinterface_managed_orchestrator_00930a")
        yield responses_subif("test_subinterface_managed_orchestrator_00930b")

    orchestrator = _build_orchestrator(ResponseGenerator(responses()))
    models = [
        _build_model(switch_ip="192.168.12.181", interface_name=name, network_os_type="ios-xe", vlan_id=vlan, ip=f"10.99.{vlan}.1", prefix=24)
        for name, vlan in (("GigabitEthernet1/0/2.100", 100), ("GigabitEthernet1/0/2.101", 101))
    ]

    with pytest.raises(RuntimeError, match=r"Bulk create failed.*accepted \['GigabitEthernet1/0/2\.100'\] from the same request"):
        orchestrator.create_bulk(models)

    assert len(orchestrator.rest_send.responses) == 2
    assert orchestrator._pending_deploys == [("GigabitEthernet1/0/2.100", "CAT9KV1701")]


def test_subinterface_managed_orchestrator_00940() -> None:
    """
    # Summary

    Verify `state: deleted` refuses to remove an IOS-XE subinterface that is deployed but not yet discovered, before anything is
    queued, while a discovered sibling passes.

    ## Test

    - The `.100` subinterface is `down`; the `.101` subinterface is `unknown` and its newest history push is its create
    - `preflight_delete` raises `RuntimeError` naming the `.101` subinterface only
    - Exactly three requests; nothing is queued

    ## Classes and Methods

    - NDBaseInterfaceOrchestrator.preflight_delete()
    - NDBaseInterfaceOrchestrator._check_xe_removal_discovered()
    """

    def responses():
        yield responses_subif("test_subinterface_managed_orchestrator_00940a")
        yield responses_subif("test_subinterface_managed_orchestrator_00940b")
        yield responses_subif("test_subinterface_managed_orchestrator_00940c")

    names = (("GigabitEthernet1/0/2.100", 100), ("GigabitEthernet1/0/2.101", 101))
    config = [{"switch_ip": "192.168.12.181", "interface_name": name} for name, vlan in names]
    orchestrator = _build_orchestrator(ResponseGenerator(responses()), state="deleted", config=config)
    models = [
        _build_model(switch_ip="192.168.12.181", interface_name=name, network_os_type="ios-xe", vlan_id=vlan, ip=f"10.99.{vlan}.1", prefix=24)
        for name, vlan in names
    ]

    with pytest.raises(RuntimeError, match=r"Cannot remove IOS-XE interface.*GigabitEthernet1/0/2\.101") as exc_info:
        orchestrator.preflight_delete(models)

    assert "GigabitEthernet1/0/2.100" not in str(exc_info.value)
    assert len(orchestrator.rest_send.responses) == 3
    assert orchestrator._pending_removes == []
    assert orchestrator._pending_deploys == []


# =============================================================================
# Test: preflight_create -- IOS-XE create requirements (PR #572 review)
# =============================================================================


def test_subinterface_managed_orchestrator_00950() -> None:
    """
    # Summary

    Verify `preflight_create` rejects a new full `iosXeSubinterface` that lacks the fields ND requires on create (`vlan_id`, `ip`),
    before any request, aggregating every incomplete item into one error that names the missing fields per item.

    ## Test

    - Create subset: `.100` with only `admin_state`, `.101` with `vlan_id` but no `ip`, `.102` complete
    - `RuntimeError` names `.100` (vlan_id, ip) and `.101` (ip) and not `.102`
    - No request is made

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.preflight_create()
    """
    orchestrator = _build_orchestrator(ResponseGenerator(iter(())))
    models = [
        _build_model(switch_ip="192.168.12.181", interface_name="GigabitEthernet1/0/2.100", network_os_type="ios-xe", admin_state=True),
        _build_model(switch_ip="192.168.12.181", interface_name="GigabitEthernet1/0/2.101", network_os_type="ios-xe", vlan_id=101),
        _build_model(
            switch_ip="192.168.12.181", interface_name="GigabitEthernet1/0/2.102", network_os_type="ios-xe", vlan_id=102, ip="10.99.102.1", prefix=24
        ),
    ]

    match = r"GigabitEthernet1/0/2\.100.*missing: vlan_id, ip.*GigabitEthernet1/0/2\.101.*missing: ip"
    with pytest.raises(RuntimeError, match=match) as exc_info:
        orchestrator.preflight_create(models)

    assert "GigabitEthernet1/0/2.102" not in str(exc_info.value)
    assert len(orchestrator.rest_send.responses) == 0


def test_subinterface_managed_orchestrator_00960() -> None:
    """
    # Summary

    Verify the IOS-XE create requirements apply only to the full `iosXeSubinterface` policy: a complete one, the admin-state-only
    `iosXeSubinterfaceShutNoshut`, and an NX-OS `subinterface` all pass, and the inherited policy-less guard still fires.

    ## Test

    - A complete `iosXeSubinterface`, an `iosXeSubinterfaceShutNoshut` with only `admin_state`, and an NX-OS subinterface do not raise
    - A create item with no policy still raises the inherited "without a policy" error

    ## Classes and Methods

    - SubinterfaceManagedInterfaceOrchestrator.preflight_create()
    - NDBaseInterfaceOrchestrator.preflight_create()
    """
    orchestrator = _build_orchestrator(ResponseGenerator(iter(())))
    models = [
        _build_model(
            switch_ip="192.168.12.181", interface_name="GigabitEthernet1/0/2.100", network_os_type="ios-xe", vlan_id=100, ip="10.99.100.1", prefix=24
        ),
        _build_model(
            switch_ip="192.168.12.181",
            interface_name="GigabitEthernet1/0/2.101",
            network_os_type="ios-xe",
            policy_type="iosXeSubinterfaceShutNoshut",
            admin_state=False,
        ),
        _build_model(interface_name="Ethernet1/3.2", admin_state=True),
    ]

    with does_not_raise():
        orchestrator.preflight_create(models)

    with pytest.raises(RuntimeError, match=r"without a policy"):
        orchestrator.preflight_create([_build_model(interface_name="Ethernet1/3.3")])
