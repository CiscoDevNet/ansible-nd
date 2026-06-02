# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `FabricUpdateGroupOrchestrator`.

Verifies the orchestrator drives `RestSend` against the switch-centric action API: `create` /
`create_bulk` attach switches via `attachGroup`, `update` reconciles membership via
`attachGroup` / `detachGroup`, `delete` detaches all switches (ND auto-deletes the empty group),
and group settings are applied via `PUT /updateGroups/{name}`. Reads (`query_one` / `query_all`)
stay on the group-centric GET endpoints.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,too-many-lines
# pylint: disable=assignment-from-no-return,use-implicit-booleaness-not-comparison
# pylint: disable=invalid-name,line-too-long

from __future__ import annotations

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.fabric_update_group.fabric_update_group import (
    FabricUpdateGroupModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.fabric_update_group import (
    FabricUpdateGroupOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_fabric_update_group(key: str):
    """Load fixture data for test_fabric_update_group tests."""
    return load_fixture("test_fabric_update_group")[key]


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


# Switches are supplied as fabric management IP addresses only. The orchestrator resolves them to
# switchIds via FabricContext; in unit tests a fake context resolves these IPs in-memory so no
# switches-list response is consumed (the create/update fixtures carry only the group operations).
_TEST_IP_TO_ID = {
    "192.168.0.1": "FDO1",
    "192.168.0.2": "FDO2",
    "192.168.0.3": "FDO3",
    "192.168.0.9": "FDO9",
}


class _FakeFabricContext:
    """In-memory `FabricContext` stand-in: resolves IPs to switchIds and back, no API calls."""

    def __init__(self, ip_to_id: dict[str, str] | None = None, id_to_ip: dict[str, str] | None = None) -> None:
        self._ip_to_id = ip_to_id or {}
        self._id_to_ip = id_to_ip if id_to_ip is not None else {sid: ip for ip, sid in self._ip_to_id.items()}

    def get_switch_id(self, switch_ip: str) -> str:
        """Resolve a fabricManagementIp to its switchId, raising if unknown (mirrors FabricContext)."""
        try:
            return self._ip_to_id[switch_ip]
        except KeyError as error:
            raise RuntimeError(f"No switch found with fabricManagementIp '{switch_ip}'.") from error

    @property
    def switch_map_by_id(self) -> dict[str, str]:
        """Return the switchId -> fabricManagementIp mapping."""
        return self._id_to_ip


class _RaisingFabricContext:
    """`FabricContext` stand-in whose `switch_map_by_id` raises (inventory unavailable)."""

    @property
    def switch_map_by_id(self) -> dict[str, str]:
        """Raise to simulate a failed switch-inventory fetch."""
        raise RuntimeError("switch inventory unavailable")


def _resolving_instance(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1") -> tuple[RestSend, FabricUpdateGroupOrchestrator]:
    """Build a `RestSend` + orchestrator with an in-memory `FabricContext` that resolves the test IPs."""
    rest_send = _build_rest_send(gen_responses, fabric_name)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    instance._fabric_context = _FakeFabricContext(ip_to_id=_TEST_IP_TO_ID)
    return rest_send, instance


def _build_model(update_group_name: str = "leaf_group", force_created: bool = False) -> FabricUpdateGroupModel:
    """Build a `FabricUpdateGroupModel` with full settings and two IP-form switches."""
    return FabricUpdateGroupModel(
        update_group_name=update_group_name,
        execution="serial",
        contingency="continue",
        analysis="snapshot",
        is_maintenance=True,
        is_disruptive_update=True,
        update_group_switches=["192.168.0.1", "192.168.0.2"],
        force_created=force_created,
    )


# =============================================================================
# Test: initialization
# =============================================================================


def test_fabric_update_group_00010() -> None:
    """
    # Summary

    Verify `FabricUpdateGroupOrchestrator` instantiates and exposes the expected ClassVars.

    ## Test

    - `model_class` is `FabricUpdateGroupModel`
    - `supports_bulk_create` is True

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.__init__()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)

    assert instance.model_class is FabricUpdateGroupModel
    assert instance.supports_bulk_create is True


def test_fabric_update_group_00020() -> None:
    """
    # Summary

    Verify `fabric_name` is read from `rest_send.params`.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.fabric_name
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, fabric_name="SITE1")
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)

    assert instance.fabric_name == "SITE1"


# =============================================================================
# Test: create
# =============================================================================


def test_fabric_update_group_00100() -> None:
    """
    # Summary

    Verify `create` attaches switches via `attachGroup` then applies settings via PUT.

    ## Test

    - attachGroup POST (207 success), GET the created group, PUT merged settings
    - The final call is the PUT against the per-name URL
    - The PUT body carries the user's settings overlaid on the GET defaults

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create()
    - FabricUpdateGroupOrchestrator._attach()
    - FabricUpdateGroupOrchestrator._apply_settings()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")
        yield responses_fabric_update_group(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = _build_model()

    with does_not_raise():
        instance.create(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert "attachUpdateGroups" not in body
    assert body["updateGroupName"] == "leaf_group"
    assert body["execution"] == "serial"
    assert body["contingency"] == "continue"
    assert body["analysis"] == "snapshot"
    assert body["isMaintenance"] is True
    assert body["isDisruptiveUpdate"] is True
    assert body["updateGroupSwitches"] == ["FDO1", "FDO2"]


def test_fabric_update_group_00110() -> None:
    """
    # Summary

    Verify `create` raises `RuntimeError` when `attachGroup` returns a 207 item with `status: failed`.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create()
    - FabricUpdateGroupOrchestrator._raise_on_207_action_errors()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = _build_model()

    with pytest.raises(RuntimeError, match=r"Create failed for .*leaf_group.*failed.*Switch not found"):
        instance.create(model)


def test_fabric_update_group_00120() -> None:
    """
    # Summary

    Verify `create` wraps a transport failure in `RuntimeError` mentioning the identifier.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = _build_model()

    with pytest.raises(RuntimeError, match=r"Create failed for .*leaf_group"):
        instance.create(model)


def test_fabric_update_group_00130() -> None:
    """
    # Summary

    Verify `create` raises when `attachGroup` returns `status: warning` and `force_created` is False.

    ## Test

    - Model has `force_created=False`
    - attachGroup 207 with `status: warning`
    - `RuntimeError` is raised so the user must explicitly opt in to force

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create()
    - FabricUpdateGroupOrchestrator._raise_on_207_action_errors()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = _build_model(force_created=False)

    with pytest.raises(RuntimeError, match=r"Create failed for .*leaf_group.*warning"):
        instance.create(model)


def test_fabric_update_group_00135() -> None:
    """
    # Summary

    Verify `create` raises on an `attachGroup` `status: warning` even when `force_created` is True.

    ND returns `status: warning` only when it did NOT apply the attach (verified live: a non-forced
    warning leaves a zero-switch ghost group). `force_created` governs the request `forceCreated`
    value, not response interpretation - a `warning` always means nothing was attached, so it always
    fails the task.

    ## Test

    - Model has `force_created=True`
    - attachGroup 207 with `status: warning` still raises `RuntimeError`

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create()
    - FabricUpdateGroupOrchestrator._raise_on_207_action_errors()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = _build_model(force_created=True)

    with pytest.raises(RuntimeError, match=r"Create failed for .*leaf_group.*warning"):
        instance.create(model)


def test_fabric_update_group_00140() -> None:
    """
    # Summary

    Verify `create` sends `forceCreated: true` in the `attachGroup` body when `force_created` is True.

    ## Test

    - Model has `force_created=True` and no settings
    - The attachGroup body item carries `forceCreated: true`

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create()
    - FabricUpdateGroupOrchestrator._attach_item()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = FabricUpdateGroupModel(update_group_name="leaf_group", update_group_switches=["192.168.0.1", "192.168.0.2"], force_created=True)

    with does_not_raise():
        instance.create(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/softwareUpdatePlan/actions/attachGroup"
    body = rest_send.committed_payload
    assert body == {"attachUpdateGroups": [{"updateGroupName": "leaf_group", "switchIds": ["FDO1", "FDO2"], "forceCreated": True}]}


def test_fabric_update_group_00150() -> None:
    """
    # Summary

    Verify `create` with no settings issues only the `attachGroup` POST (no follow-up PUT).

    ## Test

    - Model carries only name + switches
    - The single call is the attachGroup POST
    - The body is `{"attachUpdateGroups": [{updateGroupName, switchIds, forceCreated}]}`

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create()
    - FabricUpdateGroupOrchestrator._attach()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = FabricUpdateGroupModel(update_group_name="leaf_group", update_group_switches=["192.168.0.1", "192.168.0.2"])

    with does_not_raise():
        instance.create(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/softwareUpdatePlan/actions/attachGroup"
    assert rest_send.verb == HttpVerbEnum.POST.value
    body = rest_send.committed_payload
    assert body == {"attachUpdateGroups": [{"updateGroupName": "leaf_group", "switchIds": ["FDO1", "FDO2"], "forceCreated": False}]}


def test_fabric_update_group_00160() -> None:
    """
    # Summary

    Verify the create-path settings PUT carries the user's switches even when the GET issued right
    after `attachGroup` returns EMPTY membership (ND read-after-write lag). The PUT body's
    `updateGroupSwitches` must come from the user's model (re-applied by `merge`), never from the
    stale GET - otherwise the full-replace PUT would detach the switches that were just attached.

    This locks in the guarantee that an eventually-consistent GET cannot turn the create-path settings
    PUT into an accidental detach.

    ## Test

    - attachGroup 207 success, GET returns the group with `updateGroupSwitches: []`, then PUT
    - The PUT body still carries the user's resolved switchIds

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create()
    - FabricUpdateGroupOrchestrator._apply_settings()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")
        yield responses_fabric_update_group(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = _build_model()

    with does_not_raise():
        instance.create(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    body = rest_send.committed_payload
    assert body["updateGroupSwitches"] == ["FDO1", "FDO2"]


# =============================================================================
# Test: update
# =============================================================================


def test_fabric_update_group_00200() -> None:
    """
    # Summary

    Verify `update` reconciles membership (attach added, detach removed) and applies settings.

    ## Test

    - GET current group (membership FDO1, FDO9), attach FDO2, detach FDO9, PUT settings
    - The final call is the PUT carrying the desired membership and settings

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")
        yield responses_fabric_update_group(f"{method_name}c")
        yield responses_fabric_update_group(f"{method_name}d")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = _build_model()

    with does_not_raise():
        instance.update(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    body = rest_send.committed_payload
    assert body["updateGroupName"] == "leaf_group"
    assert body["execution"] == "serial"
    assert body["updateGroupSwitches"] == ["FDO1", "FDO2"]


def test_fabric_update_group_00210() -> None:
    """
    # Summary

    Verify `update` wraps a transport failure in `RuntimeError` mentioning the identifier.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = _build_model()

    with pytest.raises(RuntimeError, match=r"Update failed for .*leaf_group"):
        instance.update(model)


def test_fabric_update_group_00220() -> None:
    """
    # Summary

    Verify `update` with an added switch and no settings issues only GET + `attachGroup`.

    ## Test

    - Current membership FDO1, FDO2; desired adds FDO3; no settings on the model
    - The final call is the attachGroup POST carrying only the added switch

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.update()
    - FabricUpdateGroupOrchestrator._attach()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = FabricUpdateGroupModel(update_group_name="leaf_group", update_group_switches=["192.168.0.1", "192.168.0.2", "192.168.0.3"])

    with does_not_raise():
        instance.update(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/softwareUpdatePlan/actions/attachGroup"
    body = rest_send.committed_payload
    assert body == {"attachUpdateGroups": [{"updateGroupName": "leaf_group", "switchIds": ["FDO3"], "forceCreated": False}]}


def test_fabric_update_group_00230() -> None:
    """
    # Summary

    Verify `update` with a removed switch and no settings issues only GET + `detachGroup`.

    ## Test

    - Current membership FDO1, FDO2; desired keeps only FDO1; no settings on the model
    - The final call is the detachGroup POST carrying only the removed switch

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.update()
    - FabricUpdateGroupOrchestrator._detach()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = FabricUpdateGroupModel(update_group_name="leaf_group", update_group_switches=["192.168.0.1"])

    with does_not_raise():
        instance.update(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/softwareUpdatePlan/actions/detachGroup"
    body = rest_send.committed_payload
    assert body == {"detachUpdateGroups": [{"updateGroupName": "leaf_group", "switchIds": ["FDO2"]}]}


def test_fabric_update_group_00240() -> None:
    """
    # Summary

    Verify `update` with `state: replaced` builds a full-replace PUT body that resets an optional
    field the user omitted.

    ## Test

    - Current group carries `reportSelection: advanced`; the user's model omits it
    - `state` is `replaced`, so the PUT body seeds only the required fields from the current group and
      overlays the user's set fields - `reportSelection` is therefore absent and ND resets it
    - The user's `analysis: snapshot` still overrides the current `noAnalysis`

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.update()
    - FabricUpdateGroupOrchestrator._apply_settings()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    rest_send.params["state"] = "replaced"
    model = _build_model()

    with does_not_raise():
        instance.update(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    body = rest_send.committed_payload
    assert "reportSelection" not in body
    assert body["analysis"] == "snapshot"
    assert body["execution"] == "serial"
    assert body["updateGroupSwitches"] == ["FDO1", "FDO2"]


def test_fabric_update_group_00250() -> None:
    """
    # Summary

    Verify `update` with `state: merged` preserves an optional field the user omitted (contrast with
    the replaced behavior in 00240).

    ## Test

    - Current group carries `reportSelection: advanced`; the user's model omits it
    - `state` is `merged`, so the PUT body overlays the user's set fields onto the full current group
      and `reportSelection: advanced` is retained

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.update()
    - FabricUpdateGroupOrchestrator._apply_settings()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = _build_model()

    with does_not_raise():
        instance.update(model)

    assert rest_send.verb == HttpVerbEnum.PUT.value
    body = rest_send.committed_payload
    assert body["reportSelection"] == "advanced"
    assert body["analysis"] == "snapshot"


def test_fabric_update_group_00260() -> None:
    """
    # Summary

    Verify `update` rejects an empty `update_group_switches` (an empty update group is not permitted;
    `state: deleted` is the way to remove a group) before issuing any membership or settings write.

    ## Test

    - The model carries an empty `update_group_switches`
    - `update` GETs the current group, then raises `RuntimeError` (wrapped) without an attach/detach/PUT

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = FabricUpdateGroupModel(update_group_name="leaf_group", update_group_switches=[])

    with pytest.raises(RuntimeError, match=r"Update failed for .*leaf_group.*must be non-empty.*state: deleted"):
        instance.update(model)

    # The only request issued was the initial GET; no attach/detach/PUT followed.
    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group"
    assert rest_send.verb == HttpVerbEnum.GET.value


def test_fabric_update_group_00270() -> None:
    """
    # Summary

    Verify `update` with `state: merged` and an omitted `update_group_switches` (settings-only update)
    keeps the current membership and issues only GET + settings PUT (no attach/detach).

    ## Test

    - The model carries settings but omits `update_group_switches` (None)
    - Current membership is FDO1, FDO2; the PUT body preserves it and overlays the user's settings
    - No attachGroup / detachGroup request is issued

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.update()
    - FabricUpdateGroupOrchestrator._apply_settings()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    model = FabricUpdateGroupModel(update_group_name="leaf_group", analysis="snapshot")

    with does_not_raise():
        instance.update(model)

    # The last request is the settings PUT; no attach/detach intervened.
    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    body = rest_send.committed_payload
    assert body["updateGroupSwitches"] == ["FDO1", "FDO2"]
    assert body["analysis"] == "snapshot"
    assert body["reportSelection"] == "advanced"


def test_fabric_update_group_00280() -> None:
    """
    # Summary

    Verify `update` with `state: replaced` and an omitted `update_group_switches` keeps the current
    membership (a required PUT key) while still resetting an omitted optional field.

    ## Test

    - The model carries settings but omits `update_group_switches` (None)
    - `state` is `replaced`: the PUT seeds only required fields from the current group, so membership
      FDO1, FDO2 is preserved while the omitted optional `reportSelection` is reset (absent)

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.update()
    - FabricUpdateGroupOrchestrator._apply_settings()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    rest_send.params["state"] = "replaced"
    model = FabricUpdateGroupModel(update_group_name="leaf_group", analysis="snapshot")

    with does_not_raise():
        instance.update(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    body = rest_send.committed_payload
    assert body["updateGroupSwitches"] == ["FDO1", "FDO2"]
    assert body["analysis"] == "snapshot"
    assert "reportSelection" not in body


# =============================================================================
# Test: delete
# =============================================================================


def test_fabric_update_group_00300() -> None:
    """
    # Summary

    Verify `delete` detaches all of the group's switches (ND auto-deletes the emptied group).

    ## Test

    - GET current group to learn membership, then detachGroup POST with all switchIds

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.delete()
    - FabricUpdateGroupOrchestrator._detach()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = _build_model()

    with does_not_raise():
        instance.delete(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/softwareUpdatePlan/actions/detachGroup"
    assert rest_send.verb == HttpVerbEnum.POST.value
    body = rest_send.committed_payload
    assert body == {"detachUpdateGroups": [{"updateGroupName": "leaf_group", "switchIds": ["FDO1", "FDO2"]}]}


def test_fabric_update_group_00310() -> None:
    """
    # Summary

    Verify `delete` raises `RuntimeError` when `detachGroup` returns a 207 item with `status: failed`.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.delete()
    - FabricUpdateGroupOrchestrator._raise_on_207_action_errors()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = _build_model()

    with pytest.raises(RuntimeError, match=r"Delete failed for .*leaf_group.*failed"):
        instance.delete(model)


def test_fabric_update_group_00320() -> None:
    """
    # Summary

    Verify `delete` falls back to the group-centric DELETE when GET-single cannot read the group.

    A zero-switch ghost group returns HTTP 400 on the single GET; `delete` then issues the
    group-centric `DELETE /updateGroups/{name}` to free the reserved name.

    ## Test

    - GET single returns 400, `delete` issues DELETE against the per-name URL

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.delete()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = _build_model()

    with does_not_raise():
        instance.delete(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group"
    assert rest_send.verb == HttpVerbEnum.DELETE.value


def test_fabric_update_group_00330() -> None:
    """
    # Summary

    Verify `delete` propagates a non-ghost GET failure instead of falling back to a destructive DELETE.

    A zero-switch ghost group returns HTTP 400; any other failure (here 500) must not be mistaken for a
    ghost. `delete` re-raises so a transient/auth/server error is never turned into a DELETE.

    ## Test

    - GET single returns 500
    - `delete` raises `RuntimeError` (wrapped) and issues no DELETE; the last request is the GET

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.delete()
    - FabricUpdateGroupOrchestrator._get_group_raw_or_none()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = _build_model()

    with pytest.raises(RuntimeError, match=r"Delete failed for .*leaf_group"):
        instance.delete(model)

    # Only the GET was issued; no DELETE followed the unexpected failure.
    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group"
    assert rest_send.verb == HttpVerbEnum.GET.value


def test_fabric_update_group_00340() -> None:
    """
    # Summary

    Verify `delete` treats a 404 on the single GET as "group already gone" and falls back to the
    group-centric DELETE to free the reserved name.

    ## Test

    - GET single returns 404
    - `delete` issues DELETE against the per-name URL

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.delete()
    - FabricUpdateGroupOrchestrator._get_group_raw_or_none()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = _build_model()

    with does_not_raise():
        instance.delete(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group"
    assert rest_send.verb == HttpVerbEnum.DELETE.value


# =============================================================================
# Test: query_one
# =============================================================================


def test_fabric_update_group_00400() -> None:
    """
    # Summary

    Verify `query_one` issues GET against the per-name URL and returns the flat dict.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.query_one()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = _build_model()

    with does_not_raise():
        result = instance.query_one(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group"
    assert rest_send.verb == HttpVerbEnum.GET.value
    assert isinstance(result, dict)
    assert result["updateGroupName"] == "leaf_group"
    assert result["execution"] == "serial"


def test_fabric_update_group_00410() -> None:
    """
    # Summary

    Verify `query_one` wraps a transport failure in `RuntimeError` mentioning the identifier.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.query_one()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = _build_model()

    with pytest.raises(RuntimeError, match=r"Query failed for .*leaf_group"):
        instance.query_one(model)


# =============================================================================
# Test: query_all
# =============================================================================


def test_fabric_update_group_00500() -> None:
    """
    # Summary

    Verify `query_all` extracts the `updateGroups` list from the GET response.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups"
    assert rest_send.verb == HttpVerbEnum.GET.value
    assert isinstance(result, list)
    assert len(result) == 2
    assert {g["updateGroupName"] for g in result} == {"g1", "g2"}


def test_fabric_update_group_00510() -> None:
    """
    # Summary

    Verify `query_all` returns an empty list on 404.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert result == []


def test_fabric_update_group_00520() -> None:
    """
    # Summary

    Verify `query_all` wraps a transport failure in `RuntimeError`.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=r"Query all failed"):
        instance.query_all()


# =============================================================================
# Test: create_bulk
# =============================================================================


def test_fabric_update_group_00600() -> None:
    """
    # Summary

    Verify `create_bulk` sends one `attachGroup` POST for all groups, then per-group settings PUTs.

    ## Test

    - One attachGroup POST with both groups in `attachUpdateGroups`
    - A GET + PUT for each group's settings

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")
        yield responses_fabric_update_group(f"{method_name}c")
        yield responses_fabric_update_group(f"{method_name}d")
        yield responses_fabric_update_group(f"{method_name}e")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    models = [_build_model("g1"), _build_model("g2")]

    with does_not_raise():
        instance.create_bulk(models)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/g2"
    assert rest_send.verb == HttpVerbEnum.PUT.value


def test_fabric_update_group_00610() -> None:
    """
    # Summary

    Verify `create_bulk` raises `RuntimeError` when any `attachGroup` 207 item has `status: failed`.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create_bulk()
    - FabricUpdateGroupOrchestrator._raise_on_207_action_errors()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send, instance = _resolving_instance(gen_responses)
    models = [_build_model("g1"), _build_model("g2")]

    with pytest.raises(RuntimeError, match=r"Bulk create failed.*g2.*failed.*Switch missing"):
        instance.create_bulk(models)


# =============================================================================
# Test: switch IP <-> switchId resolution
# =============================================================================


def test_fabric_update_group_00700() -> None:
    """
    # Summary

    Verify `create` resolves switch IPs to switchIds in the `attachGroup` body via `FabricContext`.

    ## Test

    - Switches-list returns the IP -> switchId map
    - The attachGroup body carries the resolved switchIds

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create()
    - FabricUpdateGroupOrchestrator._attach_item()
    - FabricUpdateGroupOrchestrator._resolve_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = FabricUpdateGroupModel(
        update_group_name="leaf_group",
        update_group_switches=["192.168.12.151", "192.168.12.152"],
    )

    with does_not_raise():
        instance.create(model)

    body = rest_send.committed_payload
    assert body["attachUpdateGroups"][0]["switchIds"] == ["FDO12345ABC", "FDO12345ABD"]


def test_fabric_update_group_00715() -> None:
    """
    # Summary

    Verify `_resolve_switch_id` rejects a non-IP switch identifier (switches are accepted as fabric
    management IP addresses only), failing fast before any wire request.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator._resolve_switch_id()
    """
    rest_send = RestSend({"check_mode": False, "fabric_name": "fabric_1"})
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=r"is not a fabric management IP address.*IP addresses only"):
        instance._resolve_switch_id("FDO12345ABC")


def test_fabric_update_group_00710() -> None:
    """
    # Summary

    Verify `create` raises `RuntimeError` if a user-supplied switch IP cannot be resolved.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create()
    - FabricUpdateGroupOrchestrator._resolve_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = FabricUpdateGroupModel(update_group_name="leaf_group", update_group_switches=["192.168.12.151"])

    with pytest.raises(RuntimeError, match=r"Create failed for .*leaf_group.*No switch found with fabricManagementIp '192\.168\.12\.151'"):
        instance.create(model)


def test_fabric_update_group_00720() -> None:
    """
    # Summary

    Verify `update` resolves switch IPs to switchIds for both membership reconciliation and the PUT body.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.update()
    - FabricUpdateGroupOrchestrator._resolve_switch_id()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")
        yield responses_fabric_update_group(f"{method_name}c")
        yield responses_fabric_update_group(f"{method_name}d")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = FabricUpdateGroupModel(
        update_group_name="leaf_group",
        execution="serial",
        contingency="continue",
        analysis="snapshot",
        is_maintenance=True,
        is_disruptive_update=True,
        update_group_switches=["192.168.12.151", "192.168.12.152"],
    )

    with does_not_raise():
        instance.update(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    body = rest_send.committed_payload
    assert body["updateGroupSwitches"] == ["FDO12345ABC", "FDO12345ABD"]


def test_fabric_update_group_00730() -> None:
    """
    # Summary

    Verify `query_one` denormalizes switchIds back to IPs in the response.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.query_one()
    - FabricUpdateGroupOrchestrator._denormalize_switches_in_response()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = _build_model()

    with does_not_raise():
        result = instance.query_one(model)

    assert result["updateGroupSwitches"] == ["192.168.12.151", "192.168.12.152"]
    assert result["installationOrderDevices"] == ["192.168.12.151", "192.168.12.152"]


def test_fabric_update_group_00740() -> None:
    """
    # Summary

    Verify `query_all` denormalizes switchIds back to IPs, leaving unresolvable switchIds unchanged.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.query_all()
    - FabricUpdateGroupOrchestrator._denormalize_switches_in_response()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")
        yield responses_fabric_update_group(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert len(result) == 2
    by_name = {g["updateGroupName"]: g for g in result}
    assert by_name["g1"]["updateGroupSwitches"] == ["192.168.12.151"]
    assert by_name["g2"]["updateGroupSwitches"] == ["FDO99999XYZ"]


def test_fabric_update_group_00750() -> None:
    """
    # Summary

    Verify `_is_ip_address` accepts valid IPv4 and IPv6 addresses and rejects switchIds, malformed
    dotted strings, CIDR-prefixed values, and non-strings.

    ## Test

    - A valid IPv4 address is an IP
    - A valid IPv6 address is an IP (no dot - the old dot heuristic would have rejected it)
    - A switchId serial, a malformed dotted string, a CIDR-prefixed value, an empty string, and a
      non-string are not IPs

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator._is_ip_address()
    """
    assert FabricUpdateGroupOrchestrator._is_ip_address("192.168.12.151") is True
    assert FabricUpdateGroupOrchestrator._is_ip_address("2001:db8::1") is True
    assert FabricUpdateGroupOrchestrator._is_ip_address("fe80::200:5aee:feaa:20a2") is True
    assert FabricUpdateGroupOrchestrator._is_ip_address("FDO12345ABC") is False
    assert FabricUpdateGroupOrchestrator._is_ip_address("1.2.3") is False
    assert FabricUpdateGroupOrchestrator._is_ip_address("192.168.12.151/32") is False
    assert FabricUpdateGroupOrchestrator._is_ip_address("") is False
    assert FabricUpdateGroupOrchestrator._is_ip_address(None) is False


def test_fabric_update_group_00760() -> None:
    """
    # Summary

    Verify `query_all` drops the ND-managed default update group named "None".

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    names = {g["updateGroupName"] for g in result}
    assert names == {"g1", "g2"}


# =============================================================================
# Test: switchId -> IP denormalization helper
# =============================================================================


def _bare_instance(context) -> FabricUpdateGroupOrchestrator:
    """Build an orchestrator with `fabric_context` pre-seeded to a fake (no API calls)."""
    rest_send = RestSend({"check_mode": False, "fabric_name": "fabric_1"})
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    instance._fabric_context = context
    return instance


def test_fabric_update_group_00770() -> None:
    """
    # Summary

    Verify `_switch_ids_to_ips` maps wire switchIds to IPs and passes through switchIds absent from
    the fabric (stale serials).

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator._switch_ids_to_ips()
    """
    instance = _bare_instance(_FakeFabricContext(id_to_ip={"FDO1": "192.168.1.1", "FDO2": "192.168.1.2"}))

    result = instance._switch_ids_to_ips(["FDO1", "FDO2", "FDO_STALE"])

    assert result == ["192.168.1.1", "192.168.1.2", "FDO_STALE"]


def test_fabric_update_group_00790() -> None:
    """
    # Summary

    Verify `_switch_ids_to_ips` does NOT swallow a switch-inventory load failure: it propagates so a
    real fault surfaces as an error rather than masquerading as unconverted switchIds (which would
    diff against the user's IPs and report a silent perpetual `changed`).

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator._switch_ids_to_ips()
    """
    instance = _bare_instance(_RaisingFabricContext())

    with pytest.raises(RuntimeError, match=r"switch inventory unavailable"):
        instance._switch_ids_to_ips(["FDO1", "FDO2"])


# =============================================================================
# Test: propose (auto-assign)
# =============================================================================


@pytest.mark.parametrize("algorithm", ["roleBased", "evenOdd"], ids=["roleBased", "evenOdd"])
def test_fabric_update_group_00800(algorithm: str) -> None:
    """
    # Summary

    Verify `propose` POSTs the chosen algorithm to the `softwareUpdatePlan` propose action endpoint.

    ## Test

    - `propose` is called with `roleBased` / `evenOdd`
    - The request is a POST to `.../softwareUpdatePlan/actions/propose`
    - The request body is `{"algorithm": <algorithm>}`
    - The propose plan dict is returned

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.propose()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.propose(algorithm)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/softwareUpdatePlan/actions/propose"
    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.committed_payload == {"algorithm": algorithm}
    assert isinstance(result, dict)
    assert "updateGroups" in result


def test_fabric_update_group_00810() -> None:
    """
    # Summary

    Verify `propose` wraps a transport failure in `RuntimeError` mentioning the fabric.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.propose()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=r"Auto-assign \(propose\) failed for fabric 'fabric_1'"):
        instance.propose("roleBased")


# =============================================================================
# Test: _raise_on_207_action_errors
# =============================================================================


def test_fabric_update_group_00900() -> None:
    """
    # Summary

    Verify `_raise_on_207_action_errors` treats a 207 item with a MISSING `status` as a failure. ND
    reports success explicitly, so an absent status means the per-item outcome is unknown and must not
    be assumed successful.

    ## Test

    - A 207 item with no `status` key raises `RuntimeError`
    - The raised message names the offending group

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator._raise_on_207_action_errors()
    """
    result = {"attachUpdateGroups": [{"updateGroupName": "g1", "warningMessage": "no status echoed"}]}

    with pytest.raises(RuntimeError, match=r"Per-item failures in attachUpdateGroups.*g1.*None"):
        FabricUpdateGroupOrchestrator._raise_on_207_action_errors(result, "attachUpdateGroups", "warningMessage")


def test_fabric_update_group_00910() -> None:
    """
    # Summary

    Verify `_raise_on_207_action_errors` does not raise when every item reports `status: success`.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator._raise_on_207_action_errors()
    """
    result = {"attachUpdateGroups": [{"updateGroupName": "g1", "status": "success"}, {"updateGroupName": "g2", "status": "success"}]}

    with does_not_raise():
        FabricUpdateGroupOrchestrator._raise_on_207_action_errors(result, "attachUpdateGroups", "warningMessage")
