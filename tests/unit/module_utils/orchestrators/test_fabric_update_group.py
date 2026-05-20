# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `FabricUpdateGroupOrchestrator`.

Verifies that the orchestrator drives `RestSend` correctly for fabric update group CRUD,
wraps create payloads in `{"updateGroups": [...]}` for the bulk POST endpoint, inspects
per-item status in 207 responses, sends a flat PUT body, extracts `updateGroups` from
`query_all`, and resolves `fabric_name` from `RestSend` params.
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


def _build_model(update_group_name: str = "leaf_group") -> FabricUpdateGroupModel:
    """Build a minimal valid `FabricUpdateGroupModel`."""
    return FabricUpdateGroupModel(
        update_group_name=update_group_name,
        execution="serial",
        contingency="continue",
        analysis="snapshot",
        is_maintenance=True,
        is_disruptive_update=True,
        update_group_switches=["FDO1", "FDO2"],
    )


# =============================================================================
# Test: initialization
# =============================================================================


def test_fabric_update_group_00010() -> None:
    """
    # Summary

    Verify `FabricUpdateGroupOrchestrator` instantiates and exposes expected ClassVars / endpoint fields.

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

    Verify `create` issues POST against the collection URL with `{"updateGroups": [payload]}` body.

    ## Test

    - POST against `/api/v1/manage/fabrics/fabric_1/updateGroups`
    - Body wraps the single payload in the `updateGroups` array
    - Payload contains `updateGroupName: leaf_group`
    - 207 with `status: success` returns normally

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = _build_model()

    with does_not_raise():
        instance.create(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups"
    assert rest_send.verb == HttpVerbEnum.POST.value
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert "updateGroups" in body
    assert len(body["updateGroups"]) == 1
    payload_item = body["updateGroups"][0]
    assert payload_item["updateGroupName"] == "leaf_group"
    assert payload_item["execution"] == "serial"


def test_fabric_update_group_00110() -> None:
    """
    # Summary

    Verify `create` raises `RuntimeError` when a 207 response contains an item with `status: error`.

    ## Test

    - 207 with `{"updateGroups": [{updateGroupName, status: error}]}`
    - `RuntimeError` is raised with the per-item error message

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create()
    - FabricUpdateGroupOrchestrator._raise_on_207_item_errors()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = _build_model()

    with pytest.raises(RuntimeError, match=r"Create failed for .*leaf_group.*error.*Switch not found"):
        instance.create(model)


def test_fabric_update_group_00120() -> None:
    """
    # Summary

    Verify `create` wraps a transport failure in `RuntimeError` mentioning the identifier.

    ## Test

    - POST returns 500
    - `RuntimeError` matches `Create failed for .*leaf_group`

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = _build_model()

    with pytest.raises(RuntimeError, match=r"Create failed for .*leaf_group"):
        instance.create(model)


# =============================================================================
# Test: update
# =============================================================================


def test_fabric_update_group_00200() -> None:
    """
    # Summary

    Verify `update` issues PUT against per-name URL with a flat group dict (no `updateGroups` wrapper).

    ## Test

    - PUT against `/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group`
    - Body is the flat payload (`updateGroupName: leaf_group` at the top level)

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = _build_model()

    with does_not_raise():
        instance.update(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert "updateGroups" not in body
    assert body["updateGroupName"] == "leaf_group"
    assert body["execution"] == "serial"


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
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = _build_model()

    with pytest.raises(RuntimeError, match=r"Update failed for .*leaf_group"):
        instance.update(model)


# =============================================================================
# Test: delete
# =============================================================================


def test_fabric_update_group_00300() -> None:
    """
    # Summary

    Verify `delete` issues DELETE against per-name URL with no body.

    ## Test

    - DELETE against `/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group`
    - 204 returns normally

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.delete()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    model = _build_model()

    with does_not_raise():
        instance.delete(model)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups/leaf_group"
    assert rest_send.verb == HttpVerbEnum.DELETE.value


def test_fabric_update_group_00310() -> None:
    """
    # Summary

    Verify `delete` wraps a transport failure in `RuntimeError` mentioning the identifier.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.delete()
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


# =============================================================================
# Test: query_one
# =============================================================================


def test_fabric_update_group_00400() -> None:
    """
    # Summary

    Verify `query_one` issues GET against per-name URL and returns the flat dict.

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

    Verify `create_bulk` sends a single POST with all groups in the `updateGroups` array.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    models = [_build_model("g1"), _build_model("g2")]

    with does_not_raise():
        instance.create_bulk(models)

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/updateGroups"
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert len(body["updateGroups"]) == 2
    assert [g["updateGroupName"] for g in body["updateGroups"]] == ["g1", "g2"]


def test_fabric_update_group_00610() -> None:
    """
    # Summary

    Verify `create_bulk` raises `RuntimeError` when any item in the 207 response has status:error.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create_bulk()
    - FabricUpdateGroupOrchestrator._raise_on_207_item_errors()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_update_group(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricUpdateGroupOrchestrator(rest_send=rest_send)
    models = [_build_model("g1"), _build_model("g2")]

    with pytest.raises(RuntimeError, match=r"Bulk create failed.*g2.*error.*Switch missing"):
        instance.create_bulk(models)


# =============================================================================
# Test: switch IP <-> switchId resolution
# =============================================================================


def test_fabric_update_group_00700() -> None:
    """
    # Summary

    Verify `create` resolves switch IPs in `update_group_switches` and `installation_order_devices`
    to switchIds via `FabricContext` before sending.

    ## Test

    - Switches-list returns two switches (IP -> switchId map)
    - POST is issued with payload containing switchIds, not IPs
    - The serial-form entry in `update_group_switches` is passed through unchanged

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.create()
    - FabricUpdateGroupOrchestrator._resolve_switches_in_payload()
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
        execution="serial",
        contingency="continue",
        analysis="snapshot",
        is_maintenance=True,
        is_disruptive_update=True,
        # First two entries are IPs, third is a switchId pass-through
        update_group_switches=["192.168.12.151", "192.168.12.152", "FDO_PASSTHROUGH"],
        installation_order_devices=["192.168.12.152", "192.168.12.151"],
    )

    with does_not_raise():
        instance.create(model)

    body = rest_send.committed_payload
    payload_item = body["updateGroups"][0]
    assert payload_item["updateGroupSwitches"] == ["FDO12345ABC", "FDO12345ABD", "FDO_PASSTHROUGH"]
    assert payload_item["installationOrderDevices"] == ["FDO12345ABD", "FDO12345ABC"]


def test_fabric_update_group_00710() -> None:
    """
    # Summary

    Verify `create` raises `RuntimeError` if a user-supplied switch IP cannot be resolved in the fabric.

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

    model = FabricUpdateGroupModel(
        update_group_name="leaf_group",
        execution="serial",
        contingency="continue",
        analysis="snapshot",
        is_maintenance=True,
        is_disruptive_update=True,
        update_group_switches=["192.168.12.151"],
    )

    with pytest.raises(RuntimeError, match=r"Create failed for .*leaf_group.*No switch found with fabricManagementIp '192\.168\.12\.151'"):
        instance.create(model)


def test_fabric_update_group_00720() -> None:
    """
    # Summary

    Verify `update` resolves switch IPs to switchIds in the PUT body.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator.update()
    - FabricUpdateGroupOrchestrator._resolve_switches_in_payload()
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
        execution="serial",
        contingency="continue",
        analysis="snapshot",
        is_maintenance=True,
        is_disruptive_update=True,
        update_group_switches=["192.168.12.151", "192.168.12.152"],
    )

    with does_not_raise():
        instance.update(model)

    body = rest_send.committed_payload
    assert body["updateGroupSwitches"] == ["FDO12345ABC", "FDO12345ABD"]


def test_fabric_update_group_00730() -> None:
    """
    # Summary

    Verify `query_one` denormalizes switchIds back to IPs in the response.

    ## Test

    - GET returns updateGroupSwitches / installationOrderDevices as switchIds
    - Result has those lists rewritten to fabricManagementIp values

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

    Verify `query_all` denormalizes switchIds back to IPs in every list item, leaving unresolvable
    switchIds (those not present in the fabric switch map) unchanged.

    ## Test

    - GET list returns two groups: g1 has a known switchId, g2 has an unknown one
    - g1.updateGroupSwitches resolves to ["192.168.12.151"]
    - g2.updateGroupSwitches stays as ["FDO99999XYZ"] (unresolvable)

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

    Verify `_looks_like_ip` heuristic: strings with dots are IPs, others are switchIds.

    ## Classes and Methods

    - FabricUpdateGroupOrchestrator._looks_like_ip()
    """
    assert FabricUpdateGroupOrchestrator._looks_like_ip("192.168.12.151") is True
    assert FabricUpdateGroupOrchestrator._looks_like_ip("FDO12345ABC") is False
    assert FabricUpdateGroupOrchestrator._looks_like_ip("") is False


def test_fabric_update_group_00760() -> None:
    """
    # Summary

    Verify `query_all` drops the ND-managed default update group named "None".

    ND returns a system-managed default group (the literal name "None") holding switches not assigned
    to any user-defined group. It must not appear in query results, otherwise `state: overridden` would
    attempt to delete a group ND manages itself.

    ## Test

    - GET list returns three groups: g1, "None", g2
    - `query_all` returns only g1 and g2

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
