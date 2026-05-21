# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `FabricPrepareUpdateOrchestrator`.

Verifies the orchestrator drives `RestSend` against the ND software-update "prepare" workflow:
`preflight_role_check` rejects a mixed-role update group, `status_snapshot` summarizes per-switch
stage / validate status, `stage` POSTs the stage action, and `wait_for_completion` polls the plan
summary until staging succeeds, fails, or times out.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,too-many-lines
# pylint: disable=invalid-name,line-too-long

from __future__ import annotations

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.fabric_prepare_update.software_update_plan_summary import SwitchStageStatusModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.fabric_prepare_update import (
    FabricPrepareUpdateOrchestrator,
    _switch_has_failed,
    _switch_is_prepared,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_fabric_prepare_update(key: str):
    """Load fixture data for test_fabric_prepare_update tests."""
    return load_fixture("test_fabric_prepare_update")[key]


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


def test_fabric_prepare_update_00010() -> None:
    """
    # Summary

    Verify `FabricPrepareUpdateOrchestrator` instantiates with an injected `RestSend`.

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.__init__()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    assert instance.results is None


def test_fabric_prepare_update_00020() -> None:
    """
    # Summary

    Verify `fabric_name` is read from `rest_send.params`.

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.fabric_name
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, fabric_name="SITE1")
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    assert instance.fabric_name == "SITE1"


# =============================================================================
# Test: preflight_role_check
# =============================================================================


def test_fabric_prepare_update_00100() -> None:
    """
    # Summary

    Verify `preflight_role_check` passes for a single-role update group.

    ## Test

    - The summary reports `prep_leaf` with two `leaf` switches
    - `preflight_role_check` does not raise

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.preflight_role_check()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_prepare_update(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.preflight_role_check(["prep_leaf"])

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/softwareUpdatePlan/summary"
    assert rest_send.verb == HttpVerbEnum.GET.value


def test_fabric_prepare_update_00110() -> None:
    """
    # Summary

    Verify `preflight_role_check` raises for an update group that spans more than one switch role.

    ## Test

    - The summary reports `prep_mixed` containing a `leaf` and a `spine` switch
    - `preflight_role_check` raises `RuntimeError` naming both roles

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.preflight_role_check()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_prepare_update(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=r"prep_mixed.*mix of switch roles.*leaf, spine"):
        instance.preflight_role_check(["prep_mixed"])


def test_fabric_prepare_update_00120() -> None:
    """
    # Summary

    Verify `preflight_role_check` raises when a requested update group is absent from the summary.

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.preflight_role_check()
    - FabricPrepareUpdateOrchestrator._resolve_groups()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_prepare_update(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=r"missing_group.*not found in the software update plan"):
        instance.preflight_role_check(["missing_group"])


def test_fabric_prepare_update_00130() -> None:
    """
    # Summary

    Verify `get_summary` raises `RuntimeError` when the summary GET fails.

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.get_summary()
    - FabricPrepareUpdateOrchestrator._request()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_prepare_update(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=r"Request failed"):
        instance.get_summary()


# =============================================================================
# Test: status_snapshot
# =============================================================================


def test_fabric_prepare_update_00200() -> None:
    """
    # Summary

    Verify `status_snapshot` returns a per-group / per-switch status structure with switches sorted
    by name, and that `snapshot_fully_prepared` recognizes a fully staged + validated snapshot.

    ## Test

    - The summary reports `prep_leaf` fully staged and validated
    - The snapshot carries one group with two switches, name-sorted
    - `snapshot_fully_prepared` returns True for the snapshot

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.status_snapshot()
    - FabricPrepareUpdateOrchestrator.snapshot_fully_prepared()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_prepare_update(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    with does_not_raise():
        snapshot = instance.status_snapshot(["prep_leaf"])

    assert len(snapshot) == 1
    group = snapshot[0]
    assert group["update_group_name"] == "prep_leaf"
    assert group["stage_validate_percentage"] == 100
    assert [s["switch_name"] for s in group["switches"]] == ["leaf-1", "leaf-2"]
    assert group["switches"][0]["image_staged_status"] == "success"
    assert group["switches"][0]["image_validated_status"] == "success"
    assert FabricPrepareUpdateOrchestrator.snapshot_fully_prepared(snapshot) is True


def test_fabric_prepare_update_00210() -> None:
    """
    # Summary

    Verify `status_snapshot` raises when a requested update group is absent from the summary.

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.status_snapshot()
    - FabricPrepareUpdateOrchestrator._resolve_groups()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_prepare_update(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=r"prep_leaf.*not found in the software update plan"):
        instance.status_snapshot(["prep_leaf"])


def test_fabric_prepare_update_00220() -> None:
    """
    # Summary

    Verify `preflight_role_check` and `status_snapshot` reuse a caller-supplied `summary` rather
    than fetching it again, so the prepare-update startup costs a single summary GET.

    ## Test

    - The summary is fetched once via `get_summary`
    - That summary object is passed to both `preflight_role_check` and `status_snapshot`
    - Exactly one GET is issued across all three calls

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.get_summary()
    - FabricPrepareUpdateOrchestrator.preflight_role_check()
    - FabricPrepareUpdateOrchestrator.status_snapshot()
    """
    method_name = inspect.stack()[0][3]
    get_count = 0

    def responses():
        nonlocal get_count
        # Three identical summary responses are made available so a regression (a stray fetch in
        # preflight_role_check or status_snapshot) succeeds instead of raising on an exhausted
        # generator - the get_count assertion below is what catches the extra request.
        get_count += 1
        yield responses_fabric_prepare_update(f"{method_name}a")
        get_count += 1
        yield responses_fabric_prepare_update(f"{method_name}a")
        get_count += 1
        yield responses_fabric_prepare_update(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    with does_not_raise():
        summary = instance.get_summary()
        instance.preflight_role_check(["prep_leaf"], summary=summary)
        snapshot = instance.status_snapshot(["prep_leaf"], summary=summary)

    assert get_count == 1
    assert [group["update_group_name"] for group in snapshot] == ["prep_leaf"]


# =============================================================================
# Test: snapshot_fully_prepared (pure)
# =============================================================================


@pytest.mark.parametrize(
    "snapshot, expected",
    [
        ([{"switches": [{"image_staged_status": "success", "image_validated_status": "success"}]}], True),
        ([{"switches": [{"image_staged_status": "skipped", "image_validated_status": "success"}]}], True),
        ([{"switches": [{"image_staged_status": "success", "image_validated_status": "inProgress"}]}], False),
        ([{"switches": [{"image_staged_status": "none", "image_validated_status": "none"}]}], False),
        (
            [
                {"switches": [{"image_staged_status": "success", "image_validated_status": "success"}]},
                {"switches": [{"image_staged_status": "success", "image_validated_status": "failed"}]},
            ],
            False,
        ),
        ([], False),
        ([{"switches": []}], False),
    ],
    ids=["all-success", "skipped-ok", "validate-in-progress", "not-started", "one-group-failed", "empty-snapshot", "no-switches"],
)
def test_fabric_prepare_update_00300(snapshot: list, expected: bool) -> None:
    """
    # Summary

    Verify `snapshot_fully_prepared` returns True only when every switch in every group has reached
    a terminal-OK state for both the stage and validate phases.

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.snapshot_fully_prepared()
    """
    assert FabricPrepareUpdateOrchestrator.snapshot_fully_prepared(snapshot) is expected


@pytest.mark.parametrize(
    "staged, validated, prepared, failed",
    [
        ("success", "success", True, False),
        ("skipped", "success", True, False),
        ("inProgress", "none", False, False),
        ("failed", "none", False, True),
        ("success", "failed", False, True),
        ("none", "none", False, False),
    ],
    ids=["both-success", "skipped-staged", "in-progress", "stage-failed", "validate-failed", "not-started"],
)
def test_fabric_prepare_update_00310(staged: str, validated: str, prepared: bool, failed: bool) -> None:
    """
    # Summary

    Verify the `_switch_is_prepared` and `_switch_has_failed` per-switch status predicates.

    ## Classes and Methods

    - _switch_is_prepared()
    - _switch_has_failed()
    """
    switch = SwitchStageStatusModel(image_staged_status=staged, image_validated_status=validated)
    assert _switch_is_prepared(switch) is prepared
    assert _switch_has_failed(switch) is failed


# =============================================================================
# Test: stage
# =============================================================================


def test_fabric_prepare_update_00400() -> None:
    """
    # Summary

    Verify `stage` POSTs the stage action with the requested update group names.

    ## Test

    - `stage` is called with one update group name
    - The request is a POST to `.../softwareUpdatePlan/actions/stage`
    - The request body is `{"updateGroupNames": ["prep_leaf"]}`

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.stage()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_prepare_update(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.stage(["prep_leaf"])

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/softwareUpdatePlan/actions/stage"
    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.committed_payload == {"updateGroupNames": ["prep_leaf"]}


def test_fabric_prepare_update_00410() -> None:
    """
    # Summary

    Verify `stage` wraps a transport failure in `RuntimeError` naming the fabric.

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.stage()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_prepare_update(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=r"Failed to stage update group\(s\).*fabric 'fabric_1'"):
        instance.stage(["prep_leaf"])


# =============================================================================
# Test: wait_for_completion
# =============================================================================


def test_fabric_prepare_update_00500() -> None:
    """
    # Summary

    Verify `wait_for_completion` returns once every switch has staged and validated.

    ## Test

    - Poll 1 reports staging in progress; poll 2 reports staging complete
    - `wait_for_completion` polls twice and returns without raising

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.wait_for_completion()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_prepare_update(f"{method_name}a")
        yield responses_fabric_prepare_update(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.wait_for_completion(["prep_leaf"], timeout=300, interval=0)


def test_fabric_prepare_update_00510() -> None:
    """
    # Summary

    Verify `wait_for_completion` raises `RuntimeError` when a switch reports a staging failure.

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.wait_for_completion()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_prepare_update(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=r"Staging failed.*leaf-2=\[staged:failed"):
        instance.wait_for_completion(["prep_leaf"], timeout=300, interval=0)


def test_fabric_prepare_update_00520() -> None:
    """
    # Summary

    Verify `wait_for_completion` raises `RuntimeError` when staging does not complete within
    `timeout` seconds.

    ## Test

    - The summary reports staging still in progress
    - `timeout=0` forces the deadline to pass after the first poll
    - `wait_for_completion` raises a timeout `RuntimeError`

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.wait_for_completion()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_prepare_update(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=r"Timed out after 0s waiting for staging"):
        instance.wait_for_completion(["prep_leaf"], timeout=0, interval=0)


def test_fabric_prepare_update_00530() -> None:
    """
    # Summary

    Verify `wait_for_completion` retries a transient summary-poll failure rather than aborting.

    ## Test

    - Poll 1 fails with a transport error (HTTP 500)
    - Poll 2 recovers and reports staging in progress
    - Poll 3 reports staging complete
    - `wait_for_completion` rides through the failure and returns without raising

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.wait_for_completion()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_prepare_update(f"{method_name}a")
        yield responses_fabric_prepare_update(f"{method_name}b")
        yield responses_fabric_prepare_update(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.wait_for_completion(["prep_leaf"], timeout=300, interval=0)


def test_fabric_prepare_update_00540() -> None:
    """
    # Summary

    Verify `wait_for_completion` aborts when the summary poll fails more times in a row than the
    retry budget allows.

    ## Test

    - Four consecutive summary polls fail with a transport error (HTTP 500)
    - The fourth failure exceeds `_MAX_CONSECUTIVE_POLL_FAILURES` (3)
    - `wait_for_completion` raises `RuntimeError` reporting the consecutive-failure count

    ## Classes and Methods

    - FabricPrepareUpdateOrchestrator.wait_for_completion()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_prepare_update(f"{method_name}a")
        yield responses_fabric_prepare_update(f"{method_name}b")
        yield responses_fabric_prepare_update(f"{method_name}c")
        yield responses_fabric_prepare_update(f"{method_name}d")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = FabricPrepareUpdateOrchestrator(rest_send=rest_send)

    with pytest.raises(RuntimeError, match=r"failed 4 times in a row"):
        instance.wait_for_completion(["prep_leaf"], timeout=300, interval=0)
