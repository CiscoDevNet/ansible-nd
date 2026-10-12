# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Response-first breakout workflow tests, with real shared REST status handling.

The sender only returns recorded synthetic responses. These tests neither contact
a controller nor claim that synthetic response success proves device convergence.
Every call is recorded so an accidental retry, inventory scan, readback, or deploy
is visible instead of being hidden by a permissive REST mock.
"""

from __future__ import annotations

import copy
from ipaddress import ip_address
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_breakout_interfaces.breakout_interface import BreakoutInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_breakout_interfaces import (
    ManageBreakoutInterfacesOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_strategies.nd_v1_strategy import NdV1Strategy
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.modules.nd_manage_breakout_interfaces import _format_output
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

SERIAL = "FDO28481BXX"
OTHER_SERIAL = "FDO28481BYY"
BASE = "/api/v1/manage/fabrics/fab1"
BREAKOUT = BASE + "/interfaceActions/breakout"
REMOVE = BASE + "/interfaceActions/remove"
_DEFAULT_PLATFORM_INVENTORY = object()


class RecordingSender(Sender):
    """File sender with observable calls and an exhausted-fixture safety guard."""

    def __init__(self, responses):
        super().__init__()
        self.calls = []
        self.ansible_module = MockAnsibleModule()

        def scripted():
            for response in responses:
                yield response
            raise AssertionError("Unexpected REST call: fixture exhausted (possible retry/readback)")

        self.gen = ResponseGenerator(scripted())

    def commit(self):
        self.calls.append({"path": self.path, "verb": self.verb, "payload": copy.deepcopy(self.payload)})
        super().commit()

    @property
    def response(self):
        scripted = super().response
        if isinstance(scripted, BaseException):
            raise scripted
        return scripted


def response(data, *, code=200, method="GET"):
    """Wrap controller DATA in the shared Sender/ResponseHandler envelope."""
    return {"RETURN_CODE": code, "METHOD": method, "REQUEST_PATH": BASE, "MESSAGE": "OK", "DATA": data}


def inventory(serial=SERIAL, platform="nx-os", **row_fields):
    """Actual single-switch response with the platform preflight evidence."""
    return response({"switchId": serial, "additionalData": {"platformType": platform}, **row_fields})


def summary(*names, switch=SERIAL, **row_fields):
    """Only the classification fields supplied by a filtered summary query."""
    rows = [{"switchId": switch, "interfaceName": name, "interfaceType": "Ethernet", "physicalInterface": True, "fex": False, **row_fields} for name in names]
    return response({"interfaces": rows, "meta": {"counts": {"total": len(rows), "remaining": 0}}})


def item(name, *, switch=SERIAL, status="Success", message="Action completed"):
    return {"switchId": switch, "interfaceName": name, "status": status, "message": message}


def action(*items, code=207):
    return response({"results": list(items)}, code=code, method="POST")


def group(*names, switch=SERIAL, breakout_map="25g-4x"):
    config = {"switch_id": switch, "interface_names": list(names)}
    if breakout_map is not None:
        config["breakout_map"] = breakout_map
    return config


def run(
    responses,
    *,
    config=None,
    state="merged",
    check_mode=False,
    verify=None,
    config_actions=None,
    results=None,
    platform_inventory=_DEFAULT_PLATFORM_INVENTORY,
    fabric_name="fab1",
):
    """Run the public workflow through real RestSend and NdV1Strategy."""
    params = {
        "fabric_name": fabric_name,
        "state": state,
        "config": config if config is not None else [group("Ethernet1/50")],
        "check_mode": check_mode,
        "verify": verify or {"enabled": False},
    }
    if config_actions is not None:
        params["config_actions"] = config_actions
    # Serial-only workflows read each distinct switch's platform once before
    # interface discovery. Supply real wire responses and record every call;
    # do not patch the preflight or hide inventory from the returned trace.
    # IP tests explicitly supply additionalData.platformType in their lookup
    # response, so those rows are reused and need no separate inventory fixture.
    serials = []
    has_ip = False
    for entry in params["config"] if isinstance(params["config"], list) else []:
        switch = entry.get("switch_id") if isinstance(entry, dict) else None
        if not isinstance(switch, str) or not switch.strip():
            continue
        switch = switch.strip()
        try:
            ip_address(switch)
            has_ip = True
        except ValueError:
            if switch not in serials:
                serials.append(switch)
    if platform_inventory is _DEFAULT_PLATFORM_INVENTORY:
        platform_inventory = [inventory(serial) for serial in serials] if serials and not has_ip else None
    platform_responses = platform_inventory if isinstance(platform_inventory, list) else [platform_inventory] if platform_inventory is not None else []
    scripted = platform_responses + list(responses)
    sender = RecordingSender(scripted)
    handler = ResponseHandler()
    handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    handler.verb = HttpVerbEnum.GET
    handler.commit()
    assert isinstance(handler.validation_strategy, NdV1Strategy)
    rest_send = RestSend(params)
    rest_send.sender = sender
    rest_send.response_handler = handler
    rest_send.unit_test = True
    # A long budget reveals unwanted shared retries instead of hiding them with
    # a one-attempt fixture timeout; HTTP 207 failures must be terminal.
    rest_send.timeout = 600
    rest_send.send_interval = 1
    if results is not None:
        results.state = state
        results.check_mode = check_mode
    result = ManageBreakoutInterfacesOrchestrator(rest_send=rest_send, results=results).run()
    return result, sender.calls


def outcomes(result):
    return {(entry["switch_id"], entry["interface_name"]): entry for entry in result["api_outcomes"]}


def writes(calls):
    return [call for call in calls if call["verb"] == HttpVerbEnum.POST]


def assert_family_get(call, parent, switch=SERIAL):
    """Enforce targeted filters, not merely the GET verb or broad endpoint."""
    path = urlsplit(call["path"])
    query = parse_qs(path.query)
    assert call["verb"] == HttpVerbEnum.GET
    assert path.path == BASE + "/interfacesSummary"
    assert query["switchId"] == [switch]
    assert query["includeAll"] == ["true"]
    assert query["filter"] == ["interfaceName:*" + parent + "*"]


def test_complete_breakout_accepts_response_without_readback():
    result, calls = run([summary("Ethernet1/50"), action(item("Ethernet1/50"))])
    assert result["failed"] is False
    assert result["changed"] is True
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "success"
    assert result["after"][0]["requested_breakout_map"] == "25g-4x"
    assert result["after"][0]["evidence"] == "api_response"
    assert "breakout_map" not in result["after"][0]
    assert len(calls) == 3
    assert_family_get(calls[1], "Ethernet1/50")
    assert calls[2]["path"] == BREAKOUT
    assert calls[2]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": "Ethernet1/50", "breakoutMap": "25g-4x"}]}


def test_reordered_results_match_identity_not_position():
    result, calls = run(
        [summary("Ethernet1/50", "Ethernet1/51"), action(item("Ethernet1/51"), item("Ethernet1/50"))],
        config=[group("Ethernet1/50", "Ethernet1/51")],
    )
    assert result["failed"] is False
    assert {entry["outcome"] for entry in result["api_outcomes"]} == {"success"}
    assert len(calls) == 3
    assert_family_get(calls[1], "Ethernet1/5")
    assert len(writes(calls)) == 1


def test_same_interface_on_two_switches_matches_composite_identity():
    result, calls = run(
        [
            summary("Ethernet1/50"),
            summary("Ethernet1/50", switch=OTHER_SERIAL),
            action(item("Ethernet1/50", switch=OTHER_SERIAL, status="failed", message="Unsupported map"), item("Ethernet1/50")),
        ],
        config=[group("Ethernet1/50"), group("Ethernet1/50", switch=OTHER_SERIAL)],
    )
    assert result["failed"] is True
    assert result["changed"] is True
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "success"
    assert outcomes(result)[(OTHER_SERIAL, "Ethernet1/50")]["outcome"] == "failed"
    assert len(calls) == 5


def test_live_shaped_error_only_body_reports_missing_sibling_unknown():
    result, calls = run(
        [summary("Ethernet1/51", "Ethernet1/52"), action(item("Ethernet1/52", status="failed", message="Invalid parameter"))],
        config=[group("Ethernet1/51", "Ethernet1/52")],
    )
    assert result["failed"] is True
    assert result["may_have_changed"] is True
    assert outcomes(result)[(SERIAL, "Ethernet1/51")]["outcome"] == "unknown"
    assert outcomes(result)[(SERIAL, "Ethernet1/52")]["outcome"] == "failed"
    assert result["after_status"] == "unknown"
    assert len(calls) == 3  # No replay, GET reconciliation, or automatic deploy.


def test_success_and_missing_sibling_preserve_confirmed_success():
    result, calls = run(
        [summary("Ethernet1/50", "Ethernet1/51"), action(item("Ethernet1/50"))],
        config=[group("Ethernet1/50", "Ethernet1/51")],
    )
    assert result["changed"] is True
    assert result["failed"] is True
    assert result["may_have_changed"] is True
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "success"
    assert outcomes(result)[(SERIAL, "Ethernet1/51")]["outcome"] == "unknown"
    assert len(calls) == 3


@pytest.mark.parametrize("status", ["failed", "failure", "error"])
def test_explicit_failure_vocabulary_comes_from_shared_strategy(status):
    result, calls = run([summary("Ethernet1/50"), action(item("Ethernet1/50", status=status, message="Unsupported interface"))])
    assert result["failed"] is True
    assert result["may_have_changed"] is True
    assert result["after_status"] == "unknown"
    assert "after" not in result
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "failed"
    assert "Unsupported interface" in outcomes(result)[(SERIAL, "Ethernet1/50")]["message"]
    assert len(calls) == 3


@pytest.mark.parametrize("status", [" Success ", "SUCCESS", "success"])
def test_success_case_and_whitespace_use_shared_strategy(status):
    result, calls = run([summary("Ethernet1/50"), action(item("Ethernet1/50", status=status))])
    assert result["failed"] is False
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "success"
    assert len(calls) == 3


@pytest.mark.parametrize("body", [{}, {"results": None}, {"results": []}, {"results": {}}, {"results": "success"}, {"results": [None]}])
def test_missing_or_malformed_results_do_not_become_empty_success(body):
    result, calls = run([summary("Ethernet1/50"), response(body, code=207, method="POST")])
    assert result["failed"] is True
    assert result["may_have_changed"] is True
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "unknown"
    assert len(calls) == 3


@pytest.mark.parametrize(
    "reported",
    [
        item("Ethernet1/51"),
        item("Ethernet1/50", switch=OTHER_SERIAL),
        item(""),
        item("Ethernet1/50", switch=""),
        {"switchId": SERIAL, "status": "Success", "message": "No Commands to execute"},
    ],
)
def test_unidentifiable_or_foreign_results_never_confirm_requested_target(reported):
    result, calls = run([summary("Ethernet1/50"), action(reported)])
    assert result["failed"] is True
    assert result["may_have_changed"] is True
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "unknown"
    assert len(calls) == 3


def test_duplicate_response_identity_is_not_collapsed_into_success():
    result, calls = run([summary("Ethernet1/50"), action(item("Ethernet1/50"), item("Ethernet1/50"))])
    assert result["failed"] is True
    assert result["may_have_changed"] is True
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "unknown"
    assert len(calls) == 3


def test_deleted_maps_verified_child_response_back_to_requested_parent():
    result, calls = run(
        [summary("Ethernet1/50/4", "Ethernet1/50/2", "Ethernet1/50/1", "Ethernet1/50/3"), action(item("Ethernet1/50/1"))],
        config=[group("Ethernet1/50", breakout_map=None)],
        state="deleted",
    )
    target = outcomes(result)[(SERIAL, "Ethernet1/50")]
    assert target["outcome"] == "success"
    assert target["api_interface_name"] == "Ethernet1/50/1"
    assert calls[2]["path"] == REMOVE
    assert calls[2]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": "Ethernet1/50/1"}]}
    assert len(calls) == 3


def test_deleted_native_parent_is_noop_not_generic_interface_remove():
    result, calls = run([summary("Ethernet1/50")], state="deleted", config=[group("Ethernet1/50", breakout_map=None)])
    assert result["failed"] is False
    assert result["changed"] is False
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "noop"
    assert len(calls) == 2
    assert writes(calls) == []


def test_merged_broken_parent_is_noop_without_map_policy_query():
    result, calls = run([summary("Ethernet1/50/1", "Ethernet1/50/2")], config=[group("Ethernet1/50", breakout_map="50g-2x")])
    assert result["failed"] is False
    assert result["changed"] is False
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "noop"
    assert len(calls) == 2
    # No policy MAP retrieval; merged means ensure broken out, not replace map.
    assert "/policies" not in calls[1]["path"]


def test_contains_filter_excludes_other_families_and_subinterfaces_locally():
    result, calls = run([summary("Ethernet1/5", "Ethernet1/50/1", "Ethernet1/5.10"), action(item("Ethernet1/5"))], config=[group("Ethernet1/5")])
    assert result["failed"] is False
    assert calls[2]["payload"]["interfaces"][0]["interfaceName"] == "Ethernet1/5"
    assert_family_get(calls[1], "Ethernet1/5")


def test_check_mode_plans_unbreakout_without_any_write():
    result, calls = run(
        [summary("Ethernet1/50/1", "Ethernet1/50/2")],
        state="deleted",
        config=[group("Ethernet1/50", breakout_map=None)],
        check_mode=True,
    )
    assert result["failed"] is False
    assert result["changed"] is True
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "planned"
    assert len(calls) == 2
    assert writes(calls) == []


def test_partial_unbreakout_preserves_success_and_failure_without_followups():
    result, calls = run(
        [summary("Ethernet1/50/1", "Ethernet1/51/1"), action(item("Ethernet1/50/1"), item("Ethernet1/51/1", status="failed"))],
        state="deleted",
        config=[group("Ethernet1/50", "Ethernet1/51", breakout_map=None)],
    )
    assert result["failed"] is True
    assert result["changed"] is True
    assert [call["path"] for call in writes(calls)] == [REMOVE]


def test_bulk_unbreakout_excludes_native_noop_and_matches_reordered_children():
    result, calls = run(
        [
            summary("Ethernet1/50/2", "Ethernet1/50/10", "Ethernet1/51", "Ethernet1/52/4", "Ethernet1/52/1"),
            action(item("Ethernet1/52/1"), item("Ethernet1/50/2")),
        ],
        state="deleted",
        config=[group("Ethernet1/50", "Ethernet1/51", "Ethernet1/52", breakout_map=None)],
    )
    assert result["failed"] is False
    assert outcomes(result)[(SERIAL, "Ethernet1/51")]["outcome"] == "noop"
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["api_interface_name"] == "Ethernet1/50/2"
    assert outcomes(result)[(SERIAL, "Ethernet1/52")]["api_interface_name"] == "Ethernet1/52/1"
    assert calls[2]["payload"] == {
        "interfaces": [
            {"switchId": SERIAL, "interfaceName": "Ethernet1/50/2"},
            {"switchId": SERIAL, "interfaceName": "Ethernet1/52/1"},
        ]
    }
    assert len(calls) == 3


def test_unbreakout_result_for_parent_does_not_confirm_submitted_child():
    result, calls = run(
        [summary("Ethernet1/50/1"), action(item("Ethernet1/50"))],
        state="deleted",
        config=[group("Ethernet1/50", breakout_map=None)],
    )
    assert result["failed"] is True
    assert result["may_have_changed"] is True
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "unknown"
    assert len(calls) == 3


def test_nonphysical_ghost_parent_does_not_hide_actual_breakout_children():
    rows = [
        {"switchId": SERIAL, "interfaceName": "Ethernet1/50", "physicalInterface": False, "fex": False},
        {"switchId": SERIAL, "interfaceName": "Ethernet1/50/1", "physicalInterface": True, "fex": False},
    ]
    result, calls = run(
        [response({"interfaces": rows, "meta": {"counts": {"remaining": 0}}}), action(item("Ethernet1/50/1"))],
        state="deleted",
        config=[group("Ethernet1/50", breakout_map=None)],
    )
    assert result["failed"] is False
    assert writes(calls)[0]["payload"]["interfaces"][0]["interfaceName"] == "Ethernet1/50/1"


def test_physical_parent_with_physical_children_fails_closed_without_mutation():
    result, calls = run([summary("Ethernet1/50", "Ethernet1/50/1")])
    assert result["failed"] is True
    assert result["changed"] is False
    assert writes(calls) == []


def test_action_uses_existing_shared_retry_then_matches_completed_response():
    trace = Results()
    result, calls = run(
        [summary("Ethernet1/50"), response({"message": "Internal server error"}, code=500, method="POST"), action(item("Ethernet1/50"))],
        results=trace,
    )
    assert result["failed"] is False
    assert result["changed"] is True
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "success"
    assert len(calls) == 4
    posts = writes(calls)
    assert len(posts) == 2
    assert posts[0] == posts[1]
    assert posts[0]["path"] == BREAKOUT
    assert posts[0]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": "Ethernet1/50", "breakoutMap": "25g-4x"}]}
    # Standard RestSend registers the completed logical commit, not each retry.
    assert trace.path == [calls[0]["path"], calls[1]["path"], BREAKOUT]
    assert [entry["RETURN_CODE"] for entry in trace.responses] == [200, 200, 207]
    assert len(result["api_calls"]) == 3
    assert result["api_calls"][2]["response_received"] is True
    assert result["api_calls"][2]["http_status"] == 207


def test_verification_is_opt_in_focused_topology_not_map_fetch():
    result, calls = run(
        [summary("Ethernet1/50"), action(item("Ethernet1/50")), summary("Ethernet1/50/1", "Ethernet1/50/2")],
        verify={"enabled": True},
    )
    assert result["failed"] is False
    assert result["after_status"] == "observed"
    assert len(calls) == 4
    assert_family_get(calls[3], "Ethernet1/50")
    assert all("/policies" not in call["path"] for call in calls)


def test_optional_observation_does_not_erase_missing_result_error():
    result, calls = run(
        [summary("Ethernet1/50"), action(), summary("Ethernet1/50/1", "Ethernet1/50/2")],
        verify={"enabled": True},
    )
    assert result["failed"] is True
    assert result["after_status"] == "observed"
    assert len(calls) == 4
    assert_family_get(calls[3], "Ethernet1/50")


def test_check_mode_skips_optional_verification_even_when_enabled():
    result, calls = run([summary("Ethernet1/50")], check_mode=True, verify={"enabled": True})
    assert result["failed"] is False
    assert result["after_status"] == "predicted"
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "planned"
    assert len(calls) == 2


def test_repeated_management_ip_is_cached_and_resolved_with_targeted_filter():
    ip = "10.127.117.189"
    result, calls = run(
        [
            response(
                {
                    "switches": [{"switchId": SERIAL, "fabricManagementIp": ip, "additionalData": {"platformType": "nx-os"}}],
                    "meta": {"counts": {"remaining": 0}},
                }
            ),
            summary("Ethernet1/50", "Ethernet1/51"),
            action(item("Ethernet1/50"), item("Ethernet1/51")),
        ],
        config=[group("Ethernet1/50", switch=ip), group("Ethernet1/51", switch=ip)],
    )
    assert result["failed"] is False
    assert len(calls) == 3
    lookup = urlsplit(calls[0]["path"])
    assert lookup.path == BASE + "/switches"
    assert parse_qs(lookup.query)["filter"] == ["fabricManagementIp:" + ip]
    assert {entry["switch_id"] for entry in result["api_outcomes"]} == {SERIAL}
    assert {entry["switchId"] for entry in calls[2]["payload"]["interfaces"]} == {SERIAL}


def test_input_canonicalization_does_not_change_user_config():
    config = [group(" ethernet01/050 ", switch=" " + SERIAL + " ", breakout_map=" 25G-4X ")]
    original = copy.deepcopy(config)
    result, calls = run([summary("Ethernet1/50"), action(item("Ethernet1/50"))], config=config)
    assert result["failed"] is False
    assert config == original
    assert calls[2]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": "Ethernet1/50", "breakoutMap": "25g-4x"}]}


def test_missing_outcome_suppresses_deleted_followup_actions():
    result, calls = run(
        [summary("Ethernet1/50/1", "Ethernet1/51/1"), action(item("Ethernet1/50/1"))],
        state="deleted",
        config=[group("Ethernet1/50", "Ethernet1/51", breakout_map=None)],
    )
    assert result["failed"] is True
    assert result["changed"] is True
    assert result["may_have_changed"] is True
    assert [call["path"] for call in writes(calls)] == [REMOVE]


def test_unrequested_extra_result_is_exposed_as_contract_failure():
    result, calls = run([summary("Ethernet1/50"), action(item("Ethernet1/50"), item("Ethernet1/99"))])
    assert result["failed"] is True
    assert result["changed"] is True
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "success"
    assert len(calls) == 3


def test_two_disjoint_parent_families_are_narrow_queries_and_one_bulk_action():
    result, calls = run(
        [summary("Ethernet1/11"), summary("Ethernet1/48"), action(item("Ethernet1/48"), item("Ethernet1/11"))],
        config=[group("Ethernet1/11"), group("Ethernet1/48", breakout_map="50g-2x")],
    )
    assert result["failed"] is False
    assert len(calls) == 4
    assert_family_get(calls[1], "Ethernet1/11")
    assert_family_get(calls[2], "Ethernet1/48")
    assert calls[3]["payload"] == {
        "interfaces": [
            {"switchId": SERIAL, "interfaceName": "Ethernet1/11", "breakoutMap": "25g-4x"},
            {"switchId": SERIAL, "interfaceName": "Ethernet1/48", "breakoutMap": "50g-2x"},
        ]
    }


def test_filtered_summary_pagination_finishes_before_selecting_child():
    first_page = response(
        {
            "interfaces": [{"switchId": SERIAL, "interfaceName": "Ethernet1/50/3", "physicalInterface": True, "fex": False}],
            "meta": {"counts": {"total": 2, "remaining": 1}},
        }
    )
    result, calls = run(
        [first_page, summary("Ethernet1/50/1"), action(item("Ethernet1/50/1"))],
        state="deleted",
        config=[group("Ethernet1/50", breakout_map=None)],
    )
    assert result["failed"] is False
    assert len(calls) == 4
    assert parse_qs(urlsplit(calls[1]["path"]).query)["offset"] == ["0"]
    assert parse_qs(urlsplit(calls[2]["path"]).query)["offset"] == ["1"]
    assert calls[3]["payload"]["interfaces"][0]["interfaceName"] == "Ethernet1/50/1"


def test_transport_exception_is_unknown_without_replaying_mutation():
    result, calls = run([summary("Ethernet1/50"), TimeoutError("Controller action response was lost")])
    assert result["failed"] is True
    assert result["may_have_changed"] is True
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "unknown"
    assert "Controller action response was lost" in result["msg"]
    assert len(calls) == 3
    assert len(writes(calls)) == 1


def test_optional_verification_is_not_attempted_after_aborted_action():
    result, calls = run(
        [summary("Ethernet1/50"), TimeoutError("Controller action response was lost"), summary("Ethernet1/50/1")],
        verify={"enabled": True},
    )
    assert result["failed"] is True
    assert result["may_have_changed"] is True
    assert result["after_status"] == "unknown"
    assert "after" not in result
    assert result["verification"] == {"enabled": True, "complete": False}
    assert "Optional topology verification was not attempted because the action request did not complete." in result["msg"]
    assert len(calls) == 3
    assert len(writes(calls)) == 1


def test_duplicate_user_targets_fail_validation_before_any_api():
    result, calls = run([], config=[group("Ethernet1/50", "ethernet01/050")])
    assert result["failed"] is True
    assert result["changed"] is False
    assert calls == []


def test_ip_and_serial_aliases_for_same_parent_fail_before_discovery():
    ip = "10.127.117.189"
    result, calls = run(
        [
            response(
                {
                    "switches": [{"switchId": SERIAL, "fabricManagementIp": ip, "additionalData": {"platformType": "nx-os"}}],
                    "meta": {"counts": {"remaining": 0}},
                }
            )
        ],
        config=[group("Ethernet1/50", switch=ip), group("Ethernet1/50")],
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert len(calls) == 1
    assert "/switches?" in calls[0]["path"]
    assert writes(calls) == []


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("config_actions", [{}, {"save": True}, {"save": True, "deploy": True, "type": "switch"}])
def test_config_actions_are_explicitly_unsupported_before_any_api(state, config_actions):
    result, calls = run(
        [],
        state=state,
        config=[group("Ethernet1/50", breakout_map=None if state == "deleted" else "25g-4x")],
        config_actions=config_actions,
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert "config_actions" in result["msg"]
    assert calls == []


def test_completed_unbreakout_does_not_save_recalculate_or_deploy():
    result, calls = run(
        [summary("Ethernet1/50/1"), action(item("Ethernet1/50/1"))],
        state="deleted",
        config=[group("Ethernet1/50", breakout_map=None)],
    )
    assert result["failed"] is False
    assert result["changed"] is True
    assert [call["path"] for call in writes(calls)] == [REMOVE]
    assert len(calls) == 3


@pytest.mark.parametrize("status", [None, "", 1, "warning", "notExecuted", "arbitrary"])
def test_missing_or_unrecognized_item_status_is_unknown_not_success(status):
    result, calls = run([summary("Ethernet1/50"), action(item("Ethernet1/50", status=status))])
    assert result["failed"] is True
    assert result["may_have_changed"] is True
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "unknown"
    assert len(calls) == 3


def test_opt_in_verification_reads_only_mutated_not_noop_families():
    result, calls = run(
        [summary("Ethernet1/50/1", "Ethernet1/51"), action(item("Ethernet1/50/1")), summary("Ethernet1/50")],
        state="deleted",
        config=[group("Ethernet1/50", "Ethernet1/51", breakout_map=None)],
        verify={"enabled": True},
    )
    assert result["failed"] is False
    assert result["after_status"] == "partially_observed"
    assert result["verification"]["scope"] == [(SERIAL, "Ethernet1/50")]
    after = {(entry["switch_id"], entry["interface_name"]): entry for entry in result["after"]}
    assert after[(SERIAL, "Ethernet1/50")]["evidence"] == "post_action_discovery"
    assert after[(SERIAL, "Ethernet1/51")]["evidence"] == "initial_discovery"
    assert outcomes(result)[(SERIAL, "Ethernet1/51")]["outcome"] == "noop"
    assert len(calls) == 4
    assert_family_get(calls[1], "Ethernet1/5")
    assert_family_get(calls[3], "Ethernet1/50")


def test_noop_does_not_trigger_opt_in_post_action_verification():
    result, calls = run(
        [summary("Ethernet1/50")],
        state="deleted",
        config=[group("Ethernet1/50", breakout_map=None)],
        verify={"enabled": True},
    )
    assert result["failed"] is False
    assert result["changed"] is False
    assert result["after_status"] == "unchanged"
    assert len(calls) == 2


def test_failed_optional_verification_keeps_confirmed_action_and_uncertainty():
    result, calls = run(
        [summary("Ethernet1/50"), action(item("Ethernet1/50")), response({"message": "Not found"}, code=404)],
        verify={"enabled": True},
    )
    assert result["failed"] is True
    assert result["changed"] is True
    assert result["may_have_changed"] is True
    assert result["after_status"] == "unknown"
    assert "after" not in result
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "success"
    assert result["verification"]["complete"] is False
    assert len(calls) == 4


@pytest.mark.parametrize("status", ["Success", "warning", "notExecuted", "arbitrary", None])
def test_http200_action_items_still_use_strict_shared_multistatus_vocabulary(status):
    reported = item("Ethernet1/50", status=status)
    if status is None:
        reported.pop("status")
    result, calls = run([summary("Ethernet1/50"), action(reported, code=200)])
    expected_success = status == "Success"
    assert result["failed"] is not expected_success
    assert result["changed"] is expected_success
    assert result["may_have_changed"] is not expected_success
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == ("success" if expected_success else "unknown")
    assert len(calls) == 3


def test_http202_accepted_does_not_prove_breakout_action_completed():
    result, calls = run([summary("Ethernet1/50"), action(item("Ethernet1/50"), code=202)])
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["may_have_changed"] is True
    assert result["after_status"] == "unknown"
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "unknown"
    assert len(calls) == 3


def test_transport_http500_does_not_trust_success_named_in_error_body():
    result, calls = run([summary("Ethernet1/50"), action(item("Ethernet1/50"), code=500), TimeoutError("Lost retry response")])
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["may_have_changed"] is True
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "unknown"
    assert len(calls) == 4
    assert len(writes(calls)) == 2
    assert writes(calls)[0] == writes(calls)[1]


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize(
    "flags",
    [
        {"physicalInterface": True},
        {"fex": False},
        {"physicalInterface": None, "fex": False},
        {"physicalInterface": "true", "fex": False},
        {"physicalInterface": 1, "fex": False},
        {"physicalInterface": True, "fex": None},
        {"physicalInterface": True, "fex": "false"},
        {"physicalInterface": True, "fex": 0},
    ],
)
def test_incomplete_or_untyped_child_topology_flags_fail_before_mutation(state, flags):
    row = {"switchId": SERIAL, "interfaceName": "Ethernet1/50/1", **flags}
    result, calls = run(
        [response({"interfaces": [row], "meta": {"counts": {"remaining": 0}}})],
        state=state,
        config=[group("Ethernet1/50", breakout_map=None if state == "deleted" else "25g-4x")],
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["may_have_changed"] is False
    assert "physicalInterface/fex" in result["msg"]
    assert len(calls) == 2
    assert writes(calls) == []


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_fex_child_is_not_a_supported_breakout_child(state):
    result, calls = run(
        [summary("Ethernet1/50/1", fex=True)],
        state=state,
        config=[group("Ethernet1/50", breakout_map=None if state == "deleted" else "25g-4x")],
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert "FEX interface" in result["msg"]
    assert len(calls) == 2
    assert writes(calls) == []


def test_total_count_without_remaining_finishes_short_pages_before_action():
    first_page = response(
        {
            "interfaces": [{"switchId": SERIAL, "interfaceName": "Ethernet1/50/1", "physicalInterface": True, "fex": False}],
            "meta": {"counts": {"total": 2}},
        }
    )
    second_page = response(
        {
            "interfaces": [{"switchId": SERIAL, "interfaceName": "Ethernet1/50/2", "physicalInterface": True, "fex": False}],
            "meta": {"counts": {"total": 2}},
        }
    )
    result, calls = run(
        [first_page, second_page, action(item("Ethernet1/50/1"))],
        state="deleted",
        config=[group("Ethernet1/50", breakout_map=None)],
    )
    assert result["failed"] is False
    assert result["before"][0]["children"] == ["Ethernet1/50/1", "Ethernet1/50/2"]
    assert len(calls) == 4
    assert [call["verb"] for call in calls] == [HttpVerbEnum.GET, HttpVerbEnum.GET, HttpVerbEnum.GET, HttpVerbEnum.POST]
    assert parse_qs(urlsplit(calls[2]["path"]).query)["offset"] == ["1"]
    assert len(writes(calls)) == 1


@pytest.mark.parametrize(
    "meta",
    [
        None,
        [],
        "invalid",
        {"counts": None},
        {"counts": []},
        {"counts": "invalid"},
        {"counts": {"total": None}},
        {"counts": {"total": -1}},
        {"counts": {"total": True}},
        {"counts": {"total": "2"}},
        {"counts": {"total": 1.5}},
        {"counts": {"remaining": None}},
        {"counts": {"remaining": -1}},
        {"counts": {"remaining": True}},
        {"counts": {"remaining": "2"}},
        {"counts": {"remaining": 1.5}},
    ],
)
def test_malformed_pagination_metadata_fails_before_any_mutation(meta):
    row = {"switchId": SERIAL, "interfaceName": "Ethernet1/50", "physicalInterface": True, "fex": False}
    result, calls = run([response({"interfaces": [row], "meta": meta})])
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["may_have_changed"] is False
    assert "pagination" in result["msg"]
    assert len(calls) == 2
    assert writes(calls) == []


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_confirmed_initial_zero_envelope_is_missing_family_not_malformed_or_noop(state, check_mode):
    result, calls = run(
        [response({"meta": {"counts": {"total": 0, "remaining": 0}}})],
        state=state,
        check_mode=check_mode,
        config=[group("Ethernet1/50", breakout_map=None if state == "deleted" else "25g-4x")],
    )
    assert result["failed"] and not result["changed"] and not result["may_have_changed"]
    assert "Neither native parent nor breakout children found" in result["msg"]
    assert result["api_outcomes"] == [] and result["diff"] == []
    assert len(calls) == 2 and not writes(calls)


def test_confirmed_initial_zero_envelope_does_not_make_missing_child_family_a_noop():
    result, calls = run(
        [response({"meta": {"counts": {"total": 0, "remaining": 0}}})],
        state="deleted",
        config=[group("Ethernet1/50/2", breakout_map=None)],
    )
    assert result["failed"] and not result["changed"]
    assert "Neither native parent nor breakout children found" in result["msg"]
    assert len(calls) == 2 and not writes(calls)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"meta": None},
        {"meta": []},
        {"meta": {}},
        {"meta": {"counts": None}},
        {"meta": {"counts": []}},
        {"meta": {"counts": {}}},
        {"meta": {"counts": {"total": 0}}},
        {"meta": {"counts": {"remaining": 0}}},
        {"meta": {"counts": {"total": False, "remaining": 0}}},
        {"meta": {"counts": {"total": 0, "remaining": False}}},
        {"meta": {"counts": {"total": True, "remaining": 0}}},
        {"meta": {"counts": {"total": 0, "remaining": True}}},
        {"meta": {"counts": {"total": 0.0, "remaining": 0}}},
        {"meta": {"counts": {"total": 0, "remaining": 0.0}}},
        {"meta": {"counts": {"total": "0", "remaining": 0}}},
        {"meta": {"counts": {"total": 0, "remaining": None}}},
        {"meta": {"counts": {"total": 1, "remaining": 0}}},
        {"meta": {"counts": {"total": 0, "remaining": 1}}},
        {"meta": {"counts": {"total": -1, "remaining": 0}}},
    ],
)
def test_omitted_interface_array_requires_both_explicit_integer_zero_counts(body):
    result, calls = run([response(body)])
    assert result["failed"] and not result["changed"] and not result["may_have_changed"]
    assert "interfaces array" in result["msg"]
    assert len(calls) == 2 and not writes(calls)


@pytest.mark.parametrize("rows", [None, {}, "", [None]])
def test_explicit_invalid_interface_array_is_not_replaced_by_zero_count_empty_page(rows):
    result, calls = run([response({"interfaces": rows, "meta": {"counts": {"total": 0, "remaining": 0}}})])
    assert result["failed"] and "interfaces array" in result["msg"]
    assert not result["changed"] and len(calls) == 2 and not writes(calls)


def test_omitted_interface_array_with_zero_counts_is_invalid_on_later_page():
    initial = summary("Ethernet1/50")
    initial["DATA"]["meta"]["counts"] = {"total": 2, "remaining": 1}
    result, calls = run([initial, response({"meta": {"counts": {"total": 0, "remaining": 0}}})])
    assert result["failed"] and "interfaces array" in result["msg"]
    assert not result["changed"] and not result["may_have_changed"]
    assert len(calls) == 3 and not writes(calls)
    assert parse_qs(urlsplit(calls[-1]["path"]).query)["offset"] == ["1"]


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_modified_false_is_authoritative_even_for_correlated_success(state):
    api_name = "Ethernet1/50" if state == "merged" else "Ethernet1/50/1"
    reply = action(item(api_name))
    reply["modified"] = "false"
    result, calls = run(
        [summary(api_name), reply],
        state=state,
        config=[group("Ethernet1/50", breakout_map=None if state == "deleted" else "25g-4x")],
    )
    assert result["failed"] is False
    assert result["changed"] is False
    assert result["may_have_changed"] is False
    assert result["after_status"] == "response_confirmed"
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "success"
    assert len(calls) == 3


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("unknown_kind", ["missing_result", "unrecognized_status"])
def test_modified_true_reports_changed_even_when_target_outcome_is_unknown(state, unknown_kind):
    api_name = "Ethernet1/50" if state == "merged" else "Ethernet1/50/1"
    reply = action() if unknown_kind == "missing_result" else action(item(api_name, status="warning"))
    reply["modified"] = "true"
    result, calls = run(
        [summary(api_name), reply],
        state=state,
        config=[group("Ethernet1/50", breakout_map=None if state == "deleted" else "25g-4x")],
    )
    assert result["failed"] is True
    assert result["changed"] is True
    assert result["may_have_changed"] is True
    assert result["after_status"] == "unknown"
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "unknown"
    assert len(calls) == 3


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_modified_false_is_authoritative_for_mixed_success_and_failure(state):
    first = "Ethernet1/50" if state == "merged" else "Ethernet1/50/1"
    second = "Ethernet1/51" if state == "merged" else "Ethernet1/51/1"
    reply = action(item(first), item(second, status="failed", message="Unsupported interface"))
    reply["modified"] = "false"
    result, calls = run(
        [summary(first, second), reply],
        state=state,
        config=[group("Ethernet1/50", "Ethernet1/51", breakout_map=None if state == "deleted" else "25g-4x")],
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["may_have_changed"] is True
    assert result["after_status"] == "unknown"
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "success"
    assert outcomes(result)[(SERIAL, "Ethernet1/51")]["outcome"] == "failed"
    assert len(calls) == 3


def test_group_discovery_indexes_exact_families_before_each_classifier(monkeypatch):
    received_families = {}
    original_classifier = ManageBreakoutInterfacesOrchestrator._classify

    def recording_classifier(model, rows):
        received_families[model.interface_name] = [row["interfaceName"] for row in rows]
        return original_classifier(model, rows)

    monkeypatch.setattr(ManageBreakoutInterfacesOrchestrator, "_classify", staticmethod(recording_classifier))
    result, calls = run(
        [
            summary(
                "Ethernet1/50",
                "Ethernet1/51/1",
                "Ethernet1/5",
                "Ethernet1/500",
                "Ethernet1/500/1",
                "Ethernet1/50.100",
                "Ethernet1/51/1.100",
                "Ethernet1/51/1/1",
            ),
            action(item("Ethernet1/50")),
        ],
        config=[group("Ethernet1/50", "Ethernet1/51")],
    )
    assert result["failed"] is False
    assert received_families == {"Ethernet1/50": ["Ethernet1/50"], "Ethernet1/51": ["Ethernet1/51/1"]}
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["outcome"] == "success"
    assert outcomes(result)[(SERIAL, "Ethernet1/51")]["outcome"] == "noop"
    assert len(calls) == 3
    assert_family_get(calls[1], "Ethernet1/5")
    assert calls[2]["payload"]["interfaces"] == [{"switchId": SERIAL, "interfaceName": "Ethernet1/50", "breakoutMap": "25g-4x"}]


def test_disjoint_ranges_still_batch_nearby_parents_and_preserve_input_order():
    result, calls = run(
        [
            summary("Ethernet1/50", "Ethernet1/51"),
            summary("Ethernet1/21"),
            action(item("Ethernet1/51", message="Reported 51"), item("Ethernet1/21", message="Reported 21"), item("Ethernet1/50", message="Reported 50")),
        ],
        config=[group("Ethernet1/50", "Ethernet1/21", "Ethernet1/51")],
    )
    assert result["failed"] is False
    assert len(calls) == 4
    assert_family_get(calls[1], "Ethernet1/5")
    assert_family_get(calls[2], "Ethernet1/21")
    assert calls[3]["payload"] == {
        "interfaces": [
            {"switchId": SERIAL, "interfaceName": "Ethernet1/50", "breakoutMap": "25g-4x"},
            {"switchId": SERIAL, "interfaceName": "Ethernet1/21", "breakoutMap": "25g-4x"},
            {"switchId": SERIAL, "interfaceName": "Ethernet1/51", "breakoutMap": "25g-4x"},
        ]
    }
    assert [entry["interface_name"] for entry in result["api_outcomes"]] == ["Ethernet1/50", "Ethernet1/21", "Ethernet1/51"]
    assert [entry["message"] for entry in result["api_outcomes"]] == ["Reported 50", "Reported 21", "Reported 51"]
    assert len(writes(calls)) == 1


def test_discovery_buckets_never_combine_different_slots_or_switches():
    selectors = [
        (SERIAL, "Ethernet1/50"),
        (OTHER_SERIAL, "Ethernet1/50"),
        (SERIAL, "Ethernet2/50"),
        (SERIAL, "Ethernet1/51"),
        (OTHER_SERIAL, "Ethernet1/51"),
        (SERIAL, "Ethernet2/51"),
    ]
    models = [BreakoutInterfaceModel(switch_id=switch, interface_name=name, breakout_map="25g-4x") for switch, name in selectors]
    grouped = ManageBreakoutInterfacesOrchestrator.discovery_groups(models)
    assert [(switch, filter_text, [target.interface_name for target in targets]) for switch, filter_text, targets in grouped] == [
        (SERIAL, "interfaceName:*Ethernet1/5*", ["Ethernet1/50", "Ethernet1/51"]),
        (OTHER_SERIAL, "interfaceName:*Ethernet1/5*", ["Ethernet1/50", "Ethernet1/51"]),
        (SERIAL, "interfaceName:*Ethernet2/5*", ["Ethernet2/50", "Ethernet2/51"]),
    ]


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("scenario", ["success", "noop", "check_mode", "mixed_action_noop", "initial_error", "action_error"])
def test_proposed_and_diff_are_grouped_input_intent_not_api_child_names(state, scenario):
    expected = group("Ethernet1/50", "Ethernet1/51", breakout_map=None if state == "deleted" else "25g-4x")
    native = state == "merged"
    if scenario == "noop":
        native = not native
    first = "Ethernet1/50" if native else "Ethernet1/50/1"
    second = "Ethernet1/51" if native else "Ethernet1/51/1"
    if scenario == "mixed_action_noop":
        second = "Ethernet1/51/1" if state == "merged" else "Ethernet1/51"
    scripted = [summary(first, second)]
    if scenario == "initial_error":
        scripted = [summary()]
    elif scenario in {"success", "mixed_action_noop", "action_error"}:
        status = "failed" if scenario == "action_error" else "Success"
        posted_names = [first] if scenario == "mixed_action_noop" else [first, second]
        scripted.append(action(*(item(name, status=status) for name in posted_names)))
    result, calls = run(scripted, state=state, config=[expected], check_mode=scenario == "check_mode")
    assert result["proposed"] == [expected]
    if scenario in {"noop", "initial_error"}:
        assert result["diff"] == []
    elif scenario == "mixed_action_noop":
        assert result["diff"] == [group("Ethernet1/50", breakout_map=None if state == "deleted" else "25g-4x")]
    else:
        assert result["diff"] == [expected]
    assert result["failed"] is (scenario in {"initial_error", "action_error"})
    assert len(calls) == (3 if scenario in {"success", "mixed_action_noop", "action_error"} else 2)
    assert all("interface_name" not in entry and "api_interface_name" not in entry for entry in result["proposed"] + result["diff"])


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_proposed_diff_group_by_resolved_switch_and_requested_map(state):
    names = ["Ethernet1/50", "Ethernet1/21", "Ethernet1/51"]
    api_names = names if state == "merged" else [name + "/1" for name in names]
    config = [
        group(names[0], breakout_map=None if state == "deleted" else "25g-4x"),
        group(names[1], breakout_map=None if state == "deleted" else "50g-2x"),
        group(names[2], breakout_map=None if state == "deleted" else "25g-4x"),
    ]
    result, calls = run(
        [summary(api_names[0], api_names[2]), summary(api_names[1]), action(*(item(name) for name in api_names))],
        state=state,
        config=config,
    )
    expected = (
        [group(names[0], names[2], breakout_map="25g-4x"), group(names[1], breakout_map="50g-2x")] if state == "merged" else [group(*names, breakout_map=None)]
    )
    assert result["failed"] is False
    assert result["proposed"] == expected
    assert result["diff"] == expected
    assert len(calls) == 4


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_proposed_diff_normalize_ip_to_serial_then_regroup_alias_targets(state):
    ip = "10.127.117.189"
    names = ["Ethernet1/50", "Ethernet1/51"]
    api_names = names if state == "merged" else [name + "/1" for name in names]
    result, calls = run(
        [
            response(
                {
                    "switches": [{"switchId": SERIAL, "fabricManagementIp": ip, "additionalData": {"platformType": "nx-os"}}],
                    "meta": {"counts": {"remaining": 0}},
                }
            ),
            summary(*api_names),
            action(*(item(name) for name in api_names)),
        ],
        state=state,
        config=[
            group(" ethernet01/050 ", breakout_map=None if state == "deleted" else " 25G-4X "),
            group(" ethernet01/051 ", switch=" " + ip + " ", breakout_map=None if state == "deleted" else "25g-4x"),
        ],
    )
    expected = [group(*names, breakout_map=None if state == "deleted" else "25g-4x")]
    assert result["failed"] is False
    assert result["proposed"] == expected
    assert result["diff"] == expected
    assert len(calls) == 3


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_ip_resolution_error_keeps_normalized_original_selector_proposed_only(state):
    ip = "10.127.117.189"
    expected = [group("Ethernet1/50", switch=ip, breakout_map=None if state == "deleted" else "25g-4x")]
    result, calls = run(
        [response({"switches": [], "meta": {"counts": {"remaining": 0}}})],
        state=state,
        config=[group(" ethernet01/050 ", switch=" " + ip + " ", breakout_map=None if state == "deleted" else " 25G-4X ")],
    )
    assert result["failed"] is True
    assert result["proposed"] == expected
    assert result["diff"] == []
    assert "after" not in result
    assert len(calls) == 1


def assert_registered_calls(trace, calls, expected_operations, *, state="merged", check_mode=False):
    """Check actual shared Results capture, including raw handler outcomes."""
    assert trace.path == [call["path"] for call in calls]
    assert trace.verb == [call["verb"].value for call in calls]
    assert trace.payload == [call["payload"] for call in calls]
    assert trace.verbosity_level == [3 if call["verb"] == HttpVerbEnum.GET else 2 for call in calls]
    assert [metadata["action"] for metadata in trace.metadata] == [operation.value for operation in expected_operations]
    assert [metadata["sequence_number"] for metadata in trace.metadata] == list(range(1, len(calls) + 1))
    assert [metadata["state"] for metadata in trace.metadata] == [state] * len(calls)
    assert [metadata["check_mode"] for metadata in trace.metadata] == [check_mode] * len(calls)
    assert len(trace.results) == len(calls)
    assert len(trace.responses) == len(calls)


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("outcome", ["success", "partial", "failed", "noop"])
def test_shared_results_register_all_response_calls_with_expected_verbosity(state, outcome):
    trace = Results()
    native = state == "merged"
    if outcome == "noop":
        native = not native
    names = ["Ethernet1/50", "Ethernet1/51"]
    api_names = names if native else [name + "/1" for name in names]
    scripted = [summary(*api_names)]
    statuses = ["Success", "Success"] if outcome == "success" else ["Success", "failed"] if outcome == "partial" else ["failed", "failed"]
    if outcome != "noop":
        scripted.append(action(*(item(name, status=status) for name, status in zip(api_names, statuses))))
    result, calls = run(scripted, state=state, config=[group(*names, breakout_map=None if state == "deleted" else "25g-4x")], results=trace)
    operations = [OperationType.QUERY, OperationType.QUERY]
    if outcome != "noop":
        operations.append(OperationType.CREATE if state == "merged" else OperationType.DELETE)
    assert_registered_calls(trace, calls, operations, state=state)
    assert trace.results[1]["success"] is True
    assert trace.responses[1]["DATA"]["interfaces"] == scripted[0]["DATA"]["interfaces"]
    if outcome != "noop":
        assert trace.results[2]["success"] is (outcome == "success")
        assert trace.responses[2]["DATA"]["results"] == scripted[1]["DATA"]["results"]
    assert result["failed"] is (outcome in {"partial", "failed"})
    assert len(calls) == (2 if outcome == "noop" else 3)


def test_cached_ip_lookup_is_registered_once_as_read_before_action():
    ip = "10.127.117.189"
    trace = Results()
    result, calls = run(
        [
            response(
                {
                    "switches": [{"switchId": SERIAL, "fabricManagementIp": ip, "additionalData": {"platformType": "nx-os"}}],
                    "meta": {"counts": {"remaining": 0}},
                }
            ),
            summary("Ethernet1/50", "Ethernet1/51"),
            action(item("Ethernet1/50"), item("Ethernet1/51")),
        ],
        config=[group("Ethernet1/50", switch=ip), group("Ethernet1/51", switch=ip)],
        results=trace,
    )
    assert result["failed"] is False
    assert len(calls) == 3
    assert_registered_calls(trace, calls, [OperationType.QUERY, OperationType.QUERY, OperationType.CREATE])
    assert trace.payload == [None, None, calls[2]["payload"]]
    assert [response["RETURN_CODE"] for response in trace.responses] == [200, 200, 207]


def test_failed_discovery_is_registered_before_workflow_returns_error():
    trace = Results()
    result, calls = run([response({"message": "Not found"}, code=404)], results=trace)
    assert result["failed"] is True
    assert result["diff"] == []
    assert_registered_calls(trace, calls, [OperationType.QUERY, OperationType.QUERY])
    assert trace.responses[1]["RETURN_CODE"] == 404
    assert len(calls) == 2


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_lost_action_response_is_registered_as_unanswered_not_previous_get(state):
    trace = Results()
    api_name = "Ethernet1/50" if state == "merged" else "Ethernet1/50/1"
    result, calls = run(
        [summary(api_name), TimeoutError("Lost action response")],
        state=state,
        config=[group("Ethernet1/50", breakout_map=None if state == "deleted" else "25g-4x")],
        results=trace,
    )
    assert result["failed"] is True
    assert_registered_calls(
        trace, calls, [OperationType.QUERY, OperationType.QUERY, OperationType.CREATE if state == "merged" else OperationType.DELETE], state=state
    )
    assert [entry["RETURN_CODE"] for entry in trace.responses] == [200, 200, -1]
    assert trace.responses[2]["response_received"] is False
    assert trace.responses[2]["MESSAGE"] == "Lost action response"
    assert trace.results[2]["success"] is False
    assert trace.results[2]["changed"] is False
    assert len(calls) == 3


def test_lost_discovery_response_is_registered_at_read_verbosity():
    trace = Results()
    result, calls = run([TimeoutError("Lost interface discovery response")], results=trace)
    assert result["failed"] is True
    assert_registered_calls(trace, calls, [OperationType.QUERY, OperationType.QUERY])
    assert trace.responses[1]["RETURN_CODE"] == -1
    assert trace.responses[1]["response_received"] is False
    assert trace.results[1]["success"] is False
    assert trace.payload == [None, None]
    assert len(calls) == 2


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_post_timeout_preserves_unknown_outcome_without_followup_get(state):
    trace = Results()
    initial = "Ethernet1/50" if state == "merged" else "Ethernet1/50/1"
    final = "Ethernet1/50/1" if state == "merged" else "Ethernet1/50"
    result, calls = run(
        [summary(initial), TimeoutError("Lost action response"), summary(final)],
        state=state,
        config=[group("Ethernet1/50", breakout_map=None if state == "deleted" else "25g-4x")],
        verify={"enabled": True},
        results=trace,
    )
    assert result["failed"] is True
    assert result["may_have_changed"] is True
    assert result["after_status"] == "unknown"
    assert "after" not in result
    assert result["verification"] == {"enabled": True, "complete": False}
    operations = [OperationType.QUERY, OperationType.QUERY, OperationType.CREATE if state == "merged" else OperationType.DELETE]
    assert_registered_calls(trace, calls, operations, state=state)
    assert [entry["RETURN_CODE"] for entry in trace.responses] == [200, 200, -1]
    assert trace.responses[2]["response_received"] is False
    assert trace.results[2]["success"] is False
    assert len(calls) == 3


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("scenario", ["success", "noop", "check_mode", "partial", "missing_identity", "timeout"])
@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
@pytest.mark.parametrize("verbosity", [0, 1, 2, 3])
def test_real_response_results_and_ndoutput_gating_preserve_workflow_evidence(state, scenario, output_level, verbosity):
    trace = Results()
    names = ["Ethernet1/50", "Ethernet1/51"] if scenario == "partial" else ["Ethernet1/50"]
    native = state == "merged"
    if scenario == "noop":
        native = not native
    api_names = names if native else [name + "/1" for name in names]
    scripted = [summary(*api_names)]
    if scenario == "success":
        scripted.append(action(item(api_names[0])))
    elif scenario == "partial":
        scripted.append(action(item(api_names[0]), item(api_names[1], status="failed")))
    elif scenario == "missing_identity":
        scripted.append(action(item("Ethernet1/99")))
    elif scenario == "timeout":
        scripted.append(TimeoutError("Lost action response"))
    report, calls = run(
        scripted,
        state=state,
        config=[group(*names, breakout_map=None if state == "deleted" else "25g-4x")],
        check_mode=scenario == "check_mode",
        results=trace,
    )
    original_report = copy.deepcopy(report)
    module = SimpleNamespace(params={"output_level": output_level, "state": state}, _verbosity=verbosity)
    output = _format_output(module, report, trace)
    assert report == original_report
    for key in ("changed", "failed", "may_have_changed", "after_status", "api_outcomes", "before", "diff"):
        assert output[key] == report[key]
    assert output["after"] == report.get("after", [])
    assert output["output_level"] == output_level
    assert ("proposed" in output) is (output_level in {"info", "debug"})
    if "proposed" in output:
        assert output["proposed"] == report["proposed"]
    assert ("logs" in output) is (output_level == "debug")
    if "logs" in output:
        assert output["logs"] == []
    assert ("api_calls" in output) is (verbosity >= 3)
    if "api_calls" in output:
        assert output["api_calls"] == report["api_calls"]
    indices = [index for index, call in enumerate(calls) if verbosity >= 3 or verbosity >= 2 and call["verb"] == HttpVerbEnum.POST]
    assert ("api_paths" in output) is bool(indices)
    assert ("api_verbs" in output) is bool(indices)
    if indices:
        assert output["api_paths"] == [calls[index]["path"] for index in indices]
        assert output["api_verbs"] == [calls[index]["verb"].value for index in indices]
    for key in ("response", "result", "diff", "metadata", "payload"):
        assert ("api_" + key in output) is (verbosity >= 3)
    if verbosity >= 3:
        assert output["api_response"] == trace.responses
        assert output["api_result"] == trace.results
        assert output["api_metadata"] == trace.metadata
        assert output["api_payload"] == trace.payload
    if scenario in {"partial", "missing_identity", "timeout"}:
        assert output["failed"] is True
        assert output["after_status"] == "unknown"
        assert output["after"] == []  # No reliable snapshot, not physical deletion.
    elif state == "deleted":
        assert output["after"][0]["interface_name"] == "Ethernet1/50"
        assert output["after"][0]["broken_out"] is False
    assert len(calls) == (2 if scenario in {"noop", "check_mode"} else 3)


def test_lost_ip_lookup_response_is_registered_as_unanswered_read_in_debug_output():
    trace = Results()
    ip = "10.127.117.189"
    report, calls = run([TimeoutError("Lost switch lookup response")], config=[group("Ethernet1/50", switch=ip)], results=trace)
    assert report["failed"] is True
    assert report["changed"] is False
    assert report["diff"] == []
    assert len(calls) == 1
    assert writes(calls) == []
    assert_registered_calls(trace, calls, [OperationType.QUERY])
    assert trace.responses[0]["RETURN_CODE"] == -1
    assert trace.responses[0]["response_received"] is False
    assert trace.results[0]["success"] is False
    module = SimpleNamespace(params={"output_level": "debug", "state": "merged"}, _verbosity=3)
    output = _format_output(module, report, trace)
    assert output["failed"] is True
    assert output["changed"] is False
    assert output["api_paths"] == [calls[0]["path"]]
    assert output["api_verbs"] == ["GET"]
    assert output["api_payload"] == [None]
    assert output["api_response"][0]["response_received"] is False


def test_get_retry_then_transport_loss_registers_incomplete_commit_without_stale_response():
    trace = Results()
    report, calls = run([response({"message": "Controller unavailable"}, code=500), TimeoutError("Lost retry response")], results=trace)
    assert report["failed"] is True
    assert report["changed"] is False
    assert report["may_have_changed"] is False
    assert report["diff"] == []
    assert len(calls) == 3
    assert writes(calls) == []
    assert calls[1]["path"] == calls[2]["path"]
    assert trace.path == [calls[0]["path"], calls[1]["path"]]
    assert trace.verb == ["GET", "GET"]
    assert trace.payload == [None, None]
    assert trace.verbosity_level == [3, 3]
    assert trace.metadata[1]["action"] == OperationType.QUERY.value
    assert trace.metadata[1]["state"] == "merged"
    assert trace.responses[1]["RETURN_CODE"] == -1
    assert trace.responses[1]["DATA"] == {}
    assert trace.responses[1]["response_received"] is False
    assert trace.results[1]["success"] is False
    assert len(report["api_calls"]) == 2
    assert report["api_calls"][1]["response_received"] is False
    assert report["api_calls"][1]["http_status"] is None


@pytest.mark.parametrize("requested", ["Ethernet1/50/1", "Ethernet1/50/3", " ethernet01/050/003 "])
def test_deleted_child_selector_preserves_request_but_removes_whole_parent_family(requested):
    result, calls = run(
        [summary("Ethernet1/50/4", "Ethernet1/50/3", "Ethernet1/50/2", "Ethernet1/50/1"), action(item("Ethernet1/50/1"))],
        state="deleted",
        config=[group(requested, breakout_map=None)],
    )
    expected_child = "Ethernet1/50/1" if requested.endswith("/1") else "Ethernet1/50/3"
    target = outcomes(result)[(SERIAL, "Ethernet1/50")]
    assert result["failed"] is False
    assert result["changed"] is True
    assert target["requested_interface_name"] == expected_child
    assert target["api_interface_name"] == "Ethernet1/50/1"
    assert target["outcome"] == "success"
    assert result["proposed"] == [group(expected_child, breakout_map=None)]
    assert result["diff"] == result["proposed"]
    assert result["before"][0]["interface_name"] == "Ethernet1/50"
    assert result["after"][0]["interface_name"] == "Ethernet1/50"
    assert result["after"][0]["broken_out"] is False
    assert len(calls) == 3
    assert_family_get(calls[1], "Ethernet1/50")
    assert calls[2]["path"] == REMOVE
    assert calls[2]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": "Ethernet1/50/1"}]}


def test_deleted_child_repeat_is_noop_after_native_parent_returns():
    result, calls = run([summary("Ethernet1/50")], state="deleted", config=[group("Ethernet1/50/3", breakout_map=None)])
    target = outcomes(result)[(SERIAL, "Ethernet1/50")]
    assert result["failed"] is False
    assert result["changed"] is False
    assert target["outcome"] == "noop"
    assert target["requested_interface_name"] == "Ethernet1/50/3"
    assert target["api_interface_name"] is None
    assert result["proposed"] == [group("Ethernet1/50/3", breakout_map=None)]
    assert result["diff"] == []
    assert result["after"][0]["interface_name"] == "Ethernet1/50"
    assert result["after"][0]["broken_out"] is False
    assert len(calls) == 2
    assert writes(calls) == []


def test_deleted_missing_requested_lane_rejects_entire_batch_before_mutation():
    result, calls = run(
        [summary("Ethernet1/50/1", "Ethernet1/50/3", "Ethernet1/51/1", "Ethernet1/51/2")],
        state="deleted",
        config=[group("Ethernet1/50/3", "Ethernet1/51/3", breakout_map=None)],
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["may_have_changed"] is False
    assert "Ethernet1/51/3" in result["msg"]
    assert result["diff"] == []
    assert len(calls) == 2
    assert writes(calls) == []


def test_deleted_ghost_lane_cannot_validate_requested_child_selector():
    valid = summary("Ethernet1/50/1")["DATA"]["interfaces"][0]
    ghost = {"switchId": SERIAL, "interfaceName": "Ethernet1/50/3", "physicalInterface": False, "fex": False}
    result, calls = run(
        [response({"interfaces": [valid, ghost], "meta": {"counts": {"remaining": 0}}})],
        state="deleted",
        config=[group("Ethernet1/50/3", breakout_map=None)],
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert "Ethernet1/50/3" in result["msg"]
    assert len(calls) == 2
    assert writes(calls) == []


def test_deleted_three_component_fex_name_rejects_actual_fex_evidence():
    result, calls = run(
        [summary("Ethernet101/1/1", fex=True)],
        state="deleted",
        config=[group("Ethernet101/1/1", breakout_map=None)],
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert "FEX interface" in result["msg"]
    assert len(calls) == 2
    assert_family_get(calls[1], "Ethernet101/1")
    assert writes(calls) == []


@pytest.mark.parametrize("selectors", [("Ethernet1/50", "Ethernet1/50/3"), ("Ethernet1/50/1", "Ethernet1/50/3")])
def test_deleted_aliases_of_one_family_are_duplicates_before_any_api(selectors):
    result, calls = run([], state="deleted", config=[group(*selectors, breakout_map=None)])
    assert result["failed"] is True
    assert result["changed"] is False
    assert calls == []


def test_deleted_ip_and_serial_child_aliases_duplicate_family_after_lookup():
    ip = "10.127.117.189"
    result, calls = run(
        [
            response(
                {
                    "switches": [{"switchId": SERIAL, "fabricManagementIp": ip, "additionalData": {"platformType": "nx-os"}}],
                    "meta": {"counts": {"remaining": 0}},
                }
            )
        ],
        state="deleted",
        config=[group("Ethernet1/50", breakout_map=None), group("Ethernet1/50/3", switch=ip, breakout_map=None)],
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert len(calls) == 1
    assert "/switches?" in calls[0]["path"]
    assert writes(calls) == []


def test_deleted_mixed_parent_and_child_selectors_match_reordered_actual_remove_results():
    requested = ["Ethernet1/50/3", "Ethernet1/51", "Ethernet1/52/2"]
    result, calls = run(
        [
            summary("Ethernet1/50/1", "Ethernet1/50/3", "Ethernet1/51/1", "Ethernet1/52/1", "Ethernet1/52/2"),
            action(item("Ethernet1/52/1"), item("Ethernet1/50/1"), item("Ethernet1/51/1")),
        ],
        state="deleted",
        config=[group(*requested, breakout_map=None)],
    )
    assert result["failed"] is False
    assert result["proposed"] == [group(*requested, breakout_map=None)]
    assert result["diff"] == result["proposed"]
    assert [entry["interface_name"] for entry in result["api_outcomes"]] == ["Ethernet1/50", "Ethernet1/51", "Ethernet1/52"]
    assert outcomes(result)[(SERIAL, "Ethernet1/50")]["requested_interface_name"] == "Ethernet1/50/3"
    assert outcomes(result)[(SERIAL, "Ethernet1/52")]["requested_interface_name"] == "Ethernet1/52/2"
    assert {entry["outcome"] for entry in result["api_outcomes"]} == {"success"}
    assert calls[2]["payload"] == {
        "interfaces": [
            {"switchId": SERIAL, "interfaceName": "Ethernet1/50/1"},
            {"switchId": SERIAL, "interfaceName": "Ethernet1/51/1"},
            {"switchId": SERIAL, "interfaceName": "Ethernet1/52/1"},
        ]
    }
    assert len(calls) == 3


def test_deleted_response_for_requested_lane_is_unknown_when_different_lane_was_submitted():
    result, calls = run(
        [summary("Ethernet1/50/1", "Ethernet1/50/3"), action(item("Ethernet1/50/3"))],
        state="deleted",
        config=[group("Ethernet1/50/3", breakout_map=None)],
    )
    assert result["failed"] is True
    assert result["may_have_changed"] is True
    target = outcomes(result)[(SERIAL, "Ethernet1/50")]
    assert target["requested_interface_name"] == "Ethernet1/50/3"
    assert target["api_interface_name"] == "Ethernet1/50/1"
    assert target["outcome"] == "unknown"
    assert len(calls) == 3


def test_deleted_child_check_mode_plans_lowest_existing_child_without_write():
    result, calls = run(
        [summary("Ethernet1/50/3", "Ethernet1/50/1")],
        state="deleted",
        config=[group("Ethernet1/50/3", breakout_map=None)],
        check_mode=True,
    )
    target = outcomes(result)[(SERIAL, "Ethernet1/50")]
    assert result["failed"] is False
    assert result["changed"] is True
    assert target["outcome"] == "planned"
    assert target["requested_interface_name"] == "Ethernet1/50/3"
    assert target["api_interface_name"] == "Ethernet1/50/1"
    assert result["proposed"] == result["diff"] == [group("Ethernet1/50/3", breakout_map=None)]
    assert len(calls) == 2
    assert writes(calls) == []


def test_deleted_child_opt_in_verification_accepts_child_gone_and_parent_restored():
    result, calls = run(
        [summary("Ethernet1/50/3", "Ethernet1/50/1"), action(item("Ethernet1/50/1")), summary("Ethernet1/50")],
        state="deleted",
        config=[group("Ethernet1/50/3", breakout_map=None)],
        verify={"enabled": True},
    )
    assert result["failed"] is False
    assert result["after_status"] == "observed"
    assert result["verification"]["topology_matches"] is True
    assert result["after"][0]["interface_name"] == "Ethernet1/50"
    assert result["after"][0]["broken_out"] is False
    assert len(calls) == 4
    assert_family_get(calls[3], "Ethernet1/50")


def test_merged_child_selector_fails_before_any_api():
    result, calls = run([], config=[group("Ethernet1/50/3")])
    assert result["failed"] is True
    assert result["changed"] is False
    assert calls == []


@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
@pytest.mark.parametrize("verbosity", [0, 1, 2, 3])
@pytest.mark.parametrize("scenario", ["success", "noop"])
def test_deleted_child_selector_ndoutput_gating_preserves_input_and_parent_snapshot(output_level, verbosity, scenario):
    trace = Results()
    scripted = [summary("Ethernet1/50/1", "Ethernet1/50/3"), action(item("Ethernet1/50/1"))] if scenario == "success" else [summary("Ethernet1/50")]
    report, calls = run(scripted, state="deleted", config=[group("Ethernet1/50/3", breakout_map=None)], results=trace)
    module = SimpleNamespace(params={"output_level": output_level, "state": "deleted"}, _verbosity=verbosity)
    output = _format_output(module, report, trace)
    assert output["failed"] is False
    assert output["changed"] is (scenario == "success")
    assert output["api_outcomes"][0]["requested_interface_name"] == "Ethernet1/50/3"
    assert output["after"][0]["interface_name"] == "Ethernet1/50"
    assert output["after"][0]["broken_out"] is False
    assert output["diff"] == ([group("Ethernet1/50/3", breakout_map=None)] if scenario == "success" else [])
    assert ("proposed" in output) is (output_level in {"info", "debug"})
    if "proposed" in output:
        assert output["proposed"] == [group("Ethernet1/50/3", breakout_map=None)]
    assert ("logs" in output) is (output_level == "debug")
    assert ("api_calls" in output) is (verbosity >= 3)
    if verbosity >= 3:
        assert output["api_paths"] == [call["path"] for call in calls]
        assert output["api_verbs"] == [call["verb"].value for call in calls]
    elif verbosity == 2 and scenario == "success":
        assert output["api_paths"] == [REMOVE]
    else:
        assert "api_paths" not in output
    assert len(calls) == (3 if scenario == "success" else 2)


@pytest.mark.parametrize(
    "first_selector,second_selector",
    [
        ("Ethernet1/50/3", "Ethernet1/50/3"),
        ("Ethernet1/50", "Ethernet1/50/3"),
        ("Ethernet1/50/3", "Ethernet1/50"),
    ],
)
@pytest.mark.parametrize("verbosity", [0, 1, 2, 3])
def test_success_then_native_repeat_is_idempotent_across_parent_child_aliases(first_selector, second_selector, verbosity):
    first_trace = Results()
    first, first_calls = run(
        [summary("Ethernet1/50/1", "Ethernet1/50/3"), action(item("Ethernet1/50/1"))],
        state="deleted",
        config=[group(first_selector, breakout_map=None)],
        results=first_trace,
    )
    assert first["failed"] is False
    assert first["changed"] is True
    assert first["diff"] == [group(first_selector, breakout_map=None)]
    assert_registered_calls(first_trace, first_calls, [OperationType.QUERY, OperationType.QUERY, OperationType.DELETE], state="deleted")
    second_trace = Results()
    second, second_calls = run(
        [summary("Ethernet1/50")],
        state="deleted",
        config=[group(second_selector, breakout_map=None)],
        results=second_trace,
    )
    assert second["failed"] is False
    assert second["changed"] is False
    assert second["diff"] == []
    assert second["after_status"] == "unchanged"
    assert second["api_outcomes"][0]["outcome"] == "noop"
    assert second["proposed"] == [group(second_selector, breakout_map=None)]
    assert_registered_calls(second_trace, second_calls, [OperationType.QUERY, OperationType.QUERY], state="deleted")
    module = SimpleNamespace(params={"output_level": "info", "state": "deleted"}, _verbosity=verbosity)
    output = _format_output(module, second, second_trace)
    assert output["failed"] is False
    assert output["changed"] is False
    assert output["diff"] == []
    assert output["proposed"] == [group(second_selector, breakout_map=None)]
    assert output["after"][0]["interface_name"] == "Ethernet1/50"
    assert output["after"][0]["broken_out"] is False
    assert ("api_paths" in output) is (verbosity >= 3)
    assert len(first_calls) == 3
    assert len(second_calls) == 2
    assert writes(second_calls) == []


def test_deleted_absent_child_and_parent_family_is_not_a_blind_noop():
    result, calls = run([summary()], state="deleted", config=[group("Ethernet1/50/3", breakout_map=None)])
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["after_status"] == "unknown"
    assert result["proposed"] == [group("Ethernet1/50/3", breakout_map=None)]
    assert result["diff"] == []
    assert all(entry["outcome"] != "noop" for entry in result["api_outcomes"])
    assert len(calls) == 2
    assert writes(calls) == []


def assert_preflight_failure(report, calls, serials):
    """Reject before discovering, planning or submitting any topology action."""
    assert report["failed"] is True
    assert report["changed"] is False
    assert report["may_have_changed"] is False
    assert report["after_status"] == "unknown"
    assert report["api_outcomes"] == report["diff"] == []
    assert report.get("before", []) == report.get("after", []) == []
    assert calls == [{"path": BASE + "/switches/" + serial, "verb": HttpVerbEnum.GET, "payload": None} for serial in serials]
    assert [call["purpose"] for call in report["api_calls"]] == ["switch_metadata"] * len(serials)


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_iosxe_is_rejected_before_topology_policy_or_action_in_every_state(state, check_mode):
    config = [group("Ethernet1/50", breakout_map=None if state == "deleted" else "25g-4x")]
    report, calls = run([], state=state, check_mode=check_mode, config=config, platform_inventory=inventory(platform="ios-xe"))
    assert_preflight_failure(report, calls, [SERIAL])
    assert report["proposed"] == config
    assert "ios-xe" in report["msg"] and "Nexus Dashboard does not support breakout interfaces on IOS-XE" in report["msg"]
    assert "no breakout or unbreakout request was sent" in report["msg"]


@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_child_on_iosxe_is_rejected_without_a_child_or_policy_lookup(check_mode):
    config = [group("Ethernet1/50/3", breakout_map=None)]
    report, calls = run([], state="deleted", check_mode=check_mode, config=config, platform_inventory=inventory(platform="ios-xe"))
    assert_preflight_failure(report, calls, [SERIAL])
    assert report["proposed"] == config
    assert "ios-xe" in report["msg"]


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("platform", ["ios-xe", None])
def test_even_an_apparent_native_or_broken_noop_requires_a_supported_platform(state, check_mode, platform):
    # This otherwise no-op topology must not be read before eligibility is known.
    topology = summary("Ethernet1/50" if state == "deleted" else "Ethernet1/50/1")
    report, calls = run(
        [topology],
        state=state,
        check_mode=check_mode,
        config=[group("Ethernet1/50", breakout_map=None if state == "deleted" else "25g-4x")],
        platform_inventory=inventory(platform=platform),
        verify={"enabled": True},
    )
    assert_preflight_failure(report, calls, [SERIAL])
    assert "requires NX-OS" in report["msg"]


@pytest.mark.parametrize(
    "additional",
    [
        pytest.param(None, id="null-additional-data"),
        pytest.param("nx-os", id="string-additional-data"),
        pytest.param([], id="list-additional-data"),
        pytest.param({}, id="missing-platform"),
        pytest.param({"platformType": None}, id="null-platform"),
        pytest.param({"platformType": ""}, id="empty-platform"),
        pytest.param({"platformType": " NX-OS "}, id="unrecognized-case-and-whitespace"),
        pytest.param({"platformType": "future-platform"}, id="unknown-platform"),
        pytest.param({"platformType": 1}, id="integer-platform"),
        pytest.param({"platformType": True}, id="boolean-platform"),
        pytest.param({"platformType": []}, id="list-platform"),
        pytest.param({"platformType": {}}, id="object-platform"),
    ],
)
def test_missing_unknown_or_wrong_typed_platform_metadata_fails_closed(additional):
    report, calls = run([], platform_inventory=response({"switchId": SERIAL, "additionalData": additional}))
    assert_preflight_failure(report, calls, [SERIAL])
    assert "additionalData.platformType is missing or unrecognized" in report["msg"]


def test_absent_additional_data_fails_closed_before_discovery():
    report, calls = run([], platform_inventory=response({"switchId": SERIAL}))
    assert_preflight_failure(report, calls, [SERIAL])
    assert "Cannot verify the platform" in report["msg"]


@pytest.mark.parametrize("platform", ["other", "ios-xr", "sonic", "apic"])
@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_other_recognized_platforms_are_not_treated_as_nxos(platform, state, check_mode):
    report, calls = run(
        [],
        state=state,
        check_mode=check_mode,
        config=[group("Ethernet1/50", breakout_map=None if state == "deleted" else "25g-4x")],
        platform_inventory=inventory(platform=platform),
    )
    assert_preflight_failure(report, calls, [SERIAL])
    assert "unsupported platformType '" + platform + "'" in report["msg"]


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("iosxe_first", [False, True])
def test_mixed_nxos_iosxe_input_preflights_all_distinct_switches_before_any_discovery(state, check_mode, iosxe_first):
    serials = [OTHER_SERIAL, SERIAL] if iosxe_first else [SERIAL, OTHER_SERIAL]
    breakout_map = None if state == "deleted" else "25g-4x"
    config = [group("Ethernet1/50", "Ethernet1/51", switch=serial, breakout_map=breakout_map) for serial in serials]
    report, calls = run(
        [],
        state=state,
        check_mode=check_mode,
        config=config,
        platform_inventory=[inventory(serial, platform="ios-xe" if serial == OTHER_SERIAL else "nx-os") for serial in serials],
    )
    assert_preflight_failure(report, calls, serials)
    assert report["proposed"] == config
    assert OTHER_SERIAL in report["msg"] and "ios-xe" in report["msg"]
    assert "Switch '" + SERIAL + "' reports" not in report["msg"]


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_nxos_switch_in_a_campus_fabric_is_not_rejected_by_fabric_type(state, check_mode):
    api_name = "Ethernet1/50/1" if state == "deleted" else "Ethernet1/50"
    responses = [summary(api_name)] + ([] if check_mode else [action(item(api_name))])
    report, calls = run(
        responses,
        state=state,
        check_mode=check_mode,
        config=[group("Ethernet1/50", breakout_map=None if state == "deleted" else "25g-4x")],
        platform_inventory=inventory(fabricType="Campus_VXLAN_EVPN", switchRole="border"),
        fabric_name="Campus_AK",
    )
    assert report["failed"] is False and report["changed"] is True
    assert len(calls) == (2 if check_mode else 3)
    assert calls[0]["path"] == "/api/v1/manage/fabrics/Campus_AK/switches/" + SERIAL
    assert calls[1]["path"].startswith("/api/v1/manage/fabrics/Campus_AK/interfacesSummary?")
    assert all("/summary" not in call["path"] and "/policies" not in call["path"] for call in calls)
    assert len(writes(calls)) == (0 if check_mode else 1)


@pytest.mark.parametrize("serials", [(SERIAL,), (SERIAL, OTHER_SERIAL)])
def test_serial_metadata_budget_is_one_exact_get_per_distinct_switch_not_per_port(serials):
    config = [group("Ethernet1/50", switch=serial) for serial in serials] + [group("Ethernet1/51", switch=serial) for serial in serials]
    responses = [summary("Ethernet1/50", "Ethernet1/51", switch=serial) for serial in serials]
    responses.append(action(*(item(name, switch=serial) for serial in reversed(serials) for name in ("Ethernet1/51", "Ethernet1/50"))))
    trace = Results()
    report, calls = run(responses, config=config, results=trace)
    assert report["failed"] is False
    assert calls[: len(serials)] == [{"path": BASE + "/switches/" + serial, "verb": HttpVerbEnum.GET, "payload": None} for serial in serials]
    assert len(calls) == 2 * len(serials) + 1
    assert len(writes(calls)) == 1
    assert len(writes(calls)[0]["payload"]["interfaces"]) == 2 * len(serials)
    assert_registered_calls(trace, calls, [OperationType.QUERY] * (2 * len(serials)) + [OperationType.CREATE])
    assert [call["purpose"] for call in report["api_calls"][: len(serials)]] == ["switch_metadata"] * len(serials)


@pytest.mark.parametrize("platform", ["nx-os", "ios-xe", None])
@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_ip_platform_metadata_is_reused_without_refetching_serial(platform, state):
    ip = "10.127.117.189"
    row = {"switchId": SERIAL, "fabricManagementIp": ip, "additionalData": {"platformType": platform}}
    script = [response({"switches": [row], "meta": {"counts": {"remaining": 0}}})]
    api_name = "Ethernet1/50/1" if state == "deleted" else "Ethernet1/50"
    if platform == "nx-os":
        script.extend([summary(api_name), action(item(api_name))])
    trace = Results()
    report, calls = run(script, state=state, config=[group("Ethernet1/50", switch=ip, breakout_map=None if state == "deleted" else "25g-4x")], results=trace)
    assert report["failed"] is (platform != "nx-os")
    assert len(calls) == (3 if platform == "nx-os" else 1)
    assert "/switches?" in calls[0]["path"]
    assert parse_qs(urlsplit(calls[0]["path"]).query)["filter"] == ["fabricManagementIp:" + ip]
    assert not any(urlsplit(call["path"]).path == BASE + "/switches/" + SERIAL for call in calls)
    assert report["proposed"][0]["switch_id"] == SERIAL
    assert [call["purpose"] for call in report["api_calls"] if call.get("purpose") == "switch_metadata"] == ["switch_metadata"]
    if platform != "nx-os":
        assert report["changed"] is report["may_have_changed"] is False
        assert report["api_outcomes"] == report["diff"] == []
        assert_registered_calls(trace, calls, [OperationType.QUERY], state=state)


def test_mixed_ip_and_serial_reuses_ip_record_and_reads_only_uncached_serial():
    ip = "10.127.117.189"
    trace = Results()
    report, calls = run(
        [
            response(
                {
                    "switches": [{"switchId": SERIAL, "fabricManagementIp": ip, "additionalData": {"platformType": "nx-os"}}],
                    "meta": {"counts": {"remaining": 0}},
                }
            ),
            inventory(OTHER_SERIAL),
            summary("Ethernet1/50", "Ethernet1/51"),
            summary("Ethernet1/50", switch=OTHER_SERIAL),
            action(item("Ethernet1/50", switch=OTHER_SERIAL), item("Ethernet1/51"), item("Ethernet1/50")),
        ],
        config=[group("Ethernet1/50", switch=ip), group("Ethernet1/51"), group("Ethernet1/50", switch=OTHER_SERIAL)],
        platform_inventory=None,
        results=trace,
    )
    assert report["failed"] is False and len(calls) == 5
    assert "/switches?" in calls[0]["path"]
    assert calls[1]["path"] == BASE + "/switches/" + OTHER_SERIAL
    assert not any(call["path"] == BASE + "/switches/" + SERIAL for call in calls)
    assert_registered_calls(trace, calls, [OperationType.QUERY] * 4 + [OperationType.CREATE])


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_invalid_local_config_is_rejected_before_platform_metadata_get(state, check_mode):
    report, calls = run(
        [], state=state, check_mode=check_mode, config=[group("Ethernet1/50", "ethernet01/0050", breakout_map=None if state == "deleted" else "25g-4x")]
    )
    assert report["failed"] is True and report["changed"] is False
    assert calls == [] and report["api_calls"] == []
    assert "specified more than once" in report["msg"]


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("verify", [{"enabled": False}, {"enabled": True}])
def test_replaced_is_rejected_before_any_switch_topology_policy_or_action_call(check_mode, verify):
    report, calls = run([], state="replaced", check_mode=check_mode, verify=verify)
    assert report["failed"] is True and report["changed"] is report["may_have_changed"] is False
    assert "Unsupported state 'replaced'; only merged and deleted are supported." == report["msg"]
    assert calls == report["api_calls"] == report["api_outcomes"] == report["diff"] == []
    assert report["after_status"] == "unknown"
    assert report.get("before", []) == report.get("after", []) == []


@pytest.mark.parametrize("data", [None, [], {}, {"switchId": OTHER_SERIAL, "additionalData": {"platformType": "nx-os"}}, {"switches": [{"switchId": SERIAL}]}])
def test_malformed_or_wrong_identity_platform_response_is_not_authoritative(data):
    report, calls = run([], platform_inventory=response(data))
    assert_preflight_failure(report, calls, [SERIAL])
    assert "malformed or unexpected switch identity" in report["msg"]


@pytest.mark.parametrize("failure", ["not_found", "transport_loss", "http_failure_then_transport_loss", "iosxe", "unknown_platform"])
@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
@pytest.mark.parametrize("verbosity", [0, 1, 2, 3])
def test_failed_platform_get_preserves_standard_ndoutput_and_read_diagnostics(failure, output_level, verbosity):
    trace = Results()
    scripts = {
        "not_found": [response({"message": "Not found"}, code=404)],
        "transport_loss": [TimeoutError("Lost switch metadata response")],
        "http_failure_then_transport_loss": [response({"message": "Controller unavailable"}, code=500), TimeoutError("Lost metadata retry response")],
        "iosxe": [inventory(platform="ios-xe")],
        "unknown_platform": [inventory(platform=None)],
    }
    script = scripts[failure]
    report, calls = run([], platform_inventory=script, results=trace)
    assert report["failed"] is True and report["changed"] is report["may_have_changed"] is False
    assert report["api_outcomes"] == report["diff"] == []
    assert len(calls) == (2 if failure == "http_failure_then_transport_loss" else 1)
    assert all(call == {"path": BASE + "/switches/" + SERIAL, "verb": HttpVerbEnum.GET, "payload": None} for call in calls)
    # Aborted shared GET commits retain one logical failed read, not intermediate replies.
    assert trace.path == [calls[0]["path"]]
    assert trace.verb == ["GET"] and trace.payload == [None] and trace.verbosity_level == [3]
    assert trace.metadata[0]["action"] == OperationType.QUERY.value
    expected_code = {"not_found": 404, "transport_loss": -1, "http_failure_then_transport_loss": -1, "iosxe": 200, "unknown_platform": 200}[failure]
    assert trace.responses[0]["RETURN_CODE"] == expected_code
    assert trace.responses[0].get("response_received", True) is (failure not in {"transport_loss", "http_failure_then_transport_loss"})
    if failure in {"iosxe", "unknown_platform"}:
        assert trace.results[0]["success"] is True  # The GET succeeded, but eligibility did not.
        assert "requires NX-OS switches" in report["msg"]
    assert len(report["api_calls"]) == 1 and report["api_calls"][0]["purpose"] == "switch_metadata"
    module = SimpleNamespace(params={"output_level": output_level, "state": "merged"}, _verbosity=verbosity)
    original = copy.deepcopy(report)
    output = _format_output(module, report, trace)
    assert report == original
    assert output["failed"] is True and output["changed"] is output["may_have_changed"] is False
    assert output["before"] == output["after"] == output["diff"] == output["api_outcomes"] == []
    assert output["after_status"] == "unknown"
    assert ("proposed" in output) is (output_level in {"info", "debug"})
    assert ("logs" in output) is (output_level == "debug")
    assert ("api_calls" in output) is (verbosity >= 3)
    assert ("api_paths" in output) is (verbosity >= 3)
    if verbosity >= 3:
        assert output["api_paths"] == trace.path
        assert output["api_response"] == trace.responses
        assert output["api_result"] == trace.results
        assert output["api_metadata"] == trace.metadata
        assert output["api_payload"] == [None]
    if "proposed" in output:
        assert output["proposed"] == [group("Ethernet1/50")]


def test_lost_uncached_serial_metadata_does_not_reuse_preceding_ip_lookup_response():
    ip = "10.127.117.189"
    trace = Results()
    report, calls = run(
        [
            response(
                {
                    "switches": [{"switchId": SERIAL, "fabricManagementIp": ip, "additionalData": {"platformType": "nx-os"}}],
                    "meta": {"counts": {"remaining": 0}},
                }
            ),
            TimeoutError("Lost uncached serial metadata"),
        ],
        config=[group("Ethernet1/50", switch=ip), group("Ethernet1/50", switch=OTHER_SERIAL)],
        platform_inventory=None,
        results=trace,
    )
    assert report["failed"] is True and report["changed"] is report["may_have_changed"] is False
    assert len(calls) == 2 and calls[1]["path"] == BASE + "/switches/" + OTHER_SERIAL
    assert_registered_calls(trace, calls, [OperationType.QUERY, OperationType.QUERY])
    assert trace.responses[0]["RETURN_CODE"] == 200
    assert trace.responses[1]["RETURN_CODE"] == -1 and trace.responses[1]["response_received"] is False
    assert trace.responses[1]["DATA"] == {}
    assert report["api_calls"][1]["purpose"] == "switch_metadata"
    assert report["api_calls"][1]["http_status"] is None


def ip_inventory(ip, platform="nx-os"):
    """An independently fetched IP alias record, optionally missing metadata."""
    row = {"switchId": SERIAL, "fabricManagementIp": ip}
    if platform is not None:
        row["additionalData"] = {"platformType": platform}
    return response({"switches": [row], "meta": {"counts": {"total": 1, "remaining": 0}}})


@pytest.mark.parametrize("platforms", [("nx-os", "ios-xe"), ("ios-xe", "nx-os"), (None, "nx-os"), ("nx-os", None)])
@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_distinct_ip_aliases_cannot_overwrite_conflicting_or_missing_platform_metadata(platforms, state, check_mode):
    ips = ["10.127.117.189", "10.127.117.190"]
    parents = ["Ethernet1/50", "Ethernet1/51"]
    api_names = [parent + "/1" for parent in parents] if state == "deleted" else parents
    trace = Results()
    report, calls = run(
        [
            ip_inventory(ips[0], platforms[0]),
            ip_inventory(ips[1], platforms[1]),
            # Leave valid topology and action replies available. A preflight
            # bypass must not appear to fail merely because fixtures ran out.
            summary(*api_names),
            action(*(item(name) for name in api_names)),
        ],
        state=state,
        check_mode=check_mode,
        config=[group(parent, switch=ip, breakout_map=None if state == "deleted" else "25g-4x") for parent, ip in zip(parents, ips)],
        results=trace,
    )
    assert report["failed"] is True
    assert report["changed"] is report["may_have_changed"] is False
    assert report["after_status"] == "unknown"
    assert report["api_outcomes"] == report["diff"] == []
    assert report.get("before", []) == report.get("after", []) == []
    assert len(calls) == 2 and writes(calls) == []
    assert [parse_qs(urlsplit(call["path"]).query)["filter"] for call in calls] == [["fabricManagementIp:" + ip] for ip in ips]
    assert all(urlsplit(call["path"]).path == BASE + "/switches" for call in calls)
    assert_registered_calls(trace, calls, [OperationType.QUERY, OperationType.QUERY], state=state, check_mode=check_mode)
    assert all(entry["RETURN_CODE"] == 200 for entry in trace.responses)
    assert [call["purpose"] for call in report["api_calls"]] == ["switch_metadata", "switch_metadata"]
    output = _format_output(SimpleNamespace(params={"state": state, "output_level": "info"}, _verbosity=3), report, trace)
    assert output["failed"] is True and output["changed"] is output["may_have_changed"] is False
    assert output["after_status"] == "unknown"
    assert output["before"] == output["after"] == output["diff"] == output["api_outcomes"] == []
    assert output["api_paths"] == [call["path"] for call in calls]


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_distinct_ip_aliases_with_matching_nxos_metadata_allow_distinct_parent_families(state, check_mode):
    ips = ["10.127.117.189", "10.127.117.190"]
    parents = ["Ethernet1/50", "Ethernet1/51"]
    api_names = [parent + "/1" for parent in parents] if state == "deleted" else parents
    trace = Results()
    report, calls = run(
        [ip_inventory(ips[0]), ip_inventory(ips[1]), summary(*api_names), action(*(item(name) for name in api_names))],
        state=state,
        check_mode=check_mode,
        config=[group(parent, switch=ip, breakout_map=None if state == "deleted" else "25g-4x") for parent, ip in zip(parents, ips)],
        results=trace,
    )
    assert report["failed"] is False and report["changed"] is True
    assert len(calls) == (3 if check_mode else 4)
    assert [parse_qs(urlsplit(call["path"]).query)["filter"] for call in calls[:2]] == [["fabricManagementIp:" + ip] for ip in ips]
    assert_family_get(calls[2], "Ethernet1/5")
    assert not any(call["path"] == BASE + "/switches/" + SERIAL for call in calls)
    assert set(outcomes(report)) == {(SERIAL, parent) for parent in parents}
    assert {entry["outcome"] for entry in report["api_outcomes"]} == {"planned" if check_mode else "success"}
    operations = [OperationType.QUERY] * 3 + ([] if check_mode else [OperationType.DELETE if state == "deleted" else OperationType.CREATE])
    assert_registered_calls(trace, calls, operations, state=state, check_mode=check_mode)


@pytest.mark.parametrize("ips", [("10.127.117.189", " 10.127.117.189 "), ("2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001")])
@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_repeated_canonical_ip_alias_uses_one_platform_lookup_for_distinct_families(ips, state, check_mode):
    canonical_ip = str(ip_address(ips[0].strip()))
    parents = ["Ethernet1/50", "Ethernet1/51"]
    api_names = [parent + "/1" for parent in parents] if state == "deleted" else parents
    trace = Results()
    report, calls = run(
        [ip_inventory(canonical_ip), summary(*api_names), action(*(item(name) for name in api_names))],
        state=state,
        check_mode=check_mode,
        config=[group(parent, switch=ip, breakout_map=None if state == "deleted" else "25g-4x") for parent, ip in zip(parents, ips)],
        results=trace,
    )
    assert report["failed"] is False and report["changed"] is True
    assert len(calls) == (2 if check_mode else 3)
    assert parse_qs(urlsplit(calls[0]["path"]).query)["filter"] == ["fabricManagementIp:" + canonical_ip]
    assert_family_get(calls[1], "Ethernet1/5")
    assert not any(call["path"] == BASE + "/switches/" + SERIAL for call in calls)
    operations = [OperationType.QUERY] * 2 + ([] if check_mode else [OperationType.DELETE if state == "deleted" else OperationType.CREATE])
    assert_registered_calls(trace, calls, operations, state=state, check_mode=check_mode)
