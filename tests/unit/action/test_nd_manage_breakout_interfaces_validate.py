# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Independent observer tests: bad evidence must not become a passing oracle."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlsplit

import pytest
from ansible.errors import AnsibleConnectionFailure
from ansible.plugins.action import ActionBase
from ansible_collections.cisco.nd.plugins.action import (
    nd_manage_breakout_interfaces_validate as validator,
)

SERIAL = "FDO222425SE"
PARENT = "Ethernet1/50"
MAP_A = "25g-4x"
MAP_B = "50g-2x"
ACTION_BASE_RUN = ActionBase.run


class TaggedInt(int):
    """Ansible templating attaches provenance using scalar subclasses."""


class TaggedFloat(float):
    """Stand-in for Ansible's tagged floating-point interval."""


def fixture(quad=False, guards=False):
    parents = ["Ethernet1/21", "Ethernet1/22", "Ethernet1/23", "Ethernet1/24"] if quad else [PARENT]
    child_parents = [parents[0], parents[2]] if quad else parents
    result = {
        "control_parent": parents[0],
        "native_interfaces": parents,
        "profiles": {
            "map_a": {
                "breakout_map": MAP_A,
                "child_lanes": {parent: [1, 2, 3, 4] for parent in child_parents},
            },
            "map_b": {
                "breakout_map": MAP_B,
                "child_lanes": {parent: [1, 2] for parent in child_parents},
            },
        },
    }
    if guards:
        result["guard_interfaces"] = ["Ethernet1/60"]
    return result


def interface(name=PARENT, **changes):
    row = {
        "switchId": SERIAL,
        "interfaceName": name,
        "physicalInterface": True,
        "fex": False,
    }
    row.update(changes)
    return row


def policy(parent=PARENT, breakout_map=MAP_A, **changes):
    row = {
        "policyId": "POLICY-" + parent,
        "switchId": SERIAL,
        "entityName": parent,
        "entityType": "interface",
        "templateName": "breakout_interface",
        "markDeleted": False,
        "templateInputs": {"MAP": breakout_map},
    }
    row.update(changes)
    return row


def response(collection, rows, **changes):
    result = {
        "status": 200,
        "current": {
            collection: rows,
            "meta": {"counts": {"total": len(rows), "remaining": 0}},
        },
    }
    result.update(changes)
    return result


def live(raw_fixture=None, profile="native", ghost=False):
    raw_fixture = raw_fixture or fixture()
    if profile == "native":
        interfaces = [interface(parent) for parent in raw_fixture["native_interfaces"]]
        policies = []
    else:
        config = raw_fixture["profiles"][profile]
        interfaces = [interface(parent + "/" + str(lane)) for parent, lanes in config["child_lanes"].items() for lane in lanes]
        interfaces.extend(interface(parent) for parent in config.get("native_interfaces", []))
        policies = [
            policy(parent, breakout_map)
            for parent, breakout_map in config.get(
                "policy_maps",
                {parent: config["breakout_map"] for parent in config["child_lanes"]},
            ).items()
        ]
        if ghost:
            interfaces.append(interface(raw_fixture["control_parent"], physicalInterface=False, fex=None))
    # Test guard 60 is deliberately in a separate numeric-prefix bucket.
    replies = [response("interfaces", interfaces)]
    if raw_fixture.get("guard_interfaces"):
        replies.append(
            response(
                "interfaces",
                [interface(parent) for parent in raw_fixture["guard_interfaces"]],
            )
        )
    return replies + [response("policies", policies)]


@pytest.fixture(autouse=True)
def action_base_run(monkeypatch):
    monkeypatch.setattr(ActionBase, "run", lambda *args, **kwargs: {})
    monkeypatch.setattr(validator.time, "sleep", MagicMock())


def run(replies=None, check_mode=False, **changes):
    args = {
        "fabric_name": "fab1",
        "switch_id": SERIAL,
        "fixture": fixture(),
        "expected_profile": "native",
        "retries": 1,
    }
    args.update(changes)
    plugin = object.__new__(validator.ActionModule)
    plugin._task = SimpleNamespace(args=args, check_mode=check_mode)
    plugin._execute_module = MagicMock(side_effect=deepcopy(replies if replies is not None else live(args["fixture"], args["expected_profile"])))
    result = plugin.run(task_vars={"sentinel": "passed"})
    return result, plugin


def snapshot(raw_fixture=None, profile="native"):
    result, _ = run(fixture=raw_fixture or fixture(), expected_profile=profile, observe_only=True)
    assert not result["failed"]
    return result["snapshot"]


@pytest.mark.parametrize("quad", [False, True])
@pytest.mark.parametrize("profile", ["native", "map_a", "map_b"])
def test_same_suite_matches_independent_and_quad_profiles(quad, profile):
    declared = fixture(quad)
    result, plugin = run(fixture=declared, expected_profile=profile)
    assert result["failed"] is False and result["changed"] is False
    assert result["checks"] == ["topology", "policy_maps"]
    assert result["differences"] == []
    assert len(plugin._execute_module.call_args_list) == 2
    for call in plugin._execute_module.call_args_list:
        assert call.kwargs["module_name"] == "cisco.nd.nd_rest"
        assert call.kwargs["module_args"]["method"] == "GET"
        assert call.kwargs["task_vars"] == {"sentinel": "passed"}
        assert set(call.kwargs["module_args"]) == {"path", "method"}
    assert len(result["observation_calls"]) == 2


def test_quad_absent_native_collateral_parents_are_not_missing_resource_errors():
    result, _ = run(fixture=fixture(True), expected_profile="map_a")
    assert result["failed"] is False
    assert result["snapshot"]["families"]["Ethernet1/22"] == {
        "native": False,
        "children": [],
    }
    assert result["snapshot"]["families"]["Ethernet1/24"] == {
        "native": False,
        "children": [],
    }
    assert len(result["snapshot"]["families"]["Ethernet1/23"]["children"]) == 4


def test_quad_under_declared_single_family_expectation_does_not_silently_pass():
    declared = fixture(True)
    del declared["profiles"]["map_a"]["child_lanes"]["Ethernet1/23"]
    result, _ = run(live(fixture(True), "map_a"), fixture=declared, expected_profile="map_a")
    assert result["failed"] is True
    assert {item["check"] for item in result["differences"]} == {
        "topology",
        "policy_maps",
    }


def test_physical_children_and_active_map_pass_with_ghost_parent():
    result, _ = run(live(profile="map_a", ghost=True), expected_profile="map_a")
    assert result["failed"] is False


def test_ghost_parent_does_not_prove_native_restoration():
    replies = [
        response("interfaces", [interface(physicalInterface=False)]),
        response("policies", []),
    ]
    result, _ = run(replies)
    assert result["failed"] is True and result["differences"][0]["check"] == "topology"


@pytest.mark.parametrize(
    "mode",
    [
        "missing_child",
        "extra_child",
        "missing_parent",
        "wrong_map",
        "missing_policy",
        "unexpected_policy",
    ],
)
def test_incorrect_topology_or_intent_fails(mode):
    profile = "native" if mode in {"missing_parent", "unexpected_policy"} else "map_a"
    replies = live(profile=profile)
    if mode == "missing_child":
        replies[0]["current"]["interfaces"].pop()
    elif mode == "extra_child":
        replies[0]["current"]["interfaces"].append(interface(PARENT + "/5"))
    elif mode == "missing_parent":
        replies[0]["current"]["interfaces"] = []
    elif mode == "wrong_map":
        replies[1]["current"]["policies"][0]["templateInputs"]["MAP"] = MAP_B
    elif mode == "missing_policy":
        replies[1]["current"]["policies"] = []
    else:
        replies[1]["current"]["policies"] = [policy()]
    for reply in replies:
        for rows in (
            reply["current"].get("interfaces"),
            reply["current"].get("policies"),
        ):
            if rows is not None:
                reply["current"]["meta"]["counts"]["total"] = len(rows)
    result, _ = run(replies, expected_profile=profile)
    assert result["failed"] is True and result["differences"]


def test_order_case_map_and_unrelated_prefixes_are_normalized_without_false_members():
    replies = live(profile="map_a")
    for row in replies[0]["current"]["interfaces"]:
        row["interfaceName"] = row["interfaceName"].lower()
    replies[0]["current"]["interfaces"].reverse()
    replies[0]["current"]["interfaces"].extend(
        [
            interface("Ethernet1/500"),
            interface("Ethernet1/50.100"),
            interface("Ethernet1/50/1.100"),
            interface("Ethernet1/50/1/1"),
        ]
    )
    replies[0]["current"]["meta"]["counts"]["total"] = 8
    replies[1]["current"]["policies"][0]["templateInputs"] = {"map": " 25G-4X "}
    result, _ = run(replies, expected_profile="map_a")
    assert result["failed"] is False
    assert result["snapshot"]["policy_maps"] == {PARENT: MAP_A}
    assert len(result["snapshot"]["families"][PARENT]["children"]) == 4


@pytest.mark.parametrize(
    "change",
    [
        {"switchId": "WRONG"},
        {"physicalInterface": None},
        {"physicalInterface": "true"},
        {"fex": True},
        {"fex": None},
    ],
)
def test_ambiguous_physical_or_switch_evidence_fails_even_observe_only(change):
    replies = [response("interfaces", [interface(**change)]), response("policies", [])]
    result, _ = run(replies, observe_only=True)
    assert result["failed"] is True
    assert result["differences"] == []  # Invalid evidence fails immediately, not after settling.


def test_duplicate_identity_including_ghost_and_physical_is_rejected():
    replies = [
        response("interfaces", [interface(), interface(physicalInterface=False)]),
        response("policies", []),
    ]
    result, _ = run(replies, observe_only=True)
    assert result["failed"] is True and "Duplicate interface" in result["msg"]


def test_native_and_children_are_ambiguous_even_observe_only():
    replies = [
        response("interfaces", [interface(), interface(PARENT + "/1")]),
        response("policies", [policy()]),
    ]
    result, _ = run(replies, observe_only=True)
    assert result["failed"] is True and "Ambiguous native" in result["msg"]


@pytest.mark.parametrize(
    "change",
    [
        {"switchId": "WRONG"},
        {"policyId": None},
        {"policyId": ""},
        {"markDeleted": None},
        {"markDeleted": "false"},
        {"entityType": "switch"},
        {"templateInputs": {}},
        {"templateInputs": {"MAP": ""}},
        {"templateInputs": {"MAP": 4}},
        {"templateInputs": {"MAP": MAP_A, "map": MAP_A}},
        {"templateInputs": '{"MAP":"25g-4x"}'},
    ],
)
def test_policy_identity_active_status_and_map_are_strict(change):
    replies = live(profile="map_a")
    replies[1]["current"]["policies"][0].update(change)
    result, _ = run(replies, expected_profile="map_a", observe_only=True)
    assert result["failed"] is True


@pytest.mark.parametrize("field", ["switchId", "entityName", "templateName", "policyId"])
def test_malformed_policy_rows_do_not_prove_native_policy_absence(field):
    malformed = policy()
    del malformed[field]
    result, _ = run([response("interfaces", [interface()]), response("policies", [malformed])])
    assert result["failed"] is True and "explicit" in result["msg"]


def test_multiple_active_parent_policies_cannot_pass():
    replies = live(profile="map_a")
    replies[1] = response("policies", [policy(), policy(policyId="POLICY-OTHER")])
    result, _ = run(replies, expected_profile="map_a")
    assert result["failed"] is True and "Multiple active" in result["msg"]


def test_mark_deleted_policy_is_not_active_intent():
    replies = live()
    replies[1] = response("policies", [policy(markDeleted=True)])
    result, _ = run(replies)
    assert result["failed"] is False and result["snapshot"]["policy_maps"] == {}


def test_mark_deleted_only_policy_does_not_prove_broken_map():
    replies = live(profile="map_a")
    replies[1]["current"]["policies"][0]["markDeleted"] = True
    result, _ = run(replies, expected_profile="map_a")
    assert result["failed"] is True
    assert result["differences"][0]["check"] == "policy_maps"


def test_duplicate_policy_ids_even_mark_deleted_are_rejected():
    replies = live(profile="map_a")
    replies[1] = response("policies", [policy(), policy(markDeleted=True)])
    result, _ = run(replies, expected_profile="map_a")
    assert result["failed"] is True and "duplicate breakout policy identity" in result["msg"]


@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        {"status": 200, "failed": True, "msg": "boom"},
        {"status": 200, "skipped": True},
        {"status": 202},
        {"status": "200"},
        {"status": True},
        {"status": 200, "current": []},
        {"status": 200, "current": {"interfaces": None}},
        {"status": 200, "current": {"interfaces": ["bad"]}},
        {"status": 200, "current": {"interfaces": [], "meta": []}},
        {"status": 200, "current": {"interfaces": [], "meta": {"counts": []}}},
    ],
)
def test_bad_get_evidence_fails_immediately_without_retry(bad):
    result, plugin = run([bad], retries=3)
    assert result["failed"] is True and plugin._execute_module.call_count == 1
    assert not validator.time.sleep.called


@pytest.mark.parametrize(
    "counts",
    [
        {"remaining": -1},
        {"remaining": True},
        {"total": "1"},
        {"total": 0},
        {"remaining": 1, "total": 1},
    ],
)
def test_invalid_pagination_counts_rejected(counts):
    reply = response("interfaces", [interface()])
    reply["current"]["meta"]["counts"] = counts
    result, _ = run([reply])
    assert result["failed"] is True and ("pagination" in result["msg"] or "declared total" in result["msg"])


def test_filtered_pagination_fetches_all_rows_and_offsets_are_correct():
    replies = live(profile="map_a")
    rows = replies[0]["current"]["interfaces"]
    first = response("interfaces", rows[:2])
    second = response("interfaces", rows[2:])
    first["current"]["meta"]["counts"] = {"total": 4, "remaining": 2}
    second["current"]["meta"]["counts"] = {"total": 4, "remaining": 0}
    result, plugin = run([first, second, replies[1]], expected_profile="map_a")
    assert result["failed"] is False
    paths = [call.kwargs["module_args"]["path"] for call in plugin._execute_module.call_args_list]
    assert [parse_qs(urlsplit(path).query)["offset"][0] for path in paths] == [
        "0",
        "2",
        "0",
    ]


def test_empty_incomplete_page_cannot_be_an_absence_success():
    reply = response("interfaces", [])
    reply["current"]["meta"]["counts"] = {"remaining": 1, "total": 1}
    result, _ = run([reply], observe_only=True)
    assert result["failed"] is True and "ended before" in result["msg"]


def test_repeated_page_cannot_be_an_absence_success():
    reply = response("interfaces", [interface()])
    reply["current"]["meta"]["counts"] = {"remaining": 1}
    result, _ = run([reply, reply], observe_only=True)
    assert result["failed"] is True and "repeated a page" in result["msg"]


def test_duplicate_interface_across_distinct_pages_fails():
    first = response("interfaces", [interface()])
    second = response("interfaces", [interface(), interface("Ethernet1/500")])
    first["current"]["meta"]["counts"] = {"total": 3, "remaining": 2}
    second["current"]["meta"]["counts"] = {"total": 3, "remaining": 0}
    result, _ = run([first, second, response("policies", [])], observe_only=True)
    assert result["failed"] is True and "Duplicate interface" in result["msg"]


def test_pagination_safety_cap_cannot_return_a_partial_snapshot(monkeypatch):
    monkeypatch.setattr(validator, "_MAX_PAGES", 1)
    reply = response("interfaces", [interface()])
    reply["current"]["meta"]["counts"] = {"remaining": 1}
    result, _ = run([reply], observe_only=True)
    assert result["failed"] is True and "safety limit" in result["msg"]


def test_malformed_policy_collection_not_equivalent_to_no_policies():
    replies = live()
    replies[1]["current"] = {"policies": None}
    result, _ = run(replies)
    assert result["failed"] is True and "array of objects" in result["msg"]


@pytest.mark.parametrize("collection", ["interfaces", "policies"])
@pytest.mark.parametrize("number", [int, TaggedInt])
def test_initial_explicit_zero_counts_allow_omitted_collection(collection, number):
    replies = live()
    index = 0 if collection == "interfaces" else 1
    replies[index]["current"] = {"meta": {"counts": {"total": number(0), "remaining": number(0)}}}
    result, _ = run(replies, observe_only=(collection == "interfaces"))
    assert result["failed"] is False
    if collection == "interfaces":
        assert result["snapshot"]["families"][PARENT] == {
            "native": False,
            "children": [],
        }
    else:
        assert result["snapshot"]["policy_maps"] == {}


def test_zero_count_omitted_interfaces_still_cannot_prove_native_restoration():
    replies = live()
    replies[0]["current"] = {"meta": {"counts": {"total": 0, "remaining": 0}}}
    result, _ = run(replies)
    assert result["failed"] is True and result["differences"][0]["check"] == "topology"


@pytest.mark.parametrize("collection", ["interfaces", "policies"])
@pytest.mark.parametrize(
    "counts",
    [
        {},
        {"total": 0},
        {"remaining": 0},
        {"total": "0", "remaining": 0},
        {"total": 0, "remaining": False},
        {"total": True, "remaining": 0},
        {"total": 1, "remaining": 0},
        {"total": 0, "remaining": 1},
        {"total": -1, "remaining": 0},
        None,
    ],
)
def test_missing_collection_requires_both_valid_explicit_zero_counts(collection, counts):
    replies = live()
    index = 0 if collection == "interfaces" else 1
    replies[index]["current"] = {"meta": {"counts": counts}}
    result, _ = run(replies, observe_only=True)
    assert result["failed"] is True


@pytest.mark.parametrize("collection", ["interfaces", "policies"])
@pytest.mark.parametrize("value", [None, {}, "", 0])
def test_explicit_null_or_bad_collection_is_not_empty_even_with_zero_counts(collection, value):
    replies = live()
    index = 0 if collection == "interfaces" else 1
    replies[index]["current"] = {
        collection: value,
        "meta": {"counts": {"total": 0, "remaining": 0}},
    }
    result, _ = run(replies, observe_only=True)
    assert result["failed"] is True and "array of objects" in result["msg"]


@pytest.mark.parametrize("collection", ["interfaces", "policies"])
def test_later_omitted_page_is_not_accepted_as_zero_count_absence(collection):
    first_rows = [interface()] if collection == "interfaces" else [policy()]
    first = response(collection, first_rows)
    first["current"]["meta"]["counts"] = {"total": 2, "remaining": 1}
    omitted = {
        "status": 200,
        "current": {"meta": {"counts": {"total": 0, "remaining": 0}}},
    }
    replies = [first, omitted] if collection == "interfaces" else [live()[0], first, omitted]
    result, _ = run(replies, observe_only=True)
    assert result["failed"] is True and "array of objects" in result["msg"]


def test_transport_exception_is_reported_without_retry_or_lost_trace():
    plugin = object.__new__(validator.ActionModule)
    plugin._task = SimpleNamespace(
        check_mode=False,
        args={"fabric_name": "fab1", "switch_id": SERIAL, "fixture": fixture()},
    )
    plugin._execute_module = MagicMock(side_effect=AnsibleConnectionFailure("controller unavailable"))
    result = plugin.run()
    assert result["failed"] is True and result["changed"] is False
    assert "controller unavailable" in result["msg"] and len(result["observation_calls"]) == 1
    assert plugin._execute_module.call_count == 1 and not validator.time.sleep.called


def test_settling_retries_only_gets_and_returns_last_snapshot():
    replies = live() + live(profile="map_a")
    result, plugin = run(replies, expected_profile="map_a", retries=3, interval=1)
    assert result["failed"] is False and result["attempts"] == 2
    assert plugin._execute_module.call_count == 4
    validator.time.sleep.assert_called_once_with(1)
    assert all(call["method"] == "GET" for call in result["observation_calls"])


def test_unsatisfied_profile_reports_differences_after_bounded_attempts():
    result, plugin = run(live() + live() + live(), expected_profile="map_a", retries=3)
    assert result["failed"] is True and result["attempts"] == 3
    assert plugin._execute_module.call_count == 6
    assert validator.time.sleep.call_count == 2


def test_unchanged_compares_fresh_snapshot_not_module_claims():
    baseline = snapshot(profile="map_a")
    result, _ = run(expected_profile="map_a", baseline=baseline, unchanged=True)
    assert result["failed"] is False and "unchanged" in result["checks"]
    result, _ = run(expected_profile="map_b", baseline=baseline, unchanged=True)
    assert result["failed"] is True
    assert result["differences"][0]["check"] == "unchanged"


def test_guards_compared_even_when_reserved_state_changes_as_expected():
    declared = fixture(guards=True)
    baseline = snapshot(declared)
    result, _ = run(fixture=declared, expected_profile="map_a", baseline=baseline)
    assert result["failed"] is False and "guards" in result["checks"]
    replies = live(declared, "map_a")
    replies[1]["current"]["interfaces"][-1]["physicalInterface"] = False
    result, _ = run(replies, fixture=declared, expected_profile="map_a", baseline=baseline)
    assert result["failed"] is True and result["differences"][0]["check"] == "guard_topology"


def test_guard_policy_drift_is_detected():
    declared = fixture(guards=True)
    baseline = snapshot(declared)
    replies = live(declared, "map_a")
    replies[-1]["current"]["policies"].append(policy("Ethernet1/60"))
    replies[-1]["current"]["meta"]["counts"]["total"] += 1
    result, _ = run(replies, fixture=declared, expected_profile="map_a", baseline=baseline)
    assert result["failed"] is True and result["differences"][0]["check"] == "guard_policy"


def test_explicit_policy_expectations_and_retained_native_ports_are_supported():
    declared = fixture(True)
    config = declared["profiles"]["map_a"]
    config["native_interfaces"] = ["Ethernet1/22", "Ethernet1/24"]
    config["policy_maps"] = {"Ethernet1/21": MAP_A}
    result, _ = run(fixture=declared, expected_profile="map_a")
    assert result["failed"] is False


def test_query_paths_are_scoped_filters_and_fabric_is_encoded():
    result, plugin = run(fabric_name="fabric name/1")
    assert result["failed"] is False
    interface_path = plugin._execute_module.call_args_list[0].kwargs["module_args"]["path"]
    policy_path = plugin._execute_module.call_args_list[1].kwargs["module_args"]["path"]
    assert "/fabric%20name%2F1/" in interface_path
    query = parse_qs(urlsplit(interface_path).query)
    assert query["switchId"] == [SERIAL] and query["includeAll"] == ["true"]
    assert query["filter"] == ["interfaceName:*Ethernet1/50*"]
    assert parse_qs(urlsplit(policy_path).query)["filter"] == ["switchId:" + SERIAL + " AND templateName:breakout_interface AND entityName:" + PARENT]
    assert "\\" not in policy_path


def test_custom_interface_filter_is_honored():
    declared = fixture(True)
    declared["interface_filter"] = "interfaceName:*Ethernet1/2*"
    result, plugin = run(fixture=declared)
    assert result["failed"] is False
    path = plugin._execute_module.call_args_list[0].kwargs["module_args"]["path"]
    assert parse_qs(urlsplit(path).query)["filter"] == [declared["interface_filter"]]


def test_quad_default_filter_uses_one_verified_wildcard_not_summary_or():
    result, plugin = run(fixture=fixture(True), expected_profile="map_a")
    assert result["failed"] is False
    path = plugin._execute_module.call_args_list[0].kwargs["module_args"]["path"]
    assert parse_qs(urlsplit(path).query)["filter"] == ["interfaceName:*Ethernet1/2*"]
    assert len(plugin._execute_module.call_args_list) == 2


def test_disjoint_ranges_use_separate_narrow_filters_not_full_inventory():
    declared = fixture()
    declared["native_interfaces"].append("Ethernet1/21")
    replies = [
        response("interfaces", [interface("Ethernet1/21")]),
        response("interfaces", [interface()]),
        response("policies", []),
    ]
    result, plugin = run(replies, fixture=declared)
    assert result["failed"] is False
    paths = [call.kwargs["module_args"]["path"] for call in plugin._execute_module.call_args_list[:2]]
    assert [parse_qs(urlsplit(path).query)["filter"][0] for path in paths] == [
        "interfaceName:*Ethernet1/21*",
        "interfaceName:*Ethernet1/50*",
    ]


def test_multiple_interfaces_have_independent_declared_policy_maps():
    declared = fixture()
    declared["native_interfaces"].append("Ethernet1/51")
    profile = declared["profiles"]["map_a"]
    profile["child_lanes"]["Ethernet1/51"] = [1, 2]
    profile["policy_maps"] = {PARENT: MAP_A, "Ethernet1/51": MAP_B}
    result, _ = run(fixture=declared, expected_profile="map_a")
    assert result["failed"] is False
    assert result["snapshot"]["policy_maps"] == {PARENT: MAP_A, "Ethernet1/51": MAP_B}


@pytest.mark.parametrize("change", [{"policy_maps": {}}, {"policy_maps": {PARENT: MAP_B}}])
def test_profile_cannot_disable_or_misstate_requested_control_map(change):
    declared = fixture()
    declared["profiles"]["map_a"].update(change)
    result, plugin = run([], fixture=declared)
    assert result["failed"] is True and "control_parent MAP" in result["msg"]
    assert plugin._execute_module.call_count == 0


def test_profile_must_include_control_family_not_only_coupled_or_other_parent():
    declared = fixture(True)
    del declared["profiles"]["map_a"]["child_lanes"]["Ethernet1/21"]
    result, plugin = run([], fixture=declared)
    assert result["failed"] is True and "control_parent" in result["msg"]
    assert plugin._execute_module.call_count == 0


def test_check_mode_observation_rejected_clearly_without_module_call():
    result, plugin = run(check_mode=True)
    assert result["failed"] is True and "check_mode: false" in result["msg"]
    assert plugin._execute_module.call_count == 0


@pytest.mark.parametrize("check_mode", [False, True])
def test_real_action_base_contract_smoke(monkeypatch, check_mode):
    monkeypatch.setattr(ActionBase, "run", ACTION_BASE_RUN)
    plugin = object.__new__(validator.ActionModule)
    plugin._task = SimpleNamespace(
        args={"fabric_name": "fab1", "switch_id": SERIAL, "fixture": fixture()},
        check_mode=check_mode,
        async_val=0,
        action="cisco.nd.nd_manage_breakout_interfaces_validate",
    )
    plugin._connection = SimpleNamespace(_shell=SimpleNamespace(tmpdir="/private/tmp"))
    plugin._execute_module = MagicMock(side_effect=live())
    result = plugin.run()
    assert result["failed"] is check_mode
    assert result["changed"] is False
    assert plugin._execute_module.call_count == (0 if check_mode else 2)


@pytest.mark.parametrize("quad", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_validate_only_checks_whole_schema_without_any_get_or_snapshot(quad, check_mode):
    result, plugin = run(
        [],
        fixture=fixture(quad, guards=True),
        validate_only=True,
        check_mode=check_mode,
    )
    assert result["failed"] is False and result["changed"] is False
    assert result["validated"] is True and result["checks"] == ["fixture_schema"]
    assert result["observation_calls"] == [] and "snapshot" not in result
    assert plugin._execute_module.call_count == 0


def test_validate_only_rejects_invalid_optional_profile_before_first_mutation():
    declared = fixture()
    declared["profiles"]["map_b"]["child_lanes"] = {PARENT: [True]}
    result, plugin = run([], fixture=declared, expected_profile="map_a", validate_only=True)
    assert result["failed"] is True and "positive integer" in result["msg"]
    assert plugin._execute_module.call_count == 0


@pytest.mark.parametrize("interval", [TaggedInt(1), TaggedFloat(0.5)])
def test_tagged_fixture_numbers_are_valid_without_relaxing_bool_rejection(interval):
    declared = fixture(True)
    for profile in declared["profiles"].values():
        profile["child_lanes"] = {parent: [TaggedInt(lane) for lane in lanes] for parent, lanes in profile["child_lanes"].items()}
    result, plugin = run(
        [],
        fixture=declared,
        validate_only=True,
        retries=TaggedInt(3),
        interval=interval,
    )
    assert result["failed"] is False and result["validated"] is True
    assert plugin._execute_module.call_count == 0


def test_tagged_pagination_numbers_remain_complete_read_evidence():
    replies = live(profile="map_a")
    for reply in replies:
        reply["status"] = TaggedInt(200)
        reply["current"]["meta"]["counts"] = {key: TaggedInt(value) for key, value in reply["current"]["meta"]["counts"].items()}
    result, _ = run(replies, expected_profile="map_a", retries=TaggedInt(1), interval=TaggedFloat(0))
    assert result["failed"] is False


@pytest.mark.parametrize(
    "changes",
    [
        {"fabric_name": ""},
        {"switch_id": ""},
        {"switch_id": "serial AND foo:bar"},
        {"switch_id": "192.0.2.1"},
        {"fixture": None},
        {"expected_profile": "unknown"},
        {"expected_profile": []},
        {"unchanged": True},
        {"unchanged": "true"},
        {"observe_only": "true"},
        {"validate_only": "true"},
        {"validate_only": True, "observe_only": True},
        {"observe_only": True, "unchanged": True},
        {"retries": 0},
        {"retries": True},
        {"retries": 11},
        {"interval": -1},
        {"interval": "1"},
        {"interval": True},
        {"interval": 61},
        {"retries": 10, "interval": 10},
        {"baseline": {}},
        {"fixture": fixture(guards=True)},
        {"typo": "ignored arguments must not pass"},
    ],
)
def test_invalid_observer_arguments_fail_before_any_get(changes):
    result, plugin = run([], **changes)
    assert result["failed"] is True and plugin._execute_module.call_count == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("native_interfaces", []),
        ("native_interfaces", [PARENT, PARENT]),
        ("control_parent", "Ethernet1/51"),
        ("guard_interfaces", [PARENT]),
        ("profiles", []),
        ("interface_filter", ""),
    ],
)
def test_bad_fixture_structure_rejected(field, value):
    declared = fixture()
    declared[field] = value
    result, plugin = run([], fixture=declared)
    assert result["failed"] is True and plugin._execute_module.call_count == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"breakout_map": ""},
        {"child_lanes": {}},
        {"child_lanes": {PARENT: [0]}},
        {"child_lanes": {PARENT: [True]}},
        {"child_lanes": {PARENT: [1, 1]}},
        {"child_lanes": {"Ethernet1/51": [1]}},
        {"child_lanes": {PARENT: "1,2"}},
        {"native_interfaces": [PARENT]},
        {"native_interfaces": ["Ethernet1/51"]},
        {"policy_maps": []},
        {"policy_maps": {"Ethernet1/51": MAP_A}},
        {"policy_maps": {PARENT: ""}},
    ],
)
def test_bad_profile_structure_rejected(changes):
    declared = fixture()
    declared["profiles"]["map_a"].update(changes)
    result, plugin = run([], fixture=declared)
    assert result["failed"] is True and plugin._execute_module.call_count == 0


@pytest.mark.parametrize(
    "change",
    [
        {"switch_id": "OTHER"},
        {"families": {}},
        {"policy_maps": {"Ethernet1/51": MAP_A}},
        {"families": {PARENT: {"native": "true", "children": []}}},
        {"families": {PARENT: {"native": True, "children": [PARENT + "/1"]}}},
        {"families": {PARENT: {"native": False, "children": [PARENT + "/1", PARENT + "/1"]}}},
        {"families": {PARENT: {"native": False, "children": ["Ethernet1/500/1"]}}},
        {"policy_maps": {PARENT: " 25G-4X "}},
    ],
)
def test_malformed_baseline_rejected_before_get(change):
    baseline = {
        "switch_id": SERIAL,
        "families": {PARENT: {"native": True, "children": []}},
        "policy_maps": {},
    }
    baseline.update(change)
    result, plugin = run([], baseline=baseline, unchanged=True)
    assert result["failed"] is True and plugin._execute_module.call_count == 0
