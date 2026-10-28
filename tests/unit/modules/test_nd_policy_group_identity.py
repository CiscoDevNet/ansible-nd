# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Exercise exact group identity through real module planning and HTTP effects.

The existing lifecycle harness replaces only Ansible process exits and HTTP.
Normal matching, models, state machine, endpoint construction, response handling
and persistent controller state remain active.
"""

import json
from copy import deepcopy

import pytest
from ansible_collections.cisco.nd.tests.unit.modules.test_nd_policy_group_direct_id import (
    GROUP_ID,
    SECOND_ID,
    Controller,
    config,
    group,
    invoke,
)

ANONYMOUS_ID = "POLICY-GROUP-103"
MISSING_ID = "POLICY-GROUP-999"
DESCRIPTION = "Duplicate description"
TEMPLATE = "feature_enable"


def duplicate_groups(*, timestamps=(10, 20)):
    """Use distinct intent and membership to expose accidental sibling reuse."""
    return [
        group(
            description=DESCRIPTION,
            priority=400,
            switchIds=["SERIAL_OLD"],
            templateInputs={"featureName": "lacp"},
            updateTimestamp=timestamps[0],
        ),
        group(
            SECOND_ID,
            description=DESCRIPTION,
            priority=500,
            switchIds=["SERIAL_NEW"],
            templateInputs={"featureName": "lldp"},
            updateTimestamp=timestamps[1],
        ),
    ]


def select_old(selector):
    """Return supported explicit-ID forms, including documented name precedence."""
    if selector == "name":
        return {"name": GROUP_ID}
    if selector == "policy_id":
        return {"name": TEMPLATE, "policy_id": GROUP_ID, "description": DESCRIPTION}
    return {"name": GROUP_ID, "policy_id": SECOND_ID}


def mark_delete_calls(controller):
    return [call for call in controller.writes() if "/policyGroups/actions/markDelete" in call[1]]


def snapshots_by_id(result, key):
    return {item["policy_id"]: item for item in result[key]}


@pytest.mark.parametrize(
    "policy_id,description",
    [
        ("POLICY-777", None),
        ("POLICY-777", "Existing"),
        ("101", None),
        ("policy-group-101", "Existing"),
        ("", None),
        (" ", "Existing"),
        ("POLICY-GROUP-", None),
    ],
)
@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_consumed_explicit_id_rejects_invalid_namespace_before_requests(invoke, policy_id, description, state, check_mode):
    """An invalid explicit ID cannot become a template selector or a planned direct action."""
    controller = Controller([group(description="Existing"), group(SECOND_ID, description="Sibling"), group(ANONYMOUS_ID)])
    original = deepcopy(controller.groups)
    entry = config(name=TEMPLATE, policy_id=policy_id)
    if description is not None:
        entry["description"] = description
    result = invoke(controller, [entry], state=state, deploy=True, check_mode=check_mode)
    assert result["failed"] is True
    assert result["changed"] is False
    assert "config[0]" in result["msg"] and "policy_id" in result["msg"]
    assert "POLICY-GROUP-" in result["msg"]
    assert controller.calls == []
    assert controller.groups == original


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_consumed_name_id_requires_nonempty_suffix_before_requests(invoke, state, check_mode):
    """The consumed name-ID field receives the same namespace/suffix guard."""
    controller = Controller([group(description="Existing")])
    result = invoke(controller, [{"name": "POLICY-GROUP-", "policy_id": GROUP_ID}], state=state, check_mode=check_mode)
    assert result["failed"] is True
    assert result["changed"] is False
    assert "config[0]" in result["msg"] and "name" in result["msg"]
    assert controller.calls == []
    assert GROUP_ID in controller.groups


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_consumed_explicit_id_creation_flag_cannot_bypass_validation(invoke, state, check_mode):
    """A merged force-create or retained deleted flag cannot hide an invalid ID."""
    controller = Controller([group(description="Existing")])
    entry = config(name=TEMPLATE, policy_id="POLICY-777", description="Forced", create_additional_policy=True)
    result = invoke(controller, [entry], state=state, check_mode=check_mode)
    assert result["failed"] is True
    assert result["changed"] is False
    assert "policy_id" in result["msg"]
    assert "force_created" not in result
    assert controller.calls == []
    assert set(controller.groups) == {GROUP_ID}


@pytest.mark.parametrize("first_bucket", ["special", "normal", "ip"])
@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_consumed_explicit_id_preflights_complete_mixed_batch(invoke, monkeypatch, first_bucket, state, check_mode):
    """A later invalid ID stops earlier writes, previews and IP inventory requests."""
    from ansible_collections.cisco.nd.plugins.modules import nd_manage_policy_group

    inventory_reads = []

    def forbidden_inventory(*_args, **_kwargs):
        inventory_reads.append(True)
        raise AssertionError("Invalid-ID preflight must run before IP inventory")

    monkeypatch.setattr(nd_manage_policy_group.FabricSwitchInventory, "from_fabric", forbidden_inventory)
    controller = Controller([group(description="Existing"), group(ANONYMOUS_ID)])
    original = deepcopy(controller.groups)
    first = {"name": GROUP_ID, "priority": 600}
    if first_bucket == "special":
        first = config(name=TEMPLATE, description="Forced", create_additional_policy=True) if state == "merged" else {"name": ANONYMOUS_ID}
    elif first_bucket == "ip":
        first["switch_ids"] = ["192.0.2.10"]
    result = invoke(
        controller,
        [first, config(name=TEMPLATE, description="Existing", policy_id="POLICY-777")],
        state=state,
        deploy=True,
        check_mode=check_mode,
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert "config[1]" in result["msg"] and "policy_id" in result["msg"]
    assert "force_created" not in result and "direct_actions" not in result
    assert controller.calls == []
    assert inventory_reads == []
    assert controller.groups == original


@pytest.mark.parametrize("field", ["name", "policy_id"])
@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_consumed_id_outer_whitespace_matches_canonical_execution(invoke, field, state, check_mode):
    """Normalize before resolution so padded IDs inherit the canonical target's sparse intent."""
    canonical = (
        {"name": GROUP_ID, "policy_id": "POLICY-ignored", "priority": 600} if field == "name" else {"name": TEMPLATE, "policy_id": GROUP_ID, "priority": 600}
    )
    padded = {**canonical, field: f" {GROUP_ID} "}
    ordinary, normalized = Controller(duplicate_groups()), Controller(duplicate_groups())
    expected = invoke(ordinary, [canonical], state=state, deploy=True, check_mode=check_mode)
    actual = invoke(normalized, [padded], state=state, deploy=True, check_mode=check_mode)
    assert not expected.get("failed"), expected
    assert actual == expected
    assert normalized.calls == ordinary.calls
    assert normalized.groups == ordinary.groups
    assert snapshots_by_id(actual, "before")[GROUP_ID]["description"] == DESCRIPTION


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_consumed_name_id_ignores_conflicting_empty_policy_id(invoke, state, check_mode):
    """Only the effective ID is validated; an ignored empty field cannot override name."""
    controller = Controller(duplicate_groups())
    result = invoke(controller, [{"name": GROUP_ID, "policy_id": "", "priority": 600}], state=state, deploy=True, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    if check_mode:
        assert controller.writes() == []
    elif state == "deleted":
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [GROUP_ID]}]
        assert set(controller.groups) == {SECOND_ID}
    else:
        assert {call[1].rsplit("/", 1)[-1] for call in controller.writes("PUT")} == {GROUP_ID}


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_consumed_explicit_id_null_keeps_omitted_selector_behavior(invoke, state, check_mode):
    """Null remains omission, including deliberate template-wide deleted requests."""
    entry = {"name": TEMPLATE, **({"description": "Existing", "priority": 600} if state == "merged" else {})}
    omitted, null = Controller([group(description="Existing"), group(SECOND_ID, description="Sibling")]), Controller(
        [group(description="Existing"), group(SECOND_ID, description="Sibling")]
    )
    expected = invoke(omitted, [entry], state=state, check_mode=check_mode)
    actual = invoke(null, [{**entry, "policy_id": None}], state=state, check_mode=check_mode)
    assert actual == expected
    assert null.calls == omitted.calls
    assert null.groups == omitted.groups


@pytest.mark.parametrize("policy_id", ["POLICY-777", "", None])
@pytest.mark.parametrize("check_mode", [False, True])
def test_consumed_id_validation_keeps_gathered_policy_id_ignored(invoke, policy_id, check_mode):
    """Gathered remains filter-only and does not consume or validate policy_id."""
    controller = Controller([group(description="Existing"), group(SECOND_ID)])
    result = invoke(controller, [{"name": TEMPLATE, "policy_id": policy_id}], state="gathered", deploy=True, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is False
    assert {item["policy_id"] for item in result["gathered"]} == {GROUP_ID, SECOND_ID}
    assert controller.writes() == []


@pytest.mark.parametrize("check_mode", [False, True])
def test_consumed_id_validation_keeps_gathered_raw_name_filter(invoke, check_mode):
    """Mutation-only ID normalization cannot change gathered name matching."""
    controller = Controller([group(description="Existing")])
    result = invoke(controller, [{"name": f" {GROUP_ID} "}], state="gathered", check_mode=check_mode)
    assert result == {"changed": False, "gathered": []}
    assert controller.writes() == []


@pytest.mark.parametrize("template_name", ["POLICY-777", "policy-group-101"])
@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_consumed_id_validation_does_not_guess_template_name_intent(invoke, template_name, state):
    """A name outside the reserved namespace remains a template name."""
    controller = Controller([group(description="Existing", templateName=template_name)])
    result = invoke(controller, [{"name": template_name, "description": "Existing", "priority": 600}], state=state)
    assert not result.get("failed"), result
    assert result["changed"] is True
    if state == "deleted":
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [GROUP_ID]}]
    else:
        assert {call[1].rsplit("/", 1)[-1] for call in controller.writes("PUT")} == {GROUP_ID}


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_consumed_id_validation_accepts_opaque_nonnumeric_suffix(invoke, state, check_mode):
    """The module reserves a namespace, without inventing a numeric suffix contract."""
    opaque_id = "POLICY-GROUP-opaque-ABC"
    controller = Controller([group(opaque_id, description="Existing")])
    result = invoke(controller, [{"name": TEMPLATE, "policy_id": opaque_id, "priority": 600}], state=state, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    if check_mode:
        assert controller.writes() == []
    elif state == "deleted":
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [opaque_id]}]
    else:
        assert {call[1].rsplit("/", 1)[-1] for call in controller.writes("PUT")} == {opaque_id}


@pytest.mark.parametrize("selector", ["name", "policy_id", "name_precedence"])
@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_explicit_older_id_deletes_exact_group(invoke, selector, deploy, check_mode):
    """An explicit ID stays authoritative even when normal matching has a winner."""
    controller = Controller(duplicate_groups())
    sibling = deepcopy(controller.groups[SECOND_ID])
    result = invoke(controller, [select_old(selector)], state="deleted", deploy=deploy, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert snapshots_by_id(result, "before")[GROUP_ID]["priority"] == 400
    assert GROUP_ID not in snapshots_by_id(result, "after")
    assert controller.groups[SECOND_ID] == sibling
    if check_mode:
        assert controller.writes() == []
        assert GROUP_ID in controller.groups
    else:
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [GROUP_ID]}]
        assert GROUP_ID not in controller.groups
        assert len(controller.deployments()) == int(deploy)
        if deploy:
            assert controller.deployments()[0][2] == {"switchIds": ["SERIAL_OLD"]}


@pytest.mark.parametrize("selector", ["name", "policy_id", "name_precedence"])
@pytest.mark.parametrize("priority", [500, 600])
@pytest.mark.parametrize("check_mode", [False, True])
def test_explicit_older_id_preserves_omitted_fields(invoke, selector, priority, check_mode):
    """Priority-only updates inherit membership and input from the requested ID."""
    controller = Controller(duplicate_groups())
    sibling = deepcopy(controller.groups[SECOND_ID])
    entry = {**select_old(selector), "priority": priority}
    result = invoke(controller, [entry], check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert snapshots_by_id(result, "before")[GROUP_ID]["priority"] == 400
    after = snapshots_by_id(result, "after")[GROUP_ID]
    assert after["priority"] == priority
    assert after["switch_ids"] == ["SERIAL_OLD"]
    assert after["template_inputs"] == {"featureName": "lacp"}
    assert controller.groups[SECOND_ID] == sibling
    assert "execution_key" not in json.dumps(result)
    if check_mode:
        assert controller.writes() == []
        assert controller.groups[GROUP_ID]["priority"] == 400
    else:
        puts = controller.writes("PUT")
        assert len(puts) == 1
        assert puts[0][1].endswith(f"/policyGroups/{GROUP_ID}")
        assert puts[0][2]["priority"] == priority
        assert puts[0][2]["switchIds"] == ["SERIAL_OLD"]
        assert puts[0][2]["templateInputs"] == {"featureName": "lacp"}


@pytest.mark.parametrize("full_entry", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_explicit_older_id_identical_is_noop(invoke, full_entry, check_mode):
    """Compare an unchanged older ID with itself rather than its newest sibling."""
    controller = Controller(duplicate_groups())
    before = deepcopy(controller.groups)
    entry = {"name": GROUP_ID}
    if full_entry:
        entry.update(priority=400, switch_ids=["SERIAL_OLD"], template_inputs={"featureName": "lacp"})
    result = invoke(controller, [entry], check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is False
    assert result["before"] == result["after"]
    assert snapshots_by_id(result, "before")[GROUP_ID]["priority"] == 400
    assert controller.writes() == []
    assert controller.groups == before


@pytest.mark.parametrize("selector", ["name", "policy_id"])
def test_distinct_explicit_ids_same_pair_update_independently(invoke, selector):
    """Two different explicit IDs never collapse into a single proposed object."""
    controller = Controller(duplicate_groups())
    if selector == "name":
        entries = [{"name": GROUP_ID, "priority": 600}, {"name": SECOND_ID, "priority": 700}]
    else:
        entries = [
            {"name": TEMPLATE, "description": DESCRIPTION, "policy_id": GROUP_ID, "priority": 600},
            {"name": TEMPLATE, "description": DESCRIPTION, "policy_id": SECOND_ID, "priority": 700},
        ]
    result = invoke(controller, entries)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert [call[1].rsplit("/", 1)[-1] for call in controller.writes("PUT")] == [GROUP_ID, SECOND_ID]
    assert controller.groups[GROUP_ID]["priority"] == 600
    assert controller.groups[GROUP_ID]["switchIds"] == ["SERIAL_OLD"]
    assert controller.groups[SECOND_ID]["priority"] == 700
    assert controller.groups[SECOND_ID]["switchIds"] == ["SERIAL_NEW"]


def test_explicit_old_id_and_implicit_newest_update_independently(invoke):
    """Mixed selectors retain both exact identity and existing no-ID matching."""
    controller = Controller(duplicate_groups())
    result = invoke(
        controller,
        [{"name": GROUP_ID, "priority": 600}, {"name": TEMPLATE, "description": DESCRIPTION, "priority": 700}],
    )
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert {call[1].rsplit("/", 1)[-1] for call in controller.writes("PUT")} == {GROUP_ID, SECOND_ID}
    assert controller.groups[GROUP_ID]["priority"] == 600
    assert controller.groups[SECOND_ID]["priority"] == 700


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("timestamps,winner", [((10, 20), SECOND_ID), ((20, 20), GROUP_ID)])
def test_no_id_legacy_newest_and_tie_selection(invoke, state, timestamps, winner):
    """No-ID matching keeps newest selection and first-row timestamp tie behavior."""
    controller = Controller(duplicate_groups(timestamps=timestamps))
    entry = {"name": TEMPLATE, "description": DESCRIPTION}
    if state == "merged":
        entry["priority"] = 600
    result = invoke(controller, [entry], state=state)
    assert not result.get("failed"), result
    assert result["changed"] is True
    if state == "merged":
        assert [call[1].rsplit("/", 1)[-1] for call in controller.writes("PUT")] == [winner]
    else:
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [winner]}]
        assert set(controller.groups) == ({GROUP_ID, SECOND_ID} - {winner})


@pytest.mark.parametrize(
    "members", [["SERIAL_OLD_A", "SERIAL_OLD_B"], [" SERIAL_OLD_B ", "SERIAL_OLD_A", "SERIAL_OLD_B"]], ids=["exact", "normalized-reordered-duplicates"]
)
@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_pair_membership_selects_unique_older_group(invoke, members, deploy, check_mode):
    """An explicit exact member set selects its group, independent of timestamp/order."""
    records = duplicate_groups()
    records[0]["switchIds"] = ["SERIAL_OLD_A", "SERIAL_OLD_B"]
    other_id = "POLICY-GROUP-900"
    controller = Controller([*records, group(other_id, description=DESCRIPTION, templateName="other_template", switchIds=["SERIAL_OLD_A", "SERIAL_OLD_B"])])
    original = deepcopy(controller.groups)
    result = invoke(
        controller,
        [{"name": f" {TEMPLATE} ", "description": f" {DESCRIPTION} ", "switch_ids": members, "create_additional_policy": True}],
        state="deleted",
        deploy=deploy,
        check_mode=check_mode,
    )
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert "force_created" not in result
    before = snapshots_by_id(result, "before")
    assert before[GROUP_ID]["priority"] == 400
    assert before[GROUP_ID]["switch_ids"] == ["SERIAL_OLD_A", "SERIAL_OLD_B"]
    after = snapshots_by_id(result, "after")
    assert GROUP_ID not in after
    assert before[SECOND_ID]["switch_ids"] == ["SERIAL_NEW"]
    assert after[SECOND_ID] == before[SECOND_ID]
    if check_mode:
        assert controller.writes() == []
        assert controller.groups == original
    else:
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [GROUP_ID]}]
        assert set(controller.groups) == {SECOND_ID, other_id}
        assert controller.groups[SECOND_ID] == original[SECOND_ID]
        assert controller.groups[other_id] == original[other_id]
        assert [call[2] for call in controller.deployments()] == ([{"switchIds": ["SERIAL_OLD_A", "SERIAL_OLD_B"]}] if deploy else [])


@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_pair_membership_normalizes_controller_members(invoke, check_mode):
    """Controller padding and repeated members use the same normalized set identity."""
    records = duplicate_groups()
    records[0]["switchIds"] = [" SERIAL_OLD ", "SERIAL_OLD"]
    controller = Controller(records)
    result = invoke(controller, [{"name": TEMPLATE, "description": DESCRIPTION, "switch_ids": ["SERIAL_OLD"]}], state="deleted", check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert snapshots_by_id(result, "before")[GROUP_ID]["switch_ids"] == ["SERIAL_OLD", "SERIAL_OLD"]
    assert snapshots_by_id(result, "after")[SECOND_ID]["switch_ids"] == ["SERIAL_NEW"]
    if check_mode:
        assert controller.writes() == []
    else:
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [GROUP_ID]}]
        assert set(controller.groups) == {SECOND_ID}


@pytest.mark.parametrize(
    "case,members",
    [
        ("subset", ["SERIAL_OLD_A"]),
        ("superset", ["SERIAL_OLD_A", "SERIAL_OLD_B", "SERIAL_EXTRA"]),
        ("unrelated", ["SERIAL_UNKNOWN"]),
        ("ambiguous", ["SERIAL_OLD_A", "SERIAL_OLD_B"]),
        ("empty", []),
        ("invalid", [" "]),
    ],
)
@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_pair_membership_rejects_unsafe_selection(invoke, case, members, check_mode):
    """Incomplete, ambiguous or invalid member intent cannot delete the newest sibling."""
    records = duplicate_groups()
    records[0]["switchIds"] = ["SERIAL_OLD_A", "SERIAL_OLD_B"]
    if case == "ambiguous":
        records[1]["switchIds"] = ["SERIAL_OLD_B", "SERIAL_OLD_A"]
    controller = Controller(records)
    original = deepcopy(controller.groups)
    result = invoke(controller, [{"name": TEMPLATE, "description": DESCRIPTION, "switch_ids": members}], state="deleted", deploy=True, check_mode=check_mode)
    assert result["failed"] is True
    assert result["changed"] is False
    assert "switch" in result["msg"].lower() or "member" in result["msg"].lower()
    if case == "ambiguous":
        assert GROUP_ID in result["msg"] and SECOND_ID in result["msg"]
    assert controller.writes() == []
    assert controller.groups == original


@pytest.mark.parametrize("provided", ["omitted", "null"])
@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_pair_membership_omitted_or_null_keeps_legacy_winner(invoke, provided, deploy, check_mode):
    """Unspecified membership retains the existing newest-group behavior."""
    controller = Controller(duplicate_groups())
    entry = {"name": TEMPLATE, "description": DESCRIPTION}
    if provided == "null":
        entry["switch_ids"] = None
    result = invoke(controller, [entry], state="deleted", deploy=deploy, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    if check_mode:
        assert controller.writes() == []
    else:
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [SECOND_ID]}]
        assert set(controller.groups) == {GROUP_ID}
        assert [call[2] for call in controller.deployments()] == ([{"switchIds": ["SERIAL_NEW"]}] if deploy else [])


@pytest.mark.parametrize("members", [[], ["SERIAL_UNRELATED"]], ids=["empty", "unrelated"])
@pytest.mark.parametrize("selector", ["name", "policy_id", "name_precedence"])
def test_deleted_pair_membership_explicit_id_bypasses_selector(invoke, members, selector):
    """A supplied ID remains authoritative rather than becoming a membership selector."""
    controller = Controller(duplicate_groups())
    result = invoke(controller, [{**select_old(selector), "switch_ids": members}], state="deleted", deploy=True)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [GROUP_ID]}]
    assert set(controller.groups) == {SECOND_ID}
    assert [call[2] for call in controller.deployments()] == [{"switchIds": sorted({"SERIAL_OLD", *members})}]


@pytest.mark.parametrize("members,failed", [([], True), (["SERIAL_ABSENT"], False)])
@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_pair_membership_absent_pair_keeps_noop_except_empty_input(invoke, members, failed, check_mode):
    """A valid absent pair is a no-op; explicit empty selection is an input error."""
    controller = Controller(duplicate_groups())
    original = deepcopy(controller.groups)
    result = invoke(controller, [{"name": TEMPLATE, "description": "Absent", "switch_ids": members}], state="deleted", deploy=True, check_mode=check_mode)
    assert result.get("failed", False) is failed
    assert result["changed"] is False
    if failed:
        assert "switch" in result["msg"].lower() or "member" in result["msg"].lower()
    assert controller.writes() == []
    assert controller.groups == original


@pytest.mark.parametrize("earlier", ["direct", "normal", "broad"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_pair_membership_preflights_all_selectors_before_writes(invoke, earlier, check_mode):
    """A later membership mismatch stops even earlier direct or broad deletion plans."""
    other_id = "POLICY-GROUP-900"
    controller = Controller([*duplicate_groups(), group(ANONYMOUS_ID), group(other_id, templateName="other_template", description="Other")])
    original = deepcopy(controller.groups)
    first = {"name": ANONYMOUS_ID} if earlier == "direct" else {"name": "other_template", **({"description": "Other"} if earlier == "normal" else {})}
    result = invoke(
        controller,
        [first, {"name": TEMPLATE, "description": DESCRIPTION, "switch_ids": ["SERIAL_UNKNOWN"]}],
        state="deleted",
        deploy=True,
        check_mode=check_mode,
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert controller.writes() == []
    assert controller.groups == original


@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_pair_membership_matches_active_but_deploys_pending_members(invoke, check_mode):
    """Pending members affect cleanup deployment but not membership-based identity."""
    controller = Controller(
        [
            group(
                description=DESCRIPTION,
                switches=[{"switchId": "SERIAL_A", "priority": 400, "markDeleted": False}, {"switchId": "SERIAL_B", "priority": 400, "markDeleted": True}],
                updateTimestamp=10,
            ),
            group(SECOND_ID, description=DESCRIPTION, switchIds=["SERIAL_A", "SERIAL_B"], updateTimestamp=20),
        ]
    )
    result = invoke(
        controller, [{"name": TEMPLATE, "description": DESCRIPTION, "switch_ids": ["SERIAL_A"]}], state="deleted", deploy=True, check_mode=check_mode
    )
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert snapshots_by_id(result, "before")[GROUP_ID]["switch_ids"] == ["SERIAL_A"]
    if check_mode:
        assert controller.writes() == []
    else:
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [GROUP_ID]}]
        assert [call[2] for call in controller.deployments()] == [{"switchIds": ["SERIAL_A", "SERIAL_B"]}]
        assert set(controller.groups) == {SECOND_ID}


@pytest.mark.parametrize("empty_inventory", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_pair_membership_whitespace_description_cannot_select_anonymous(invoke, empty_inventory, check_mode):
    """An unusable supplied pair fails rather than becoming broad or anonymous intent."""
    controller = Controller([] if empty_inventory else [group(description="Existing"), group(ANONYMOUS_ID, description="", switchIds=["SERIAL_A"])])
    original = deepcopy(controller.groups)
    result = invoke(controller, [{"name": TEMPLATE, "description": " ", "switch_ids": ["SERIAL_A"]}], state="deleted", deploy=True, check_mode=check_mode)
    assert result["failed"] is True
    assert result["changed"] is False
    assert "description" in result["msg"].lower()
    assert controller.writes() == []
    assert controller.groups == original


@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_pair_membership_resolves_ip_before_selection(invoke, monkeypatch, check_mode):
    """The existing inventory resolver feeds serial membership to exact selection."""
    from types import SimpleNamespace

    from ansible_collections.cisco.nd.plugins.modules import nd_manage_policy_group

    inventory_reads = []

    def from_fabric(_cls, client, fabric_name, _log, model_class):
        inventory_reads.append(fabric_name)
        assert client.rest_send.check_mode is False
        return SimpleNamespace(by_ip=lambda: {"192.0.2.10": SimpleNamespace(switch_id="SERIAL_OLD")})

    monkeypatch.setattr(nd_manage_policy_group.FabricSwitchInventory, "from_fabric", classmethod(from_fabric))
    controller = Controller(duplicate_groups())
    result = invoke(
        controller, [{"name": TEMPLATE, "description": DESCRIPTION, "switch_ids": ["192.0.2.10"]}], state="deleted", deploy=True, check_mode=check_mode
    )
    assert not result.get("failed"), result
    assert inventory_reads == ["FABRIC_A"]
    assert result["changed"] is True
    assert snapshots_by_id(result, "before")[GROUP_ID]["switch_ids"] == ["SERIAL_OLD"]
    assert GROUP_ID not in snapshots_by_id(result, "after")
    if check_mode:
        assert controller.writes() == []
    else:
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [GROUP_ID]}]
        assert [call[2] for call in controller.deployments()] == [{"switchIds": ["SERIAL_OLD"]}]


@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_pair_membership_pins_pending_cleanup_to_selected_active_id(invoke, check_mode):
    """Normalized active selection cannot additionally deploy a pending same-pair sibling."""
    pending_id = "POLICY-GROUP-900"
    controller = Controller(
        [
            *duplicate_groups(),
            group(
                pending_id,
                description=f" {DESCRIPTION} ",
                markDeleted=True,
                switches=[{"switchId": "SERIAL_PENDING_SIBLING", "priority": 500, "markDeleted": True}],
            ),
        ]
    )
    result = invoke(
        controller,
        [{"name": f" {TEMPLATE} ", "description": f" {DESCRIPTION} ", "switch_ids": ["SERIAL_OLD"]}],
        state="deleted",
        deploy=True,
        check_mode=check_mode,
    )
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert snapshots_by_id(result, "before")[GROUP_ID]["switch_ids"] == ["SERIAL_OLD"]
    assert "pending_deleted_cleanup" not in result
    if check_mode:
        assert controller.writes() == []
    else:
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [GROUP_ID]}]
        assert [call[2] for call in controller.deployments()] == [{"switchIds": ["SERIAL_OLD"]}]
        assert set(controller.groups) == {SECOND_ID, pending_id}


@pytest.mark.parametrize("provided", ["omitted", "null"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_pair_membership_keeps_legacy_pending_cleanup_when_unsupplied(invoke, provided, check_mode):
    """The new membership selector cannot alter omitted/null pending-cleanup targets."""
    pending_id = "POLICY-GROUP-900"
    controller = Controller(
        [
            group(description=DESCRIPTION, switchIds=["SERIAL_ACTIVE"]),
            group(
                pending_id, description=f" {DESCRIPTION} ", markDeleted=True, switches=[{"switchId": "SERIAL_PENDING", "priority": 500, "markDeleted": True}]
            ),
        ]
    )
    entry = {"name": TEMPLATE, "description": f" {DESCRIPTION} "}
    if provided == "null":
        entry["switch_ids"] = None
    result = invoke(controller, [entry], state="deleted", deploy=True, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    if check_mode:
        assert result["pending_deleted_cleanup"]["switch_ids"] == ["SERIAL_PENDING"]
        assert controller.writes() == []
    else:
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [GROUP_ID]}]
        assert [call[2] for call in controller.deployments()] == [{"switchIds": ["SERIAL_ACTIVE", "SERIAL_PENDING"]}]
        assert set(controller.groups) == {pending_id}


@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_pair_membership_does_not_change_merged_member_updates(invoke, check_mode):
    """Merged membership remains writable intent for the existing newest winner."""
    controller = Controller(duplicate_groups())
    original_old = deepcopy(controller.groups[GROUP_ID])
    result = invoke(controller, [config(name=TEMPLATE, description=DESCRIPTION, switch_ids=["SERIAL_OLD"], priority=600)], check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert snapshots_by_id(result, "after")[SECOND_ID]["switch_ids"] == ["SERIAL_OLD"]
    assert snapshots_by_id(result, "after")[SECOND_ID]["priority"] == 600
    assert controller.groups[GROUP_ID] == original_old
    if check_mode:
        assert controller.writes() == []
    else:
        assert {call[1].rsplit("/", 1)[-1] for call in controller.writes("PUT")} == {SECOND_ID}


@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_pair_membership_does_not_reject_empty_template_wide_selector(invoke, check_mode):
    """Explicit empty membership is forbidden only for no-ID described selectors."""
    controller = Controller([*duplicate_groups(), group(ANONYMOUS_ID)])
    result = invoke(controller, [{"name": TEMPLATE, "switch_ids": []}], state="deleted", deploy=True, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    if check_mode:
        assert controller.writes() == []
    else:
        assert {pid for call in mark_delete_calls(controller) for pid in call[2]["policyIds"]} == {GROUP_ID, SECOND_ID, ANONYMOUS_ID}
        assert controller.groups == {}


@pytest.mark.parametrize("second_members", ["provided", "omitted", "null"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_pair_membership_keeps_normalized_duplicate_proposal_failure(invoke, second_members, check_mode):
    """Membership cannot make unsupported duplicate no-ID proposals independent."""
    controller = Controller(duplicate_groups())
    original = deepcopy(controller.groups)
    entries = [
        {"name": TEMPLATE, "description": DESCRIPTION, "switch_ids": ["SERIAL_OLD"]},
        {"name": f" {TEMPLATE} ", "description": f" {DESCRIPTION} "},
    ]
    if second_members != "omitted":
        entries[1]["switch_ids"] = ["SERIAL_NEW"] if second_members == "provided" else None
    result = invoke(controller, entries, state="deleted", deploy=True, check_mode=check_mode)
    assert result["failed"] is True
    assert result["changed"] is False
    assert "duplicate" in result["msg"].lower() or "identifier" in result["msg"].lower()
    assert controller.writes() == []
    assert controller.groups == original


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_raw_duplicate_proposals_keep_existing_preflight_shape(invoke, state, check_mode):
    """Adding changed=false for normalized duplicates must preserve raw failure output."""
    controller = Controller(duplicate_groups())
    original = deepcopy(controller.groups)
    entry = {"name": TEMPLATE, "description": DESCRIPTION}
    result = invoke(controller, [entry, deepcopy(entry)], state=state, deploy=True, check_mode=check_mode)
    assert result["failed"] is True
    assert "Duplicate" in result["msg"]
    assert "changed" not in result
    assert controller.writes() == []
    assert controller.groups == original


def deleted_selector(selector):
    """Return normal selectors and their existing matched IDs/member sets."""
    groups = duplicate_groups()
    if selector == "pair":
        return groups, {"name": TEMPLATE, "description": DESCRIPTION}, SECOND_ID, ["SERIAL_NEW"]
    if selector == "id":
        return groups, {"name": GROUP_ID}, GROUP_ID, ["SERIAL_OLD"]
    if selector == "policy_id":
        return groups, {"name": TEMPLATE, "policy_id": GROUP_ID, "description": DESCRIPTION}, GROUP_ID, ["SERIAL_OLD"]
    if selector == "template":
        return [group(description="Unique")], {"name": TEMPLATE}, GROUP_ID, ["SERIAL_A", "SERIAL_B"]
    if selector == "missing_id":
        return groups, {"name": MISSING_ID}, None, []
    if selector == "missing_pair":
        return groups, {"name": TEMPLATE, "description": "Missing"}, None, []
    anonymous = group(ANONYMOUS_ID, description=None, switchIds=["SERIAL_ANONYMOUS"])
    if selector == "anonymous_id":
        return [anonymous], {"name": ANONYMOUS_ID, "switch_ids": ["SERIAL_ANONYMOUS"]}, ANONYMOUS_ID, ["SERIAL_ANONYMOUS"]
    return [anonymous], {"name": TEMPLATE, "policy_id": ANONYMOUS_ID, "switch_ids": ["SERIAL_ANONYMOUS"]}, ANONYMOUS_ID, ["SERIAL_ANONYMOUS"]


@pytest.mark.parametrize("selector", ["pair", "id", "policy_id", "template", "missing_id", "missing_pair", "anonymous_id", "anonymous_policy_id"])
@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_deleted_force_flag_never_creates(invoke, selector, deploy, check_mode):
    """A merged-only creation flag cannot transform deletion into creation."""
    groups, entry, expected_id, expected_members = deleted_selector(selector)
    controller = Controller(groups)
    result = invoke(controller, [{**entry, "create_additional_policy": True}], state="deleted", deploy=deploy, check_mode=check_mode)
    assert not result.get("failed"), result
    assert not any(call[0] == "POST" and call[1].endswith("/policyGroups") for call in controller.calls)
    assert "force_created" not in result
    assert result["changed"] is bool(expected_id)
    if check_mode:
        assert controller.writes() == []
    elif expected_id:
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [expected_id]}]
        assert expected_id not in controller.groups
        assert len(controller.deployments()) == int(deploy)
        if deploy:
            assert controller.deployments()[0][2] == {"switchIds": expected_members}
    else:
        assert controller.writes() == []


@pytest.mark.parametrize("use_id", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_merged_force_creation_is_preserved(invoke, use_id, check_mode):
    """Deliberate merged creation remains available for both naming forms."""
    controller = Controller(duplicate_groups())
    entry = config(name=GROUP_ID if use_id else TEMPLATE, description=DESCRIPTION, create_additional_policy=True)
    result = invoke(controller, [entry], check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert len(result["force_created"]) == 1
    if check_mode:
        assert "policy_id" not in result["force_created"][0]
        assert controller.writes() == []
    else:
        assert result["force_created"][0]["policy_id"] == "POLICY-GROUP-200"
        assert len(controller.groups) == 3
        assert len(controller.writes("POST")) == 1


@pytest.mark.parametrize("kind", ["duplicate", "anonymous", "mixed"])
@pytest.mark.parametrize("force_flag", [False, True])
@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_template_only_delete_selects_all_duplicate_and_anonymous_ids(invoke, kind, force_flag, deploy, check_mode):
    """A template-wide selector removes every matching ID, preserving other templates."""
    selected = []
    if kind in {"duplicate", "mixed"}:
        selected.extend(duplicate_groups())
    if kind in {"anonymous", "mixed"}:
        selected.extend([group(ANONYMOUS_ID, switchIds=["SERIAL_ANON"]), group("POLICY-GROUP-104", description="", switchIds=["SERIAL_EMPTY"])])
    keep_id = "POLICY-GROUP-900"
    controller = Controller([*selected, group(keep_id, description="Keep", templateName="other_template", switchIds=["SERIAL_KEEP"])])
    original = deepcopy(controller.groups)
    result = invoke(controller, [{"name": TEMPLATE, "create_additional_policy": force_flag}], state="deleted", deploy=deploy, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert "force_created" not in result
    target_ids = {item["policyId"] for item in selected}
    if "before" in result:
        assert {item["policyId"] for item in selected if item.get("description")} <= {item["policy_id"] for item in result["before"]}
        assert {item["policy_id"] for item in result["after"]} == {keep_id}
    if check_mode:
        assert controller.writes() == []
        assert controller.groups == original
    else:
        requested_ids = [pid for call in mark_delete_calls(controller) for pid in call[2]["policyIds"]]
        assert set(requested_ids) == target_ids
        assert len(requested_ids) == len(target_ids)
        assert set(controller.groups) == {keep_id}
        deployed = {sid for call in controller.deployments() for sid in call[2]["switchIds"]}
        assert deployed == ({sid for item in selected for sid in item["switchIds"]} if deploy else set())


@pytest.mark.parametrize("broad_first", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_template_only_delete_coalesces_overlapping_selectors(invoke, broad_first, check_mode):
    """Repeated broad and overlapping narrow selectors delete each exact ID once."""
    controller = Controller(duplicate_groups())
    broad = {"name": TEMPLATE, "switch_ids": ["SERIAL_BROAD_EXTRA"]}
    narrow = [{"name": GROUP_ID, "switch_ids": ["SERIAL_ID_EXTRA"]}, {"name": TEMPLATE, "description": DESCRIPTION, "switch_ids": ["SERIAL_NEW"]}]
    entries = [broad, *narrow, deepcopy(broad)] if broad_first else [*narrow, broad, deepcopy(broad)]
    result = invoke(controller, entries, state="deleted", deploy=True, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    if check_mode:
        assert controller.writes() == []
    else:
        requested_ids = [pid for call in mark_delete_calls(controller) for pid in call[2]["policyIds"]]
        assert requested_ids == [GROUP_ID, SECOND_ID]
        assert controller.groups == {}
        assert {sid for call in controller.deployments() for sid in call[2]["switchIds"]} == {
            "SERIAL_OLD",
            "SERIAL_NEW",
            "SERIAL_BROAD_EXTRA",
            "SERIAL_ID_EXTRA",
        }


@pytest.mark.parametrize("check_mode", [False, True])
def test_template_only_delete_preserves_other_template_pair_winner(invoke, check_mode):
    """A broad request does not broaden a separate description/template selector."""
    controller = Controller([*duplicate_groups(), group(ANONYMOUS_ID, templateName="other_template", description="Other")])
    result = invoke(
        controller,
        [{"name": "other_template"}, {"name": TEMPLATE, "description": DESCRIPTION}],
        state="deleted",
        check_mode=check_mode,
    )
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert not ({ANONYMOUS_ID, SECOND_ID} & set(snapshots_by_id(result, "after")))
    if check_mode:
        assert controller.writes() == []
    else:
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [ANONYMOUS_ID, SECOND_ID]}]
        assert set(controller.groups) == {GROUP_ID}


@pytest.mark.parametrize("failure", ["second-delete", "deploy"])
def test_template_only_delete_retains_accepted_progress_on_failure(invoke, failure):
    """Broad exact-ID plans retain accepted deletion and original rejected siblings."""
    from ansible_collections.cisco.nd.tests.unit.modules.test_nd_policy_group_reporting import RejectingController

    controller = RejectingController(
        duplicate_groups(),
        partial_delete=failure == "second-delete",
        rejected_ids=[SECOND_ID],
        reject_deploy=failure == "deploy",
    )
    result = invoke(controller, [{"name": TEMPLATE}], state="deleted", deploy=True)
    assert result["failed"] is True
    assert result["changed"] is True
    assert set(snapshots_by_id(result, "before")) == {GROUP_ID, SECOND_ID}
    assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [GROUP_ID, SECOND_ID]}]
    if failure == "second-delete":
        assert set(snapshots_by_id(result, "after")) == {SECOND_ID}
        assert set(controller.groups) == {SECOND_ID}
        assert [call[1].rsplit("/", 1)[-1] for call in controller.writes("DELETE")] == [SECOND_ID]
        assert controller.deployments() == []
    else:
        assert snapshots_by_id(result, "after") == {}
        assert controller.groups == {}
        assert [call[2] for call in controller.deployments()] == [{"switchIds": ["SERIAL_NEW", "SERIAL_OLD"]}]


@pytest.mark.parametrize("include_broad", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_template_only_delete_does_not_broaden_whitespace_description(invoke, include_broad, check_mode):
    """A nonempty raw description never becomes a template-wide selector."""
    keep_id = "POLICY-GROUP-900"
    records = [*duplicate_groups(), group(ANONYMOUS_ID, description=""), group(keep_id, description="Other", templateName="other_template")]
    controller = Controller(records)
    entries = [{"name": TEMPLATE, "description": " "}]
    if include_broad:
        entries.append({"name": "other_template"})
    result = invoke(controller, entries, state="deleted", check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is include_broad
    if check_mode:
        assert controller.writes() == []
    else:
        assert set(controller.groups) == ({item["policyId"] for item in records} - ({keep_id} if include_broad else set()))


@pytest.mark.parametrize("missing_id", [None, ""])
@pytest.mark.parametrize("check_mode", [False, True])
def test_template_only_delete_rejects_selected_row_without_id(invoke, missing_id, check_mode):
    """Malformed selected inventory cannot fall back to a sibling's composite identity."""

    class MissingIdController(Controller):
        @staticmethod
        def summary(current):
            result = Controller.summary(current)
            if current["policyId"] == ANONYMOUS_ID:
                result.update(policyId=missing_id, policyType="group")
            return result

    controller = MissingIdController([group(description="Valid"), group(ANONYMOUS_ID, description="Malformed")])
    original = deepcopy(controller.groups)
    result = invoke(controller, [{"name": TEMPLATE}], state="deleted", deploy=True, check_mode=check_mode)
    assert result["failed"] is True
    assert result.get("changed", False) is False
    assert "id" in result["msg"].lower()
    assert controller.writes() == []
    assert controller.groups == original


@pytest.mark.parametrize("check_mode", [False, True])
def test_template_only_delete_carries_active_pending_and_linked_members(invoke, check_mode):
    """Every provable selected removal member survives normal/direct planning."""
    pending_id, child_id = "POLICY-GROUP-201", "POLICY-GROUP-202"
    controller = Controller(
        [
            group(
                description=DESCRIPTION,
                switches=[
                    {"switchId": "SERIAL_ACTIVE", "priority": 500, "markDeleted": False},
                    {"switchId": "SERIAL_PENDING", "priority": 500, "markDeleted": True},
                ],
            ),
            group(SECOND_ID, description=DESCRIPTION, switchIds=["SERIAL_DUPLICATE"]),
            group(ANONYMOUS_ID, switchIds=["SERIAL_ANON"]),
            group(
                pending_id, description="Fully pending", markDeleted=True, switches=[{"switchId": "SERIAL_FULL_PENDING", "priority": 500, "markDeleted": True}]
            ),
            group(
                child_id,
                description=DESCRIPTION,
                templateName="generated_other_template",
                source=GROUP_ID,
                markDeleted=True,
                switches=[{"switchId": "SERIAL_CHILD", "priority": 500, "markDeleted": True}],
            ),
        ]
    )
    result = invoke(controller, [{"name": TEMPLATE}], state="deleted", deploy=True, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    if check_mode:
        assert controller.writes() == []
    else:
        requested_ids = [pid for call in mark_delete_calls(controller) for pid in call[2]["policyIds"]]
        assert set(requested_ids) == {GROUP_ID, SECOND_ID, ANONYMOUS_ID}
        assert {sid for call in controller.deployments() for sid in call[2]["switchIds"]} == {
            "SERIAL_ACTIVE",
            "SERIAL_PENDING",
            "SERIAL_DUPLICATE",
            "SERIAL_ANON",
            "SERIAL_FULL_PENDING",
            "SERIAL_CHILD",
        }


@pytest.mark.parametrize("check_mode", [False, True])
def test_template_only_pending_delete_unions_caller_cleanup_targets(invoke, check_mode):
    """A proven pending match carries both cached members and explicit cleanup extras."""
    controller = Controller(
        [
            group(
                description="Pending",
                markDeleted=True,
                switchIds=["SERIAL_PENDING"],
                switches=[{"switchId": "SERIAL_PENDING", "priority": 500, "markDeleted": True}],
            )
        ]
    )
    original = deepcopy(controller.groups)
    result = invoke(
        controller,
        [{"name": TEMPLATE, "switch_ids": ["SERIAL_EXTRA", "SERIAL_EXTRA"], "template_inputs": ["unused in deletion"]}],
        state="deleted",
        deploy=True,
        check_mode=check_mode,
    )
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert result["pending_deleted_cleanup"]["switch_ids"] == ["SERIAL_EXTRA", "SERIAL_PENDING"]
    assert mark_delete_calls(controller) == []
    assert controller.groups == original
    if check_mode:
        assert controller.writes() == []
    else:
        assert [call[2] for call in controller.deployments()] == [{"switchIds": ["SERIAL_EXTRA", "SERIAL_PENDING"]}]


@pytest.mark.parametrize("provided", [[" "], [17]], ids=["whitespace", "non-string"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_template_only_pending_delete_preflights_caller_members(invoke, provided, check_mode):
    """Pending-only planning cannot bypass switch-ID validation or mutate other groups first."""
    controller = Controller(
        [
            group(description="Active", templateName="other_template"),
            group(
                SECOND_ID,
                description="Pending",
                markDeleted=True,
                switchIds=["SERIAL_PENDING"],
                switches=[{"switchId": "SERIAL_PENDING", "priority": 500, "markDeleted": True}],
            ),
        ]
    )
    original = deepcopy(controller.groups)
    result = invoke(
        controller,
        [{"name": "other_template"}, {"name": TEMPLATE, "switch_ids": provided}],
        state="deleted",
        deploy=True,
        check_mode=check_mode,
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert "switch" in result["msg"].lower()
    assert controller.writes() == []
    assert controller.groups == original


@pytest.mark.parametrize("selector", ["pair", "template"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_template_pending_orphan_reports_visible_exact_id_requirement(invoke, selector, check_mode):
    """Unprovable original templates produce a visible skip instead of a false match."""
    parent_id = "POLICY-GROUP-999"
    controller = Controller(
        [
            group(
                ANONYMOUS_ID,
                description=DESCRIPTION,
                templateName="generated_other_template",
                source=parent_id,
                markDeleted=True,
                switches=[{"switchId": "SERIAL_UNKNOWN", "priority": 500, "markDeleted": True}],
            )
        ]
    )
    entry = {"name": TEMPLATE, "switch_ids": ["SERIAL_MUST_NOT_DEPLOY"], **({"description": DESCRIPTION} if selector == "pair" else {})}
    result = invoke(controller, [entry], state="deleted", deploy=True, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is False
    skips = result["pending_deleted_cleanup"]["skipped"]
    assert len(skips) == 1
    assert skips[0]["reason_code"] == "unresolved_original_template"
    assert skips[0]["policy_group_id"] == parent_id
    assert skips[0]["matched_policy_ids"] == [ANONYMOUS_ID]
    assert len(controller.warnings) == 1
    assert parent_id in controller.warnings[0]
    assert controller.writes() == []


@pytest.mark.parametrize("entry", [{"name": MISSING_ID}, {"name": TEMPLATE, "description": "Missing"}, {"name": TEMPLATE}])
def test_plain_absent_delete_keeps_existing_no_warning_shape(invoke, entry):
    controller = Controller()
    result = invoke(controller, [{**entry, "switch_ids": ["SERIAL_MUST_NOT_DEPLOY"]}], state="deleted", deploy=True)
    assert not result.get("failed"), result
    assert result["changed"] is False
    assert "pending_deleted_cleanup" not in result
    assert controller.warnings == []
    assert controller.writes() == []


def test_gathered_preserves_distinct_duplicate_ids(invoke):
    """Read-only gathered output keeps every active ID despite composite clashes."""
    controller = Controller(duplicate_groups())
    result = invoke(controller, None, state="gathered")
    assert not result.get("failed"), result
    assert result["changed"] is False
    assert {item["policy_id"] for item in result["gathered"]} == {GROUP_ID, SECOND_ID}
    assert controller.writes() == []


@pytest.mark.parametrize("anonymous", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_gathered_explicit_ids_replay_without_mutation(invoke, anonymous, check_mode):
    """Gathered policy_id fields remain authoritative during merged replay."""
    controller = Controller([group()] if anonymous else duplicate_groups())
    before = deepcopy(controller.groups)
    gathered = invoke(controller, None, state="gathered")
    result = invoke(controller, gathered["gathered"], check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is False
    assert controller.writes() == []
    assert controller.groups == before


@pytest.mark.parametrize("check_mode", [False, True])
def test_fully_pending_cleanup_uses_name_id_precedence(invoke, check_mode):
    """Conflicting alias IDs follow the same name precedence during cleanup."""

    class PendingController(Controller):
        @staticmethod
        def summary(current):
            result = Controller.summary(current)
            if current.get("markDeleted"):
                for switch in result["switches"]:
                    switch["markDeleted"] = True
            return result

    controller = PendingController(
        [
            group("POLICY-GROUP-201", source=GROUP_ID, markDeleted=True, switchIds=["SERIAL_PENDING_OLD"]),
            group("POLICY-GROUP-202", source=SECOND_ID, markDeleted=True, switchIds=["SERIAL_PENDING_NEW"]),
        ]
    )
    result = invoke(controller, [{"name": GROUP_ID, "policy_id": SECOND_ID}], state="deleted", deploy=True, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert result["pending_deleted_cleanup"]["switch_ids"] == ["SERIAL_PENDING_OLD"]
    if check_mode:
        assert controller.writes() == []
    else:
        assert [call[2] for call in controller.deployments()] == [{"switchIds": ["SERIAL_PENDING_OLD"]}]
        assert len(controller.writes()) == 1


def test_new_group_identity_survives_server_id_and_rerun(invoke):
    """Server ID assignment cannot invalidate a newly created collection key."""
    controller = Controller()
    entry = config(name=TEMPLATE, description="Created normally")
    first = invoke(controller, [entry])
    assert not first.get("failed"), first
    assert first["changed"] is True
    assert first["after"][0]["policy_id"] == "POLICY-GROUP-200"
    assert "execution_key" not in json.dumps(first)
    assert len(controller.writes("POST")) == 1
    controller.calls.clear()
    second = invoke(controller, [entry])
    assert not second.get("failed"), second
    assert second["changed"] is False
    assert controller.writes() == []


def test_unchanged_older_id_explicit_deploy_keeps_exact_members(invoke):
    """A deploy-only request targets the exact unchanged ID's own switches."""
    controller = Controller(duplicate_groups())
    result = invoke(
        controller,
        [{"name": GROUP_ID, "priority": 400, "switch_ids": ["SERIAL_OLD"], "template_inputs": {"featureName": "lacp"}}],
        deploy=True,
    )
    assert not result.get("failed"), result
    assert result["changed"] is False
    assert controller.writes("PUT") == []
    assert [call[2] for call in controller.deployments()] == [{"switchIds": ["SERIAL_OLD"]}]


def test_force_then_normal_pair_preserves_latest_selection_timing(invoke):
    """No-ID matching sees force-created state at the same point as before."""

    class TimestampController(Controller):
        def request(self, verb, path, payload):
            response = super().request(verb, path, payload)
            if verb == "POST" and path.endswith("/policyGroups"):
                for item in response["DATA"]["policyGroups"]:
                    self.groups[item["policyId"]]["updateTimestamp"] = 100
            return response

    controller = TimestampController(duplicate_groups())
    entries = [
        {"name": GROUP_ID, "priority": 450, "switch_ids": ["SERIAL_OLD"], "template_inputs": {"featureName": "lacp"}, "create_additional_policy": True},
        {"name": TEMPLATE, "description": DESCRIPTION, "priority": 700},
    ]
    result = invoke(controller, entries)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert [call[0] for call in controller.writes()] == ["POST", "PUT"]
    assert controller.writes("PUT")[0][1].endswith("/policyGroups/POLICY-GROUP-200")
    assert controller.groups[GROUP_ID]["priority"] == 400
    assert controller.groups[SECOND_ID]["priority"] == 500
    assert controller.groups["POLICY-GROUP-200"]["priority"] == 700


@pytest.mark.parametrize("duplicate", [False, True])
def test_failed_update_keeps_public_identifier_diagnostics(invoke, duplicate):
    """Internal execution identity must not leak into existing error labels."""
    from ansible_collections.cisco.nd.tests.unit.modules.test_nd_policy_group_reporting import RejectingController

    controller = RejectingController(duplicate_groups() if duplicate else [group(description=DESCRIPTION)], rejected_ids=[GROUP_ID])
    result = invoke(controller, [{"name": GROUP_ID, "priority": 600}])
    assert result.get("failed") is True
    assert f"({DESCRIPTION!r}, {TEMPLATE!r})" in result["msg"]
    assert "execution_key" not in result["msg"]
    assert "('policy_id'," not in result["msg"]
    assert "Rejected priority by controller" in result["msg"]


@pytest.mark.parametrize("force_flag", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_anonymous_delete_omitted_members_deploys_exact_group(invoke, force_flag, check_mode):
    """An ID-only delete infers every exact target member without another GET."""
    controller = Controller([group(ANONYMOUS_ID, switchIds=["SERIAL_B", "SERIAL_A"]), group(GROUP_ID, switchIds=["SERIAL_OTHER"])])
    original = deepcopy(controller.groups)
    result = invoke(
        controller,
        [{"name": ANONYMOUS_ID, "create_additional_policy": force_flag}],
        state="deleted",
        deploy=True,
        check_mode=check_mode,
    )
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert "force_created" not in result
    assert set(result["direct_actions"]["deleted"][0]["switch_ids"]) == {"SERIAL_A", "SERIAL_B"}
    assert controller.groups[GROUP_ID] == original[GROUP_ID]
    assert len([call for call in controller.calls if call[0] == "GET"]) == 1
    if check_mode:
        assert controller.writes() == []
        assert controller.groups == original
    else:
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [ANONYMOUS_ID]}]
        assert [call[2] for call in controller.deployments()] == [{"switchIds": ["SERIAL_A", "SERIAL_B"]}]
        assert ANONYMOUS_ID not in controller.groups


@pytest.mark.parametrize(
    "selector,provided,expected_reported",
    [
        ("policy_id", None, ["SERIAL_A", "SERIAL_B"]),
        ("changed_description", None, ["SERIAL_A", "SERIAL_B"]),
        ("name", ["SERIAL_B"], ["SERIAL_B", "SERIAL_A"]),
        ("name", ["SERIAL_B", "SERIAL_EXTRA", "SERIAL_B"], ["SERIAL_B", "SERIAL_EXTRA", "SERIAL_B", "SERIAL_A"]),
    ],
    ids=["separate-policy-id", "described-direct-delete", "caller-subset", "caller-extra-and-duplicates"],
)
@pytest.mark.parametrize("check_mode", [False, True])
def test_direct_delete_effective_members_preserve_caller_targets(invoke, selector, provided, expected_reported, check_mode):
    """Current members cannot be omitted, while explicitly requested cleanup targets remain."""
    controller = Controller([group(ANONYMOUS_ID, description="Original" if selector == "changed_description" else None, switchIds=["SERIAL_A", "SERIAL_B"])])
    entry = {"name": TEMPLATE, "policy_id": ANONYMOUS_ID} if selector == "policy_id" else {"name": ANONYMOUS_ID}
    if selector == "changed_description":
        entry["description"] = "Different delete description"
    if provided is not None:
        entry["switch_ids"] = provided
    result = invoke(controller, [entry], state="deleted", deploy=True, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert result["direct_actions"]["deleted"][0]["switch_ids"] == expected_reported
    assert len([call for call in controller.calls if call[0] == "GET"]) == 1
    if check_mode:
        assert controller.writes() == []
    else:
        assert [call[2] for call in controller.deployments()] == [{"switchIds": sorted(set(expected_reported))}]


@pytest.mark.parametrize("check_mode", [False, True])
def test_anonymous_delete_without_deploy_keeps_omitted_member_contract(invoke, check_mode):
    """Staging-only deletion does not infer members or add deployment validation."""
    controller = Controller([group(ANONYMOUS_ID, switchIds=[])])
    result = invoke(controller, [{"name": ANONYMOUS_ID}], state="deleted", deploy=False, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert result["direct_actions"]["deleted"][0]["switch_ids"] == []
    assert controller.deployments() == []
    assert len(controller.writes()) == int(not check_mode)


@pytest.mark.parametrize("caller_fallback", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_anonymous_delete_preflights_all_members_before_any_write(invoke, caller_fallback, check_mode):
    """Unusable later membership fails the whole direct-delete plan before markDelete."""
    controller = Controller([group(GROUP_ID, switchIds=["SERIAL_A"]), group(ANONYMOUS_ID, switchIds=[])])
    original = deepcopy(controller.groups)
    later = {"name": ANONYMOUS_ID}
    if caller_fallback:
        later["switch_ids"] = ["SERIAL_FALLBACK"]
    result = invoke(controller, [{"name": GROUP_ID}, later], state="deleted", deploy=True, check_mode=check_mode)
    assert result.get("failed", False) is (not caller_fallback)
    assert result["changed"] is caller_fallback
    assert len([call for call in controller.calls if call[0] == "GET"]) == 1
    if not caller_fallback:
        assert ANONYMOUS_ID in result["msg"]
        assert "switch" in result["msg"].lower() or "member" in result["msg"].lower()
    if check_mode or not caller_fallback:
        assert controller.writes() == []
        assert controller.groups == original
    else:
        assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [GROUP_ID, ANONYMOUS_ID]}]
        assert [call[2] for call in controller.deployments()] == [{"switchIds": ["SERIAL_A", "SERIAL_FALLBACK"]}]


def test_anonymous_bulk_delete_deploys_overlapping_members_once(invoke):
    """Two inferred groups share one consolidated switch deployment."""
    controller = Controller([group(GROUP_ID, switchIds=["SERIAL_A", "SERIAL_B"]), group(ANONYMOUS_ID, switchIds=["SERIAL_B", "SERIAL_C"])])
    result = invoke(controller, [{"name": GROUP_ID}, {"name": ANONYMOUS_ID}], state="deleted", deploy=True)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [GROUP_ID, ANONYMOUS_ID]}]
    assert [call[2] for call in controller.deployments()] == [{"switchIds": ["SERIAL_A", "SERIAL_B", "SERIAL_C"]}]
    assert len([call for call in controller.calls if call[0] == "GET"]) == 1
    assert controller.groups == {}


@pytest.mark.parametrize("reject_deploy", [False, True])
def test_anonymous_delete_inferred_members_survive_delete_fallback(invoke, reject_deploy):
    """Inferred deployment survives direct-DELETE fallback and retains accepted failure state."""
    from ansible_collections.cisco.nd.tests.unit.modules.test_nd_policy_group_reporting import RejectingController

    class FallbackController(RejectingController):
        def request(self, verb, path, payload):
            if verb == "POST" and path.endswith("/markDelete"):
                self.calls.append((verb, path, deepcopy(payload)))
                return {
                    "RETURN_CODE": 207,
                    "METHOD": verb,
                    "REQUEST_PATH": path,
                    "MESSAGE": "Multi-Status",
                    "DATA": {"policyGroups": [{"policyId": ANONYMOUS_ID, "status": "failed", "message": "retry direct delete"}]},
                }
            if verb == "DELETE":
                self.calls.append((verb, path, deepcopy(payload)))
                self.groups.pop(path.rsplit("/", 1)[-1])
                return {"RETURN_CODE": 200, "METHOD": verb, "REQUEST_PATH": path, "MESSAGE": "OK", "DATA": {}}
            return super().request(verb, path, payload)

    controller = FallbackController([group(ANONYMOUS_ID, switchIds=["SERIAL_A", "SERIAL_B"])], reject_deploy=reject_deploy)
    result = invoke(controller, [{"name": ANONYMOUS_ID}], state="deleted", deploy=True)
    assert result.get("failed", False) is reject_deploy
    assert result["changed"] is True
    assert [item["policy_id"] for item in result["direct_actions"]["deleted"]] == [ANONYMOUS_ID]
    assert result["direct_actions"]["deleted"][0]["switch_ids"] == ["SERIAL_A", "SERIAL_B"]
    assert [call[1].rsplit("/", 1)[-1] for call in controller.writes("DELETE")] == [ANONYMOUS_ID]
    assert [call[2] for call in controller.deployments()] == [{"switchIds": ["SERIAL_A", "SERIAL_B"]}]
    assert len([call for call in controller.calls if call[0] == "GET"]) == 1
    assert controller.groups == {}
    if reject_deploy:
        assert "Rejected priority by controller" in result["msg"]


def test_anonymous_delete_inferred_members_keep_partial_failure_progress(invoke):
    """Member inference does not erase accepted deletions when another fallback fails."""
    from ansible_collections.cisco.nd.tests.unit.modules.test_nd_policy_group_reporting import RejectingController

    controller = RejectingController(
        [group(GROUP_ID, switchIds=["SERIAL_A"]), group(ANONYMOUS_ID, switchIds=["SERIAL_B"])],
        partial_delete=True,
        rejected_ids=[ANONYMOUS_ID],
    )
    result = invoke(controller, [{"name": GROUP_ID}, {"name": ANONYMOUS_ID}], state="deleted", deploy=True)
    assert result["failed"] is True
    assert result["changed"] is True
    assert [item["policy_id"] for item in result["direct_actions"]["deleted"]] == [GROUP_ID]
    assert result["direct_actions"]["deleted"][0]["switch_ids"] == ["SERIAL_A"]
    assert set(controller.groups) == {ANONYMOUS_ID}
    assert controller.deployments() == []


@pytest.mark.parametrize("provided", [[" "], [17]], ids=["whitespace", "non-string-model-value"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_direct_delete_inference_does_not_sanitize_invalid_caller_members(invoke, provided, check_mode):
    """Inferred valid members cannot hide invalid values from model validation."""
    controller = Controller([group(ANONYMOUS_ID, switchIds=["SERIAL_A"])])
    original = deepcopy(controller.groups)
    result = invoke(controller, [{"name": ANONYMOUS_ID, "switch_ids": provided}], state="deleted", deploy=True, check_mode=check_mode)
    assert result["failed"] is True
    assert result["changed"] is False
    assert "switch" in result["msg"].lower()
    assert controller.writes() == []
    assert controller.groups == original


@pytest.mark.parametrize("check_mode", [False, True])
def test_direct_delete_inference_includes_mixed_pending_members(invoke, check_mode):
    """Use both active and pending members from the same exact cached group."""
    controller = Controller(
        [
            group(
                ANONYMOUS_ID,
                switchIds=["SERIAL_ACTIVE", "SERIAL_PENDING"],
                switches=[
                    {"switchId": "SERIAL_ACTIVE", "priority": 500, "markDeleted": False},
                    {"switchId": "SERIAL_PENDING", "priority": 500, "markDeleted": True},
                ],
            )
        ]
    )
    result = invoke(controller, [{"name": ANONYMOUS_ID}], state="deleted", deploy=True, check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert result["direct_actions"]["deleted"][0]["switch_ids"] == ["SERIAL_ACTIVE", "SERIAL_PENDING"]
    assert "pending_deleted_cleanup" not in result
    if check_mode:
        assert controller.writes() == []
    else:
        assert [call[2] for call in controller.deployments()] == [{"switchIds": ["SERIAL_ACTIVE", "SERIAL_PENDING"]}]
    assert len([call for call in controller.calls if call[0] == "GET"]) == 1


@pytest.mark.parametrize("pad_description,pad_template", [(True, False), (False, True), (True, True)])
def test_padded_user_identity_matches_existing_group(invoke, pad_description, pad_template):
    """Identity planning uses the same whitespace normalization as the model."""
    controller = Controller([group(description="Normalized group")])
    entry = {
        "name": f" {TEMPLATE} " if pad_template else TEMPLATE,
        "description": " Normalized group " if pad_description else "Normalized group",
        "priority": 600,
    }
    result = invoke(controller, [entry])
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert [call[1].rsplit("/", 1)[-1] for call in controller.writes("PUT")] == [GROUP_ID]
    assert not any(call[0] == "POST" and call[1].endswith("/policyGroups") for call in controller.calls)
    assert controller.groups[GROUP_ID]["priority"] == 600
    assert set(controller.groups) == {GROUP_ID}


@pytest.mark.parametrize("mixed_explicit", [False, True])
def test_controller_normalization_collisions_keep_legacy_prewrite_failure(invoke, mixed_explicit):
    """Do not silently reconcile raw-distinct groups whose model identities collide."""
    controller = Controller([group(description="group"), group(SECOND_ID, description=" group ")])
    before = deepcopy(controller.groups)
    entries = [{"name": TEMPLATE, "description": "group", "priority": 700}]
    if mixed_explicit:
        entries.insert(0, {"name": GROUP_ID, "priority": 600})
    result = invoke(controller, entries)
    assert result.get("failed") is True
    assert f"('group', {TEMPLATE!r})" in result["msg"]
    assert "execution_key" not in result["msg"]
    assert controller.writes() == []
    assert controller.groups == before


def test_normalized_duplicate_new_proposals_keep_prewrite_failure(invoke):
    """Whitespace cannot turn duplicate proposals into independent creations."""
    controller = Controller()
    result = invoke(
        controller,
        [{"name": TEMPLATE, "description": "group", "priority": 600}, {"name": f" {TEMPLATE} ", "description": " group ", "priority": 700}],
    )
    assert result.get("failed") is True
    assert "identifier" in result["msg"].lower()
    assert controller.writes() == []


@pytest.mark.parametrize("check_mode", [False, True])
def test_direct_delete_retains_cached_active_member_order(invoke, check_mode):
    """Deployment indexing must not reorder the existing public direct preview."""
    controller = Controller([group(ANONYMOUS_ID, switchIds=["SERIAL_Z", "SERIAL_A"])])

    result = invoke(controller, [{"name": ANONYMOUS_ID}], state="deleted", deploy=True, check_mode=check_mode)

    assert not result.get("failed"), result
    assert result["direct_actions"]["deleted"][0]["switch_ids"] == ["SERIAL_Z", "SERIAL_A"]
    assert len([call for call in controller.calls if call[0] == "GET"]) == 1
    if check_mode:
        assert controller.writes() == []
    else:
        assert [call[2] for call in controller.deployments()] == [{"switchIds": ["SERIAL_A", "SERIAL_Z"]}]
