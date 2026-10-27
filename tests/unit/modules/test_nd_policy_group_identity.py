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


@pytest.mark.parametrize("kind", ["duplicate", "anonymous"])
@pytest.mark.parametrize("force_flag", [False, True])
def test_template_only_legacy_ambiguous_delete_failure_is_preserved(invoke, kind, force_flag):
    """Do not silently expand this fix into new template-only deletion semantics."""
    controller = Controller(duplicate_groups() if kind == "duplicate" else [group()])
    before = deepcopy(controller.groups)
    result = invoke(controller, [{"name": TEMPLATE, "create_additional_policy": force_flag}], state="deleted")
    assert result.get("failed") is True
    assert "identifier" in result["msg"].lower()
    assert controller.writes() == []
    assert controller.groups == before


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
def test_anonymous_delete_omitted_member_deploy_limitation_is_unchanged(invoke, force_flag):
    """Keep the pre-existing sparse-direct-delete deployment limitation scoped.

    This control records existing behavior rather than desired delete semantics:
    a direct no-description delete without switch_ids does not infer deployment
    members. Correcting that separate workflow is outside the recovered fixes.
    """
    controller = Controller([group(ANONYMOUS_ID, switchIds=["SERIAL_ANONYMOUS"])])
    result = invoke(controller, [{"name": ANONYMOUS_ID, "create_additional_policy": force_flag}], state="deleted", deploy=True)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert [call[2] for call in mark_delete_calls(controller)] == [{"policyIds": [ANONYMOUS_ID]}]
    assert controller.deployments() == []


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
