# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Verify policy-group reporting through real module reconciliation."""

from copy import deepcopy

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.tests.unit.modules.test_nd_policy_group_direct_id import (
    GROUP_ID,
    SECOND_ID,
    Controller,
    config,
    group,
    invoke,
)


class RejectingController(Controller):
    """Reject selected writes while preserving accepted earlier HTTP effects."""

    def __init__(self, groups=None, *, rejected_ids=None, reject_put_at=None, reject_deploy=False, partial_create=False, partial_delete=False):
        super().__init__(groups)
        self.rejected_ids = set(rejected_ids or [])
        self.reject_put_at = reject_put_at
        self.put_count = 0
        self.reject_deploy = reject_deploy
        self.partial_create = partial_create
        self.partial_delete = partial_delete

    def request(self, verb, path, payload):
        if verb == "PUT":
            self.put_count += 1
        if (
            (verb == "PUT" and (path.rsplit("/", 1)[-1] in self.rejected_ids or self.put_count == self.reject_put_at))
            or (verb == "POST" and path.endswith("/switchActions/deploy") and self.reject_deploy)
            or (verb == "DELETE" and path.rsplit("/", 1)[-1] in self.rejected_ids)
        ):
            self.calls.append((verb, path, deepcopy(payload)))
            return {
                "RETURN_CODE": 400,
                "METHOD": verb,
                "REQUEST_PATH": path,
                "MESSAGE": "Rejected priority by controller",
                "DATA": {"message": "Rejected priority by controller"},
            }
        if verb == "POST" and path.endswith("/policyGroups") and self.partial_create:
            self.calls.append((verb, path, deepcopy(payload)))
            pid = f"POLICY-GROUP-{self.next_id}"
            self.next_id += 1
            self.groups[pid] = {**deepcopy(payload["policyGroups"][0]), "policyId": pid}
            return {
                "RETURN_CODE": 207,
                "METHOD": verb,
                "REQUEST_PATH": path,
                "MESSAGE": "Multi-Status",
                "DATA": {"policyGroups": [{"policyId": pid, "status": "success"}, {"status": "failed", "message": "Second create rejected"}]},
            }
        if verb == "POST" and path.endswith("/markDelete") and self.partial_delete:
            self.calls.append((verb, path, deepcopy(payload)))
            first, second = payload["policyIds"]
            self.groups.pop(first)
            return {
                "RETURN_CODE": 207,
                "METHOD": verb,
                "REQUEST_PATH": path,
                "MESSAGE": "Multi-Status",
                "DATA": {"policyGroups": [{"policyId": first, "status": "success"}, {"policyId": second, "status": "failed"}]},
            }
        return super().request(verb, path, payload)


@pytest.mark.parametrize("use_existing_id", [False, True])
def test_group_forced_create_check_mode_preview(invoke, use_existing_id):
    """Forced-create dry runs expose validated intent without an allocated ID."""
    controller = Controller([group()])
    entry = config(name=GROUP_ID if use_existing_id else "feature_enable", description="Forced group", create_additional_policy=True)
    before = deepcopy(controller.groups)
    result = invoke(controller, [entry], deploy=True, check_mode=True)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert len(result["force_created"]) == 1
    preview = result["force_created"][0]
    assert "policy_id" not in preview
    assert preview["description"] == "Forced group"
    assert preview["template_name"] == "feature_enable"
    assert preview["switch_ids"] == ["SERIAL_A", "SERIAL_B"]
    assert controller.writes() == []
    assert controller.groups == before


def test_group_forced_create_preview_materializes_priority(invoke):
    """A preview uses the same create-only priority default as the real POST."""
    controller = Controller()
    entry = config(name="feature_enable", description="Forced", create_additional_policy=True)
    entry.pop("priority")
    result = invoke(controller, [entry], check_mode=True)
    assert not result.get("failed"), result
    assert result["force_created"][0]["priority"] == 500
    assert controller.writes() == []


def test_group_forced_create_check_mode_validates_model(invoke):
    """A malformed force-create request fails in check mode before writes."""
    controller = Controller()
    result = invoke(controller, [config(name="feature_enable", priority=0, create_additional_policy=True)], check_mode=True)
    assert result["failed"] is True
    assert result.get("changed", False) is False
    assert "priority" in result["msg"]
    assert controller.writes() == []


@pytest.mark.parametrize("entries", [None, [{"name": "nonexistent_template"}]])
def test_group_empty_gathered_is_explicit_list(invoke, entries):
    """Empty and unmatched read-only queries consistently return gathered: []."""
    controller = Controller()
    result = invoke(controller, entries, state="gathered")
    assert result == {"changed": False, "gathered": []}
    assert controller.writes() == []


@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
def test_group_second_update_failure_preserves_accepted_state(invoke, output_level):
    """Only a preceding accepted update appears applied after later rejection."""
    third_id = "POLICY-GROUP-103"
    controller = RejectingController(
        [group(description="Group A"), group(SECOND_ID, description="Group B"), group(third_id, description="Group C")],
        rejected_ids=[SECOND_ID],
    )
    entries = [
        config(name="feature_enable", description="Group A", priority=600),
        config(name="feature_enable", description="Group B", priority=700),
        config(name="feature_enable", description="Group C", priority=800),
    ]
    result = invoke(controller, entries, output_level=output_level)
    assert result["failed"] is True
    assert "Rejected priority by controller" in result["msg"]
    assert result["changed"] is True
    before = {item["policy_id"]: item["priority"] for item in result["before"]}
    after = {item["policy_id"]: item["priority"] for item in result["after"]}
    assert before == {GROUP_ID: 500, SECOND_ID: 500, third_id: 500}
    assert after == {GROUP_ID: 600, SECOND_ID: 500, third_id: 500}
    assert {pid: value["priority"] for pid, value in controller.groups.items()} == after
    assert [call[1].rsplit("/", 1)[-1] for call in controller.writes("PUT")] == [GROUP_ID, SECOND_ID]


def test_group_first_update_failure_reports_unchanged(invoke):
    """A rejected first update retains original snapshots and changed false."""
    controller = RejectingController([group(description="Group A")], rejected_ids=[GROUP_ID])
    result = invoke(controller, [config(name="feature_enable", description="Group A", priority=600)])
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["before"] == result["after"]
    assert result["after"][0]["priority"] == 500


def test_group_reporting_failure_preserves_original_error(invoke, monkeypatch):
    """A formatting failure must never mask the operation's original rejection."""
    controller = RejectingController([group(description="Group A"), group(SECOND_ID, description="Group B")], rejected_ids=[SECOND_ID])

    def broken_format(self, **kwargs):
        raise RuntimeError("Reporting formatter broke")

    monkeypatch.setattr(NDOutput, "format", broken_format)
    result = invoke(
        controller,
        [config(name="feature_enable", description="Group A", priority=600), config(name="feature_enable", description="Group B", priority=700)],
    )
    assert result["failed"] is True
    assert result["changed"] is True
    assert "Rejected priority by controller" in result["msg"]
    assert "Reporting formatter broke" not in result["msg"]


def test_group_direct_progress_survives_later_normal_failure(invoke):
    """An accepted direct-ID update remains visible if normal reconciliation fails."""
    controller = RejectingController([group(), group(SECOND_ID, description="Group B")], rejected_ids=[SECOND_ID])
    result = invoke(controller, [config(priority=600), config(name="feature_enable", description="Group B", priority=700)])
    assert result["failed"] is True
    assert result["changed"] is True
    assert result["direct_actions"]["updated"][0]["policy_id"] == GROUP_ID
    assert result["direct_actions"]["updated"][0]["priority"] == 600
    assert controller.groups[GROUP_ID]["priority"] == 600
    assert controller.groups[SECOND_ID]["priority"] == 500


@pytest.mark.parametrize("anonymous", [False, True])
def test_group_split_update_failure_preserves_first_payload(invoke, anonymous):
    """The first accepted membership PUT survives rejection of the intent PUT."""
    controller = RejectingController([group(description=None if anonymous else "Group A")], reject_put_at=2)
    entry = config(name=GROUP_ID if anonymous else "feature_enable", priority=600, switch_ids=["SERIAL_B", "SERIAL_C"])
    if not anonymous:
        entry["description"] = "Group A"
    result = invoke(controller, [entry])
    assert result["failed"] is True
    assert result["changed"] is True
    accepted = result["direct_actions"]["updated"][0] if anonymous else result["after"][0]
    assert accepted["priority"] == 500
    assert accepted["switch_ids"] == ["SERIAL_B", "SERIAL_C"]
    assert controller.groups[GROUP_ID]["priority"] == 500
    assert len(controller.writes("PUT")) == 2


def test_group_update_deploy_failure_retains_accepted_configuration(invoke):
    """Deployment failure does not erase an accepted configuration PUT."""
    controller = RejectingController([group(description="Group A")], reject_deploy=True)
    result = invoke(controller, [config(name="feature_enable", description="Group A", priority=600)], deploy=True)
    assert result["failed"] is True
    assert result["changed"] is True
    assert result["before"][0]["priority"] == 500
    assert result["after"][0]["priority"] == 600


@pytest.mark.parametrize("force", [False, True])
def test_group_partial_create_reports_only_accepted_items(invoke, force):
    """Rejected bulk items never appear in after or accepted force-created output."""
    controller = RejectingController(partial_create=True)
    entries = [
        config(name="feature_enable", description="Group A", create_additional_policy=force),
        config(name="feature_enable", description="Group B", create_additional_policy=force),
    ]
    result = invoke(controller, entries)
    assert result["failed"] is True
    assert result["changed"] is True
    assert result["before"] == []
    assert [item["description"] for item in result["after"]] == ["Group A"]
    if force:
        assert [item["description"] for item in result["force_created"]] == ["Group A"]


@pytest.mark.parametrize("force", [False, True])
def test_group_create_deploy_failure_preserves_new_group(invoke, force):
    """Accepted create state remains available when its trailing deploy fails."""
    controller = RejectingController(reject_deploy=True)
    result = invoke(controller, [config(name="feature_enable", description="Group A", create_additional_policy=force)], deploy=True)
    assert result["failed"] is True
    assert result["changed"] is True
    assert result["before"] == []
    assert [item["description"] for item in result["after"]] == ["Group A"]
    if force:
        assert result["force_created"][0]["policy_id"] == "POLICY-GROUP-200"


@pytest.mark.parametrize("anonymous", [False, True])
def test_group_partial_delete_retains_rejected_group(invoke, anonymous):
    """Accepted markDelete results survive a failed direct-DELETE fallback."""
    controller = RejectingController(
        [group(description=None if anonymous else "Group A"), group(SECOND_ID, description=None if anonymous else "Group B")],
        rejected_ids=[SECOND_ID],
        partial_delete=True,
    )
    entries = [config(name=GROUP_ID), config(name=SECOND_ID)]
    result = invoke(controller, entries, state="deleted")
    assert result["failed"] is True
    assert result["changed"] is True
    if anonymous:
        assert [item["policy_id"] for item in result["direct_actions"]["deleted"]] == [GROUP_ID]
    else:
        assert [item["policy_id"] for item in result["after"]] == [SECOND_ID]
    assert set(controller.groups) == {SECOND_ID}


def test_group_delete_deploy_failure_retains_accepted_removal(invoke):
    """A post-delete deployment error retains removed intent and original before."""
    controller = RejectingController([group(description="Group A")], reject_deploy=True)
    result = invoke(controller, [config()], state="deleted", deploy=True)
    assert result["failed"] is True
    assert result["changed"] is True
    assert [item["policy_id"] for item in result["before"]] == [GROUP_ID]
    assert result["after"] == []


def test_group_force_preview_survives_later_model_error(invoke):
    """A validated force preview remains visible if normal model planning fails."""
    controller = Controller()
    entries = [
        config(name="feature_enable", description="Forced", create_additional_policy=True),
        config(name="feature_enable", description="Invalid normal", priority=0),
    ]
    result = invoke(controller, entries, check_mode=True)
    assert result["failed"] is True
    assert result["changed"] is True
    assert result["force_created"][0]["description"] == "Forced"
    assert "policy_id" not in result["force_created"][0]
    assert controller.writes() == []


def test_group_direct_preview_survives_later_model_error(invoke):
    """Only a valid preceding direct preview survives another direct model error."""
    controller = Controller([group(), group(SECOND_ID)])
    result = invoke(controller, [config(priority=600), config(name=SECOND_ID, priority=0)], check_mode=True)
    assert result["failed"] is True
    assert result["changed"] is True
    assert [item["policy_id"] for item in result["direct_actions"]["updated"]] == [GROUP_ID]
    assert controller.writes() == []


def test_group_before_precedes_force_and_direct_writes(invoke):
    """Successful before stays at invocation time despite earlier special writes."""
    controller = Controller([group(description="Original")])
    entries = [
        config(description="Renamed"),
        config(name="feature_enable", description="Forced", create_additional_policy=True),
    ]
    result = invoke(controller, entries)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert [item["description"] for item in result["before"]] == ["Original"]
    assert {item["description"] for item in result["after"]} == {"Renamed", "Forced"}


def test_group_check_mode_normal_model_error_has_no_validated_plan(invoke):
    """Atomic model initialization cannot present unvalidated sibling intent."""
    controller = Controller([group(description="Group A"), group(SECOND_ID, description="Group B")])
    result = invoke(
        controller,
        [config(name="feature_enable", description="Group A", priority=600), config(name="feature_enable", description="Group B", priority=0)],
        check_mode=True,
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["before"] == result["after"]
    assert controller.writes() == []


def test_group_check_mode_valid_plan_survives_invalid_template_sibling(invoke):
    """Pruned schema failures preserve the remaining validated normal plan."""
    controller = Controller([group(description="Group A"), group(SECOND_ID, description="Group B")])
    result = invoke(
        controller,
        [
            config(name="feature_enable", description="Group A", priority=600),
            config(name="feature_enable", description="Group B", template_inputs={"unsupported": "value"}),
        ],
        check_mode=True,
    )
    assert result["failed"] is True
    assert result["changed"] is True
    assert {item["policy_id"]: item["priority"] for item in result["after"]} == {GROUP_ID: 600, SECOND_ID: 500}
    assert controller.writes() == []


@pytest.mark.parametrize("id_field", ["policyId", "policy_id", "embedded"])
@pytest.mark.parametrize("status", [None, ""])
def test_group_create_accepted_id_aliases_survive_deploy_failure(invoke, id_field, status):
    """Reporting retains the existing parser's accepted response compatibility."""

    class AliasController(RejectingController):
        def request(self, verb, path, payload):
            result = super().request(verb, path, payload)
            if verb == "POST" and path.endswith("/policyGroups"):
                item = result["DATA"]["policyGroups"][0]
                pid = item.pop("policyId")
                if id_field == "embedded":
                    item["templateInputs"] = {"POLICY_ID": pid}
                else:
                    item[id_field] = pid
                if status is None:
                    item.pop("status")
                else:
                    item["status"] = status
            return result

    controller = AliasController(reject_deploy=True)
    result = invoke(controller, [config(name="feature_enable", description="Group A")], deploy=True)
    assert result["failed"] is True
    assert result["changed"] is True
    assert result["after"][0]["policy_id"] == "POLICY-GROUP-200"


@pytest.mark.parametrize("check_mode,reject_deploy", [(False, False), (True, False), (False, True)])
def test_group_direct_effective_reporting_preserves_omitted_priority(invoke, check_mode, reject_deploy):
    """Normal, preview and failure reports describe the effective PUT intent."""
    current = group(priority=725, description="", source="")
    controller = RejectingController([current], reject_deploy=reject_deploy)
    entry = config(template_inputs={"featureName": "lldp"})
    entry.pop("priority")
    result = invoke(controller, [entry], check_mode=check_mode, deploy=reject_deploy)
    assert result.get("failed", False) is reject_deploy
    assert result["changed"] is True
    reported = result["direct_actions"]["updated"][0]
    assert reported["priority"] == 725
    assert reported["description"] == ""
    assert reported["source"] == ""
    assert reported["template_inputs"] == {"featureName": "lldp"}
    if check_mode:
        assert controller.writes() == []
    else:
        assert controller.writes("PUT")[0][2]["priority"] == reported["priority"]
        assert controller.writes("PUT")[0][2]["templateInputs"] == reported["template_inputs"]


def test_group_failed_reporting_helper_retains_original_error(invoke, monkeypatch):
    """Even failure of snapshot reconstruction cannot replace the API error."""
    from ansible_collections.cisco.nd.plugins.modules import nd_manage_policy_group

    controller = RejectingController([group(description="Group A"), group(SECOND_ID, description="Group B")], rejected_ids=[SECOND_ID])

    def broken_report(*args, **kwargs):
        raise RuntimeError("Broken reconstruction")

    monkeypatch.setattr(nd_manage_policy_group, "_build_group_failure_result", broken_report)
    result = invoke(
        controller,
        [config(name="feature_enable", description="Group A", priority=600), config(name="feature_enable", description="Group B", priority=700)],
    )
    assert result["failed"] is True
    assert result["changed"] is True
    assert "Rejected priority by controller" in result["msg"]
    assert "Broken reconstruction" not in result["msg"]


def test_group_normal_check_mode_plan_survives_reporting_failure(invoke, monkeypatch):
    """A completed validated normal preview survives a later formatter error."""
    controller = Controller([group(description="Group A")])

    def broken_format(self, **kwargs):
        raise RuntimeError("Reporting formatter broke")

    monkeypatch.setattr(NDOutput, "format", broken_format)
    result = invoke(controller, [config(name="feature_enable", description="Group A", priority=600)], check_mode=True)
    assert result["failed"] is True
    assert result["changed"] is True
    assert result["before"][0]["priority"] == 500
    assert result["after"][0]["priority"] == 600
    assert "Reporting formatter broke" in result["msg"]
    assert controller.writes() == []


def test_group_repair_of_unmodelable_original_stays_successful(invoke):
    """Snapshot reporting never fails an otherwise accepted direct repair."""
    controller = Controller([group(description="Original", priority=0)])
    result = invoke(controller, [config(description="Repaired", priority=600)])
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert "before" not in result
    assert result["after"][0]["description"] == "Repaired"
    assert result["after"][0]["priority"] == 600
    assert len(controller.writes("PUT")) == 1
    assert controller.groups[GROUP_ID]["priority"] == 600


def test_group_accepted_repair_survives_failure_with_unmodelable_before(invoke):
    """An unavailable original snapshot cannot erase a known accepted repair."""
    controller = RejectingController([group(description="Original", priority=0), group(SECOND_ID, description="Group B")], rejected_ids=[SECOND_ID])
    result = invoke(
        controller,
        [config(description="Repaired", priority=600), config(name="feature_enable", description="Group B", priority=700)],
    )
    assert result["failed"] is True
    assert result["changed"] is True
    assert "before" not in result
    assert {item["policy_id"]: item["priority"] for item in result["after"]} == {GROUP_ID: 600, SECOND_ID: 500}
    assert result["direct_actions"]["updated"][0]["description"] == "Repaired"
    assert "Rejected priority by controller" in result["msg"]


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("priority", [None, 725])
def test_group_creation_reports_effective_priority(invoke, force, check_mode, priority):
    """New-group normal/forced reports expose effective defaults or explicit input."""
    controller = Controller()
    entry = config(name="feature_enable", description="Created", create_additional_policy=force)
    if priority is None:
        entry.pop("priority")
    else:
        entry["priority"] = priority
    result = invoke(controller, [entry], check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    reported = result["force_created"][0] if force else result["after"][0]
    assert reported["priority"] == (500 if priority is None else priority)
    if force:
        assert reported["create_additional_policy"] is True
    if check_mode:
        assert controller.writes() == []
        assert "policy_id" not in reported
    else:
        assert controller.writes("POST")[0][2]["policyGroups"][0]["priority"] == reported["priority"]


def test_group_force_failure_preserves_creation_flag(invoke):
    """Accepted force-create reports retain the same control flag on failure."""
    controller = RejectingController(reject_deploy=True)
    result = invoke(controller, [config(name="feature_enable", description="Created", create_additional_policy=True)], deploy=True)
    assert result["failed"] is True
    assert result["force_created"][0]["create_additional_policy"] is True


def test_group_creation_priority_does_not_require_a_generated_id(invoke):
    """Legacy permissive replies retain unknown identity but report the sent default."""

    class MissingIdController(Controller):
        def request(self, verb, path, payload):
            response = super().request(verb, path, payload)
            if verb == "POST" and path.endswith("/policyGroups"):
                response["DATA"]["policyGroups"][0].pop("policyId", None)
            return response

    controller = MissingIdController()
    entry = config(name="feature_enable", description="Created")
    entry.pop("priority")
    result = invoke(controller, [entry])
    assert not result.get("failed"), result
    assert result["after"][0]["priority"] == controller.writes("POST")[0][2]["policyGroups"][0]["priority"] == 500
    assert "policy_id" not in result["after"][0]


@pytest.mark.parametrize("outcome", ["accepted", "preview", "deploy_failure", "rejected", "rename_into_duplicate"])
def test_group_older_duplicate_direct_rename_preserves_original_target(invoke, outcome):
    """An explicitly renamed duplicate keeps its own before and accepted after."""
    destination_id = "POLICY-GROUP-103"
    records = [
        group(description="Shared", priority=400, switchIds=["SERIAL_OLD"], updateTimestamp=10),
        group(SECOND_ID, description="Shared", priority=500, switchIds=["SERIAL_NEW"], updateTimestamp=20),
        group(destination_id, description="Destination", priority=550, switchIds=["SERIAL_DEST"], updateTimestamp=30),
    ]
    controller = RejectingController(records, rejected_ids=[GROUP_ID] if outcome == "rejected" else [], reject_deploy=outcome == "deploy_failure")
    original = deepcopy(controller.groups)
    description = "Destination" if outcome == "rename_into_duplicate" else "Renamed"
    result = invoke(
        controller,
        [config(description=description, priority=600, switch_ids=["SERIAL_OLD"])],
        check_mode=outcome == "preview",
        deploy=outcome == "deploy_failure",
    )

    assert result.get("failed", False) is (outcome in {"deploy_failure", "rejected"})
    assert result["changed"] is (outcome != "rejected")
    before = {item["policy_id"]: item for item in result["before"]}
    after = {item["policy_id"]: item for item in result["after"]}
    assert set(before) == set(after) == {GROUP_ID, SECOND_ID, destination_id}
    assert (before[GROUP_ID]["description"], before[GROUP_ID]["priority"], before[GROUP_ID]["switch_ids"]) == ("Shared", 400, ["SERIAL_OLD"])
    accepted = outcome not in {"preview", "rejected"}
    assert (after[GROUP_ID]["description"], after[GROUP_ID]["priority"]) == ((description, 600) if accepted else ("Shared", 400))
    assert after[GROUP_ID]["switch_ids"] == ["SERIAL_OLD"]
    assert after[SECOND_ID] == before[SECOND_ID]
    assert after[destination_id] == before[destination_id]
    assert controller.groups[SECOND_ID] == original[SECOND_ID]
    assert controller.groups[destination_id] == original[destination_id]
    updates = result["direct_actions"]["updated"]
    assert len(updates) == int(outcome != "rejected")
    if updates:
        assert (updates[0]["policy_id"], updates[0]["description"], updates[0]["priority"]) == (GROUP_ID, description, 600)
    if outcome == "preview":
        assert controller.writes() == []
        assert controller.groups == original
    else:
        assert [call[1].rsplit("/", 1)[-1] for call in controller.writes("PUT")] == [GROUP_ID]
        assert len(controller.deployments()) == int(outcome == "deploy_failure")


@pytest.mark.parametrize("check_mode,invalid_sibling", [(False, False), (True, False), (True, True)])
def test_group_direct_snapshot_survives_ordinary_plan(invoke, check_mode, invalid_sibling):
    """Normal plans and failure reconstruction retain the direct target snapshot."""
    normal_id = "POLICY-GROUP-103"
    controller = Controller(
        [
            group(description="Shared", priority=400, switchIds=["SERIAL_OLD"], updateTimestamp=10),
            group(SECOND_ID, description="Shared", priority=500, switchIds=["SERIAL_NEW"], updateTimestamp=20),
            group(normal_id, description="Normal", priority=550),
        ]
    )
    original = deepcopy(controller.groups)
    entries = [
        config(description="Renamed", priority=600, switch_ids=["SERIAL_OLD"]),
        config(name="feature_enable", description="Normal", priority=700),
    ]
    if invalid_sibling:
        entries.append(config(name="feature_enable", description="Invalid", template_inputs={"unsupported": "value"}))
    result = invoke(controller, entries, check_mode=check_mode)

    assert result.get("failed", False) is invalid_sibling
    assert result["changed"] is True
    before = {item["policy_id"]: item for item in result["before"]}
    after = {item["policy_id"]: item for item in result["after"]}
    assert set(before) == set(after) == {GROUP_ID, SECOND_ID, normal_id}
    assert (before[GROUP_ID]["description"], before[GROUP_ID]["priority"]) == ("Shared", 400)
    assert (after[GROUP_ID]["description"], after[GROUP_ID]["priority"]) == (("Shared", 400) if check_mode else ("Renamed", 600))
    assert before[normal_id]["priority"] == 550
    assert after[normal_id]["priority"] == 700
    assert after[SECOND_ID] == before[SECOND_ID]
    assert result["direct_actions"]["updated"][0]["description"] == "Renamed"
    if check_mode:
        assert controller.writes() == []
        assert controller.groups == original
    else:
        assert [call[1].rsplit("/", 1)[-1] for call in controller.writes("PUT")] == [GROUP_ID, normal_id]


@pytest.mark.parametrize("scenario", ["delete", "delete_deploy_failure", "anonymous_rename", "anonymous_unchanged_visibility"])
def test_group_direct_snapshot_preserves_deletion_and_anonymous_visibility(invoke, scenario):
    """Snapshot completion cannot restore removed IDs or expose anonymous rows."""
    deleting = scenario.startswith("delete")
    anonymous = not deleting
    controller = RejectingController(
        [
            group(description=None if anonymous else "Shared", priority=400, switchIds=["SERIAL_OLD"], updateTimestamp=10),
            group(SECOND_ID, description="Shared", priority=500, switchIds=["SERIAL_NEW"], updateTimestamp=20),
        ],
        reject_deploy=scenario == "delete_deploy_failure",
    )
    sibling = deepcopy(controller.groups[SECOND_ID])
    entry = config(priority=600, switch_ids=["SERIAL_OLD"])
    if deleting:
        entry["description"] = "Different delete description"
    elif scenario == "anonymous_rename":
        entry["description"] = "Shared"
    result = invoke(controller, [entry], state="deleted" if deleting else "merged", deploy=scenario == "delete_deploy_failure")

    assert result.get("failed", False) is (scenario == "delete_deploy_failure")
    assert result["changed"] is True
    if scenario == "delete":
        # Successful direct-only deletions retain their existing output shape.
        assert "before" not in result
        assert "after" not in result
        assert GROUP_ID not in controller.groups
        assert controller.groups[SECOND_ID] == sibling
        assert [item["policy_id"] for item in result["direct_actions"]["deleted"]] == [GROUP_ID]
        return
    before = {item["policy_id"]: item for item in result["before"]}
    after = {item["policy_id"]: item for item in result["after"]}
    assert set(before) == ({GROUP_ID, SECOND_ID} if deleting else {SECOND_ID})
    assert after[SECOND_ID] == before[SECOND_ID]
    assert controller.groups[SECOND_ID] == sibling
    if deleting:
        assert (before[GROUP_ID]["description"], before[GROUP_ID]["priority"]) == ("Shared", 400)
        assert GROUP_ID not in after
        assert GROUP_ID not in controller.groups
        assert [item["policy_id"] for item in result["direct_actions"]["deleted"]] == [GROUP_ID]
    elif scenario == "anonymous_rename":
        assert (after[GROUP_ID]["description"], after[GROUP_ID]["priority"]) == ("Shared", 600)
    else:
        assert GROUP_ID not in after
        assert result["direct_actions"]["updated"][0]["priority"] == 600


@pytest.mark.parametrize("rejected_fallback", ["POLICY-GROUP-103", GROUP_ID])
def test_group_delete_fallback_failure_retains_requested_order_and_duplicates(invoke, rejected_fallback):
    """Failure output keeps accepted source entries in their original order, including repeats."""
    third_id = "POLICY-GROUP-103"

    class OrderedDeleteController(RejectingController):
        def request(self, verb, path, payload):
            if verb == "POST" and path.endswith("/markDelete"):
                self.calls.append((verb, path, deepcopy(payload)))
                self.groups.pop(SECOND_ID)
                return {
                    "RETURN_CODE": 207,
                    "METHOD": verb,
                    "REQUEST_PATH": path,
                    "MESSAGE": "Multi-Status",
                    "DATA": {
                        "policyGroups": [
                            {"policyId": third_id, "status": "failed"},
                            {"policyId": GROUP_ID, "status": "failed"},
                            {"policyId": SECOND_ID, "status": "SUCCESS"},
                        ]
                    },
                }
            if verb == "DELETE" and path.rsplit("/", 1)[-1] not in self.rejected_ids:
                self.calls.append((verb, path, deepcopy(payload)))
                self.groups.pop(path.rsplit("/", 1)[-1])
                return {"RETURN_CODE": 200, "METHOD": verb, "REQUEST_PATH": path, "MESSAGE": "OK", "DATA": {}}
            return super().request(verb, path, payload)

    controller = OrderedDeleteController([group(), group(SECOND_ID), group(third_id)], rejected_ids=[rejected_fallback])
    requested_ids = [SECOND_ID, GROUP_ID, SECOND_ID, third_id]
    result = invoke(controller, [config(name=pid) for pid in requested_ids], state="deleted", deploy=True)

    assert result["failed"] is True
    assert result["changed"] is True
    assert "Rejected priority by controller" in result["msg"]
    assert controller.writes()[0][2] == {"policyIds": requested_ids}
    expected_fallbacks = [third_id] if rejected_fallback == third_id else [third_id, GROUP_ID]
    assert [call[1].rsplit("/", 1)[-1] for call in controller.writes("DELETE")] == expected_fallbacks
    expected_deleted = [SECOND_ID, SECOND_ID] if rejected_fallback == third_id else [SECOND_ID, SECOND_ID, third_id]
    assert [item["policy_id"] for item in result["direct_actions"]["deleted"]] == expected_deleted
    assert set(controller.groups) == ({GROUP_ID, SECOND_ID, third_id} - set(expected_deleted))
    assert controller.deployments() == []
