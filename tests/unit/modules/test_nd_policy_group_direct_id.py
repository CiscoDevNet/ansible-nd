# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Exercise direct-ID policy-group reconciliation through the real module.

Only Ansible process boundaries and the HTTP sender are replaced. The module,
state machine, models, orchestrator, RestSend, and response handler execute
normally, including persistent controller state between successive invocations.
"""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from ansible_collections.cisco.nd.plugins.module_utils import nd_state_machine
from ansible_collections.cisco.nd.plugins.modules import nd_manage_policy_group

GROUP_ID = "POLICY-GROUP-101"
SECOND_ID = "POLICY-GROUP-102"


class ModuleResult(BaseException):
    """Stop module execution without the module catching its own exit."""

    def __init__(self, result):
        self.result = result


class Controller:
    """Small stateful HTTP boundary with exact request capture."""

    def __init__(self, groups=None):
        self.groups = {g["policyId"]: deepcopy(g) for g in (groups or [])}
        self.calls = []
        self.next_id = 200
        self.omit_group_after_create = False
        self.omit_group_from_next_summary = False
        self.warnings = []

    def request(self, verb, path, payload):
        self.calls.append((verb, path, deepcopy(payload)))
        resource = urlsplit(path).path
        status = 200
        if verb == "GET" and resource.endswith("/policySummary"):
            data = {"policies": [self.summary(g) for g in self.groups.values()]}
            if self.omit_group_from_next_summary:
                data["policies"] = [g for g in data["policies"] if g["policyId"] != GROUP_ID]
                self.omit_group_from_next_summary = False
        elif verb == "GET" and resource.endswith("/parameters"):
            parameter = "CONF" if "/switch_freeform/" in resource else "featureName"
            data = {"parameters": [{"name": parameter, "parameterType": "string"}]}
        elif verb == "GET" and "/policyGroups/" in resource:
            pid = resource.rsplit("/", 1)[-1]
            if pid not in self.groups:
                status, data = 404, {"message": "Not found"}
            else:
                data = deepcopy(self.groups[pid])
        elif verb == "PUT" and "/policyGroups/" in resource:
            pid = resource.rsplit("/", 1)[-1]
            self.groups[pid] = {**deepcopy(payload), "policyId": pid}
            data = {"policyId": pid, "status": "success"}
        elif verb == "POST" and resource.endswith("/policyGroups"):
            status, created = 207, []
            for entry in payload["policyGroups"]:
                pid = f"POLICY-GROUP-{self.next_id}"
                self.next_id += 1
                self.groups[pid] = {**deepcopy(entry), "policyId": pid}
                created.append({"policyId": pid, "status": "success"})
            data = {"policyGroups": created}
            self.omit_group_from_next_summary = self.omit_group_after_create
        elif verb == "POST" and resource.endswith("/markDelete"):
            data = {"policyGroups": [{"policyId": pid, "status": "success"} for pid in payload["policyIds"]]}
            for pid in payload["policyIds"]:
                self.groups.pop(pid, None)
            status = 207
        elif verb == "POST" and resource.endswith("/switchActions/deploy"):
            data = {"switchIds": [{"switchId": sid, "status": "success"} for sid in payload["switchIds"]]}
        else:
            raise AssertionError(f"Unexpected request: {verb} {path}: {payload!r}")
        return {"RETURN_CODE": status, "METHOD": verb, "REQUEST_PATH": path, "MESSAGE": "OK", "DATA": data}

    @staticmethod
    def summary(group):
        result = deepcopy(group)
        if "switches" not in result:
            result["switches"] = [{"switchId": sid, "priority": group.get("priority", 500), "markDeleted": False} for sid in group.get("switchIds", [])]
        return result

    def writes(self, verb=None):
        return [call for call in self.calls if call[0] != "GET" and (verb is None or call[0] == verb)]

    def deployments(self):
        return [call for call in self.writes() if "/switchActions/deploy" in call[1]]


def group(pid=GROUP_ID, description=None, **overrides):
    """Return a controller group containing the complete writable intent."""
    return {
        "policyId": pid,
        "templateName": "feature_enable",
        "description": description,
        "switchIds": ["SERIAL_A", "SERIAL_B"],
        "priority": 500,
        "entityName": "SWITCH",
        "entityType": "switch",
        "templateInputs": {"featureName": "lacp"},
        **overrides,
    }


def config(name=GROUP_ID, **overrides):
    """Return an explicit full desired group, independent of API parsing."""
    return {"name": name, "switch_ids": ["SERIAL_A", "SERIAL_B"], "priority": 500, "template_inputs": {"featureName": "lacp"}, **overrides}


def freeform_group():
    """Return the anonymous metadata-bearing policySummary shape seen live."""
    return {
        "policyId": GROUP_ID,
        "policyType": "group",
        "templateName": "switch_freeform",
        "description": None,
        "entityName": "SWITCH",
        "entityType": "switch",
        "source": "",
        "switches": [{"switchId": "SERIAL_A", "priority": 510, "markDeleted": False}],
        "templateInputs": {
            "CONF": "! audit marker",
            "FABRIC_ID": "-1",
            "POLICY_DESC": "",
            "POLICY_ID": GROUP_ID,
            "PRIORITY": "510",
            "SECENTITY": "",
            "SECENTTYPE": "",
        },
    }


@pytest.fixture
def invoke(monkeypatch):
    """Invoke main against a persistent controller and real reconciliation."""
    active = {}

    class Sender:
        """Implement the runtime SenderProtocol at the HTTP boundary."""

        def __init__(self):
            self.path = None
            self.verb = None
            self.payload = None
            self.response = {}
            self.ansible_module = None

        def commit(self):
            self.response = active["controller"].request(self.verb.value, self.path, self.payload)

    class Module:
        """Represent Ansible's parsed invocation and process exits."""

        def __init__(self, params, check_mode):
            self.params = deepcopy(params)
            self.check_mode = check_mode
            self.no_log_values = set()

        def exit_json(self, **kwargs):
            raise ModuleResult(kwargs)

        def fail_json(self, **kwargs):
            raise ModuleResult({"failed": True, **kwargs})

        def warn(self, message):
            active["controller"].warnings.append(message)

    monkeypatch.setattr(nd_manage_policy_group, "Sender", Sender)
    monkeypatch.setattr(nd_state_machine, "Sender", Sender)
    monkeypatch.setattr(nd_manage_policy_group, "Log", lambda: SimpleNamespace(commit=lambda: None))

    def run(controller, entries=None, *, state="merged", deploy=False, check_mode=False, output_level="normal"):
        active["controller"] = controller
        params = {"fabric_name": "FABRIC_A", "state": state, "deploy": deploy, "config": entries, "output_level": output_level}
        module = Module(params, check_mode)
        monkeypatch.setattr(nd_manage_policy_group, "AnsibleModule", lambda **_kwargs: module)
        with pytest.raises(ModuleResult) as captured:
            nd_manage_policy_group.main()
        return captured.value.result

    return run


@pytest.mark.parametrize("description", [None, ""])
@pytest.mark.parametrize("check_mode", [False, True])
def test_direct_id_identical_intent_is_noop(invoke, description, check_mode):
    """An identical no-description ID update sends no PUT and reports no change."""
    controller = Controller([group(description=description)])
    before = deepcopy(controller.groups)
    result = invoke(controller, [config()], check_mode=check_mode)
    assert not result.get("failed"), result
    assert controller.writes() == []
    assert result["changed"] is False
    assert result.get("direct_actions", {"updated": []})["updated"] == []
    assert controller.groups == before


@pytest.mark.parametrize("check_mode", [False, True])
def test_direct_id_missing_description_field_is_noop(invoke, check_mode):
    """A genuinely omitted API description matches equivalent empty intent."""
    current = group()
    current.pop("description")
    controller = Controller([current])
    before = deepcopy(controller.groups)
    result = invoke(controller, [config()], check_mode=check_mode)
    assert not result.get("failed"), result
    assert controller.writes() == []
    assert result["changed"] is False
    assert result.get("direct_actions", {"updated": []})["updated"] == []
    assert controller.groups == before


@pytest.mark.parametrize("check_mode", [False, True])
def test_direct_id_real_priority_change_and_rerun(invoke, check_mode):
    """A genuine change retains its exact request; a persisted rerun skips it."""
    controller = Controller([group()])
    result = invoke(controller, [config(priority=600)], check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert len(result["direct_actions"]["updated"]) == 1
    if check_mode:
        assert controller.writes() == []
        assert controller.groups[GROUP_ID]["priority"] == 500
        return
    assert len(controller.writes("PUT")) == 1
    assert controller.writes("PUT")[0][1].endswith(f"/policyGroups/{GROUP_ID}")
    assert controller.writes("PUT")[0][2]["priority"] == 600
    controller.calls.clear()
    rerun = invoke(controller, [config(priority=600)])
    assert not rerun.get("failed"), rerun
    assert controller.writes() == []
    assert rerun["changed"] is False


@pytest.mark.parametrize("deploy", [False, True])
def test_direct_id_membership_order_is_noop(invoke, deploy):
    """Reordering members does not mutate; explicit deployment keeps its scope."""
    controller = Controller([group()])
    result = invoke(controller, [config(switch_ids=["SERIAL_B", "SERIAL_A"])], deploy=deploy)
    assert not result.get("failed"), result
    assert result["changed"] is False
    assert controller.writes("PUT") == []
    assert len(controller.deployments()) == int(deploy)
    if deploy:
        assert controller.deployments()[0][2] == {"switchIds": ["SERIAL_A", "SERIAL_B"]}


@pytest.mark.parametrize("priority,changed", [(500, False), (600, True)])
def test_direct_id_check_mode_never_deploys(invoke, priority, changed):
    """An explicit deploy request remains read-only during direct-ID dry runs."""
    controller = Controller([group()])
    result = invoke(controller, [config(priority=priority)], deploy=True, check_mode=True)
    assert not result.get("failed"), result
    assert result["changed"] is changed
    assert controller.writes() == []


@pytest.mark.parametrize("priority,changed", [(500, False), (600, True)])
def test_direct_id_comparison_uses_exact_anonymous_group(invoke, priority, changed):
    """A sibling with identical template/description cannot supply equality."""
    controller = Controller([group(), group(SECOND_ID, priority=600)])
    sibling = deepcopy(controller.groups[SECOND_ID])
    result = invoke(controller, [config(priority=priority)])
    assert not result.get("failed"), result
    assert result["changed"] is changed
    assert len(controller.writes("PUT")) == int(changed)
    if changed:
        assert controller.writes("PUT")[0][1].endswith(f"/policyGroups/{GROUP_ID}")
    assert controller.groups[SECOND_ID] == sibling


def test_direct_id_normalized_template_values_are_noop(invoke):
    """Ansible integer inputs compare with controller-stringified values."""
    controller = Controller([group(templateInputs={"featureName": "5"})])
    result = invoke(controller, [config(template_inputs={"featureName": 5})])
    assert not result.get("failed"), result
    assert controller.writes() == []
    assert result["changed"] is False


def test_direct_id_omitted_priority_is_preserved(invoke):
    """A sparse direct request compares against the effective preserved priority."""
    controller = Controller([group(priority=600)])
    entry = config()
    entry.pop("priority")
    result = invoke(controller, [entry])
    assert not result.get("failed"), result
    assert controller.writes() == []
    assert controller.groups[GROUP_ID]["priority"] == 600
    assert result["changed"] is False


def test_direct_id_omitted_membership_keeps_existing_replacement_behavior(invoke):
    """The no-op check must not reinterpret an omitted list as preserve-members."""
    controller = Controller([group()])
    entry = config()
    entry.pop("switch_ids")
    result = invoke(controller, [entry])
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert len(controller.writes("PUT")) == 1
    assert controller.writes("PUT")[0][2]["switchIds"] == []


def test_direct_id_omitted_inputs_keep_existing_replacement_behavior(invoke):
    """An omitted template-input map keeps the prior direct-path PUT semantics."""
    controller = Controller([group()])
    entry = config()
    entry.pop("template_inputs")
    result = invoke(controller, [entry])
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert len(controller.writes("PUT")) == 1
    assert "templateInputs" not in controller.writes("PUT")[0][2]


def test_direct_id_member_only_update_preserves_one_put(invoke):
    """Membership-only changes keep their current single request and old intent."""
    controller = Controller([group()])
    result = invoke(controller, [config(switch_ids=["SERIAL_B", "SERIAL_C"])])
    assert not result.get("failed"), result
    assert result["changed"] is True
    puts = controller.writes("PUT")
    assert len(puts) == 1
    assert puts[0][2]["switchIds"] == ["SERIAL_B", "SERIAL_C"]
    assert puts[0][2]["priority"] == 500
    assert puts[0][2]["templateInputs"] == {"featureName": "lacp"}


@pytest.mark.parametrize("deploy", [False, True])
def test_direct_id_split_update_sequence_unchanged(invoke, deploy):
    """Simultaneous member/intent changes preserve the two-step update contract."""
    controller = Controller([group()])
    result = invoke(controller, [config(priority=600, switch_ids=["SERIAL_B", "SERIAL_C"])], deploy=deploy)
    assert not result.get("failed"), result
    assert result["changed"] is True
    puts = controller.writes("PUT")
    assert len(puts) == 2
    assert [call[2]["priority"] for call in puts] == [500, 600]
    assert [call[2]["switchIds"] for call in puts] == [["SERIAL_B", "SERIAL_C"]] * 2
    assert len(controller.deployments()) == int(deploy)
    if deploy:
        assert controller.deployments()[0][2] == {"switchIds": ["SERIAL_A", "SERIAL_B", "SERIAL_C"]}


def test_rename_updates_once_then_normal_path_is_noop(invoke):
    """Adding a description uses direct PUT once and reconciles normally later."""
    controller = Controller([group()])
    entry = config(description="Managed group")
    first = invoke(controller, [entry])
    assert not first.get("failed"), first
    assert first["changed"] is True
    assert len(controller.writes("PUT")) == 1
    controller.calls.clear()
    second = invoke(controller, [entry])
    assert not second.get("failed"), second
    assert second["changed"] is False
    assert controller.writes() == []


@pytest.mark.parametrize("direct_priority", [500, 600])
def test_mixed_direct_normal_force_operations(invoke, direct_priority):
    """Skipping one direct no-op preserves unrelated force and normal actions."""
    controller = Controller([group(), group(SECOND_ID, description="Normal group")])
    entries = [
        config(priority=direct_priority),
        config(name="feature_enable", description="Normal group", priority=700),
        config(name="feature_enable", description="Extra group", create_additional_policy=True),
    ]
    result = invoke(controller, entries)
    assert not result.get("failed"), result
    assert result["changed"] is True
    puts = controller.writes("PUT")
    assert [call[1].rsplit("/", 1)[-1] for call in puts] == ([GROUP_ID] if direct_priority != 500 else []) + [SECOND_ID]
    assert len(result["force_created"]) == 1
    assert len(result["direct_actions"]["updated"]) == int(direct_priority != 500)
    assert controller.groups[SECOND_ID]["priority"] == 700
    assert len(controller.groups) == 3


@pytest.mark.parametrize("check_mode", [False, True])
def test_direct_id_deleted_still_deletes(invoke, check_mode):
    """The merged-state comparison never suppresses deletion of existing groups."""
    controller = Controller([group()])
    result = invoke(controller, [config()], state="deleted", check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert controller.writes("PUT") == []
    assert len(controller.writes()) == (0 if check_mode else 1)
    if not check_mode:
        assert controller.writes()[0][2] == {"policyIds": [GROUP_ID]}


def test_direct_id_gathered_remains_read_only(invoke):
    """No-description groups remain discoverable and replayable by ID."""
    controller = Controller([group()])
    result = invoke(controller, [{"name": GROUP_ID}], state="gathered")
    assert not result.get("failed"), result
    assert result["changed"] is False
    assert result["gathered"][0]["policy_id"] == GROUP_ID
    assert controller.writes() == []


def test_missing_direct_id_is_failure_not_noop(invoke):
    """A missing requested ID fails before mutations rather than guessing equality."""
    controller = Controller()
    result = invoke(controller, [config()])
    assert result["failed"] is True
    assert "not found" in result["msg"]
    assert controller.writes() == []


def test_invalid_current_template_does_not_false_noop(invoke):
    """An unparseable current group cannot qualify as a validated no-op."""
    controller = Controller([group(templateName="")])
    result = invoke(controller, [config()])
    assert result.get("failed") is True or controller.writes("PUT")
    assert not (result.get("changed") is False and not result.get("failed"))


def test_failed_current_lookup_keeps_conservative_update(invoke):
    """Cache invalidation plus unavailable exact read cannot silently skip a PUT."""
    controller = Controller([group()])
    controller.omit_group_after_create = True
    entries = [config(name="feature_enable", description="Force", create_additional_policy=True), config(priority=600)]
    result = invoke(controller, entries)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert len(controller.writes("PUT")) == 1
    assert controller.groups[GROUP_ID]["priority"] == 600


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("deploy", [False, True])
def test_metadata_bearing_anonymous_direct_id_noop(invoke, check_mode, deploy):
    """The live freeform metadata shape must not cause PUTs or changed=true."""
    controller = Controller([freeform_group()])
    before = deepcopy(controller.groups)
    entry = {
        "name": GROUP_ID,
        "switch_ids": ["SERIAL_A"],
        "priority": 510,
        "template_inputs": {"CONF": "! audit marker"},
    }

    result = invoke(controller, [entry], deploy=deploy, check_mode=check_mode)

    assert not result.get("failed"), result
    assert result["changed"] is False
    assert controller.writes("PUT") == []
    assert len(controller.deployments()) == int(deploy and not check_mode)
    if controller.deployments():
        assert controller.deployments()[0][2] == {"switchIds": ["SERIAL_A"]}
    assert controller.groups == before


@pytest.mark.parametrize("check_mode", [False, True])
def test_metadata_bearing_anonymous_gathered_replay_is_noop(invoke, check_mode):
    """Gather strips bookkeeping; replay still matches the original raw group."""
    controller = Controller([freeform_group()])
    before = deepcopy(controller.groups)
    gathered = invoke(controller, [{"name": GROUP_ID}], state="gathered")
    assert not gathered.get("failed"), gathered
    assert gathered["changed"] is False
    entry = gathered["gathered"][0]
    assert entry["name"] == "switch_freeform"
    assert entry["policy_id"] == GROUP_ID
    assert entry["template_inputs"] == {"CONF": "! audit marker"}
    assert entry["priority"] == 510
    controller.calls.clear()

    result = invoke(controller, [entry], check_mode=check_mode)

    assert not result.get("failed"), result
    assert result["changed"] is False
    assert controller.writes() == []
    assert controller.groups == before


@pytest.mark.parametrize("check_mode", [False, True])
def test_metadata_bearing_anonymous_real_update_preserves_desired_payload(invoke, check_mode):
    """A CONF change still writes its existing payload, including desired echoes."""
    controller = Controller([freeform_group()])
    before = deepcopy(controller.groups)
    inputs = {"CONF": "! changed marker", "FABRIC_ID": "-1"}
    entry = {"name": GROUP_ID, "switch_ids": ["SERIAL_A"], "priority": 510, "template_inputs": inputs}

    result = invoke(controller, [entry], check_mode=check_mode)

    assert not result.get("failed"), result
    assert result["changed"] is True
    if check_mode:
        assert controller.groups == before
        assert controller.writes() == []
    else:
        assert len(controller.writes("PUT")) == 1
        assert controller.writes("PUT")[0][2] == {
            "switchIds": ["SERIAL_A"],
            "templateName": "switch_freeform",
            "entityType": "switch",
            "entityName": "SWITCH",
            "priority": 510,
            "source": "",
            "templateInputs": inputs,
        }
