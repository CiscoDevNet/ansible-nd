# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Compatibility and no-op acceptance tests for direct policy-group updates.

These tests keep the existing effective PUT contract explicit: omitted priority
is preserved, omitted membership and inputs keep their existing direct-update
meaning, and real membership/intent changes retain their staged request order.
"""

# pylint: disable=protected-access

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.policy_group_base import (
    PolicyGroupCreate,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_policy_group import (
    PolicyGroupOrchestrator,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_policy_group_orchestrator import (
    _build_pg_raw,
    _build_rest_send,
    _make_orchestrator,
    _make_results,
    _resp,
)

POLICY_ID = "POLICY-GROUP-101"


def _current(**overrides):
    group = _build_pg_raw(
        policy_id=POLICY_ID,
        description=None,
        priority=725,
        switch_ids=["SN1", "SN2"],
        template_inputs={"featureName": "lacp"},
    )
    group.update(overrides)
    return group


def _desired(**overrides):
    config = {
        "name": "feature_enable",
        "policy_id": POLICY_ID,
        "switch_ids": ["SN1", "SN2"],
        "template_inputs": {"featureName": "lacp"},
    }
    config.update(overrides)
    return PolicyGroupCreate.from_config(config)


def _freeform_current():
    """Normalize the metadata-bearing summary shape observed on a controller."""
    return PolicyGroupOrchestrator._summary_to_policy_group(
        {
            "policyId": POLICY_ID,
            "policyType": "group",
            "templateName": "switch_freeform",
            "description": None,
            "entityName": "SWITCH",
            "entityType": "switch",
            "source": "",
            "switches": [{"switchId": "SN1", "priority": 510, "markDeleted": False}],
            "templateInputs": {
                "CONF": "! audit marker",
                "FABRIC_ID": "-1",
                "POLICY_DESC": "",
                "POLICY_ID": POLICY_ID,
                "PRIORITY": "510",
                "SECENTITY": "",
                "SECENTTYPE": "",
            },
        }
    )


def _freeform_desired(**overrides):
    config = {
        "name": "switch_freeform",
        "policy_id": POLICY_ID,
        "switch_ids": ["SN1"],
        "template_inputs": {"CONF": "! audit marker"},
    }
    config.update(overrides)
    return PolicyGroupCreate.from_config(config)


@pytest.mark.parametrize("current_priority", [1, 500, 725, 2000, "725"])
def test_omitted_priority_retains_existing_value_on_real_update(current_priority):
    """A no-op guard must not default an omitted update priority to 500."""
    current = _current(priority=current_priority)
    model = _desired(template_inputs={"featureName": "lldp"})
    rest_send = _build_rest_send([_resp({"policyId": POLICY_ID}, method="PUT")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [current]

    instance.update(model)

    assert len(results._tasks) == 1
    assert results._tasks[0].payload["priority"] == int(current_priority)
    assert results._tasks[0].payload["templateInputs"] == {"featureName": "lldp"}
    assert model.priority is None


@pytest.mark.parametrize("current_priority", [None, "invalid", 0, 2001])
def test_unusable_current_priority_retains_existing_fallback(current_priority):
    """Unknown controller priority must keep the previous outgoing 500 fallback."""
    rest_send = _build_rest_send([_resp({"policyId": POLICY_ID}, method="PUT")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [_current(priority=current_priority)]

    instance.update(_desired(template_inputs={"featureName": "lldp"}))

    assert results._tasks[-1].payload["priority"] == 500


@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("change", ["intent", "membership", "both", "rename"])
def test_real_changes_preserve_put_sequence_and_deploy_union(change, deploy):
    """Real changes keep the existing one/two-PUT wire behavior exactly."""
    current = _current()
    kwargs = {"priority": 725}
    if change in {"intent", "both"}:
        kwargs["template_inputs"] = {"featureName": "lldp"}
    if change in {"membership", "both"}:
        kwargs["switch_ids"] = ["SN2", "SN3"]
    if change == "rename":
        kwargs["description"] = "new description"
    model = _desired(**kwargs)
    split = change == "both"
    responses = [_resp({"policyId": POLICY_ID}, method="PUT") for _ in range(2 if split else 1)]
    if deploy:
        responses.append(_resp({"switchIds": []}, method="POST"))
    rest_send = _build_rest_send(responses)
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=deploy, results=results)
    instance._raw_cache = [current]

    instance.update(model)

    mutations = [task for task in results._tasks if task.verb == "PUT"]
    assert len(mutations) == (2 if split else 1)
    assert all(task.path.endswith("/policyGroups/" + POLICY_ID) for task in mutations)
    if split:
        expected_membership = PolicyGroupOrchestrator._policy_group_to_payload(current)
        expected_membership["switchIds"] = ["SN2", "SN3"]
        assert mutations[0].payload == expected_membership
    assert mutations[-1].payload == model.to_payload()
    deploys = [task for task in results._tasks if "switchActions/deploy" in task.path]
    assert len(deploys) == int(deploy)
    if deploy:
        expected = ["SN1", "SN2", "SN3"] if change in {"membership", "both"} else ["SN1", "SN2"]
        assert deploys[0].payload == {"switchIds": expected}


@pytest.mark.parametrize("missing_field", ["switch_ids", "template_inputs"])
def test_omitted_direct_fields_keep_existing_payload_meaning(missing_field):
    """The guard must not turn omission into a new implicit merge behavior."""
    current = _current()
    config = {
        "name": "feature_enable",
        "policy_id": POLICY_ID,
        "priority": 725,
        "switch_ids": ["SN1", "SN2"],
        "template_inputs": {"featureName": "lacp"},
    }
    del config[missing_field]
    model = PolicyGroupCreate.from_config(config)
    # Missing membership is still [], while missing inputs are still absent.
    desired = model.to_payload()
    if missing_field == "switch_ids":
        assert desired["switchIds"] == []
    else:
        assert "templateInputs" not in desired
    expected = PolicyGroupOrchestrator._build_update_payloads(current, desired)
    responses = [_resp({"policyId": POLICY_ID}, method="PUT") for _ in expected]
    rest_send = _build_rest_send(responses)
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [deepcopy(current)]

    instance.update(model)

    assert [task.payload for task in results._tasks] == expected
    assert expected[-1] == desired


@pytest.mark.parametrize(
    "current",
    [
        {},
        {"policyId": POLICY_ID, "switchIds": ["SN1"]},
        {
            "policyId": POLICY_ID,
            "templateName": "feature_enable",
            "priority": "invalid",
        },
    ],
)
def test_incomplete_or_invalid_current_state_keeps_fallback_put(current):
    """Failure to prove equality must not suppress the previous outgoing PUT."""
    rest_send = _build_rest_send([_resp({"policyId": POLICY_ID}, method="PUT")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [current] if current else []

    instance.update(_desired(priority=725))

    assert len(results._tasks) == 1
    assert results._tasks[0].verb == "PUT"


def test_current_lookup_targets_exact_id_before_update():
    """A same-template/description sibling must never supply update defaults."""
    wrong = _current(policyId="POLICY-GROUP-102", priority=500)
    correct = _current(priority=725)
    rest_send = _build_rest_send([_resp({"policyId": POLICY_ID}, method="PUT")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [wrong, correct]

    instance.update(_desired(template_inputs={"featureName": "lldp"}))

    assert results._tasks[0].payload["priority"] == 725
    assert results._tasks[0].path.endswith("/policyGroups/" + POLICY_ID)


@pytest.mark.parametrize("deploy", [False, True])
def test_generic_update_retains_its_existing_unconditional_put_contract(deploy):
    """The direct-only correction must not change the normal update API."""
    responses = [_resp({"policyId": POLICY_ID}, method="PUT")]
    if deploy:
        responses.append(_resp({"switchIds": []}, method="POST"))
    rest_send = _build_rest_send(responses)
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=deploy, results=results)
    instance._raw_cache = [_current()]

    result = instance.update(_desired())

    assert result == {"policyId": POLICY_ID}
    assert results._tasks[0].verb == "PUT"
    assert results._tasks[0].payload["priority"] == 725
    assert len(results._tasks) == (2 if deploy else 1)


@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("description", [None, ""])
def test_identical_direct_update_skips_put_and_preserves_requested_deploy(deploy, check_mode, description):
    """A proved no-op skips configuration writes, including dry-run requests."""
    responses = [_resp({"switchIds": []}, method="POST")] if deploy and not check_mode else []
    rest_send = _build_rest_send(responses)
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=deploy, results=results)
    instance._raw_cache = [_current(description=description)]

    changed = instance.update_direct(_desired(description=description), check_mode=check_mode)

    assert changed is False
    assert all(task.verb != "PUT" for task in results._tasks)
    assert len(results._tasks) == int(deploy and not check_mode)
    if results._tasks:
        assert "switchActions/deploy" in results._tasks[0].path
        assert results._tasks[0].payload == {"switchIds": ["SN1", "SN2"]}


@pytest.mark.parametrize("switch_ids", [["SN2", "SN1"], ["SN2", "SN1", "SN2"]])
def test_direct_noop_treats_membership_as_a_set(switch_ids):
    """Order and repeated members do not introduce a controller mutation."""
    rest_send = _build_rest_send([])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [_current()]

    assert instance.update_direct(_desired(switch_ids=switch_ids)) is False
    assert results._tasks == []


@pytest.mark.parametrize("user_value,controller_value", [(5, "5"), (True, "True"), ("005", "005")])
def test_direct_noop_uses_existing_template_input_config_coercion(user_value, controller_value):
    """Controller strings compare with the existing user-input coercion."""
    rest_send = _build_rest_send([])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [_current(templateInputs={"value": controller_value})]

    assert instance.update_direct(_desired(template_inputs={"value": user_value})) is False
    assert results._tasks == []


def test_direct_noop_ignores_controller_identity_and_status_metadata():
    """Only the normalized writable configuration determines a no-op."""
    rest_send = _build_rest_send([])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [
        _current(
            policyType="group",
            updateTimestamp=123456,
            createTimestamp=123,
            status="out-of-sync",
            generatedConfig="feature lacp",
            switches=[{"switchId": "SN1", "status": "pending"}],
        )
    ]

    assert instance.update_direct(_desired()) is False
    assert results._tasks == []


def test_direct_noop_normalizes_controller_priority_echo():
    """The established PRIORITY compatibility normalization also applies here."""
    current = _current(templateInputs={"featureName": "lacp", "PRIORITY": "725"})
    del current["priority"]
    rest_send = _build_rest_send([])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [current]

    assert instance.update_direct(_desired()) is False
    assert results._tasks == []


@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("change", ["intent", "membership", "both", "rename"])
def test_direct_real_changes_keep_requests_and_report_planned_changes(change, deploy, check_mode):
    """Direct mode changes only no-op handling, not accepted mutation bodies."""
    current = _current()
    kwargs = {"priority": 725}
    if change in {"intent", "both"}:
        kwargs["template_inputs"] = {"featureName": "lldp"}
    if change in {"membership", "both"}:
        kwargs["switch_ids"] = ["SN2", "SN3"]
    if change == "rename":
        kwargs["description"] = "new description"
    model = _desired(**kwargs)
    expected = PolicyGroupOrchestrator._build_update_payloads(current, model.to_payload())
    responses = []
    if not check_mode:
        responses.extend(_resp({"policyId": POLICY_ID}, method="PUT") for _ in expected)
        if deploy:
            responses.append(_resp({"switchIds": []}, method="POST"))
    rest_send = _build_rest_send(responses)
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=deploy, results=results)
    instance._raw_cache = [current]

    assert instance.update_direct(model, check_mode=check_mode) is True
    if check_mode:
        assert results._tasks == []
    else:
        assert [task.payload for task in results._tasks if task.verb == "PUT"] == expected
        deploy_tasks = [task for task in results._tasks if "switchActions/deploy" in task.path]
        assert len(deploy_tasks) == int(deploy)
        if deploy:
            expected_switches = ["SN1", "SN2", "SN3"] if change in {"membership", "both"} else ["SN1", "SN2"]
            assert deploy_tasks[0].payload == {"switchIds": expected_switches}


@pytest.mark.parametrize(
    "current",
    [
        {},
        {"policyId": POLICY_ID, "switchIds": ["SN1", "SN2"]},
        _current(priority="invalid"),
        _current(priority=0),
        _current(policyId="POLICY-GROUP-102"),
    ],
)
@pytest.mark.parametrize("check_mode", [False, True])
def test_direct_unknown_or_unreliable_current_falls_back_to_existing_update(current, check_mode):
    """Unknown state cannot prove equality and must never become a false no-op."""
    responses = [] if check_mode else [_resp({"policyId": POLICY_ID}, method="PUT")]
    rest_send = _build_rest_send(responses)
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [current] if current else []

    assert instance.update_direct(_desired(priority=725), check_mode=check_mode) is True
    assert len(results._tasks) == int(not check_mode)
    if results._tasks:
        assert results._tasks[0].verb == "PUT"
        assert results._tasks[0].path.endswith("/policyGroups/" + POLICY_ID)


@pytest.mark.parametrize("omitted", ["switch_ids", "template_inputs"])
def test_direct_omitted_fields_are_compared_with_existing_effective_payload(omitted):
    """A sparse direct update retains its established clearing/replacement body."""
    config = {
        "name": "feature_enable",
        "policy_id": POLICY_ID,
        "priority": 725,
        "switch_ids": ["SN1", "SN2"],
        "template_inputs": {"featureName": "lacp"},
    }
    del config[omitted]
    model = PolicyGroupCreate.from_config(config)
    expected = PolicyGroupOrchestrator._build_update_payloads(_current(), model.to_payload())
    rest_send = _build_rest_send([_resp({"policyId": POLICY_ID}, method="PUT") for _ in expected])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [_current()]

    assert instance.update_direct(model) is True
    assert [task.payload for task in results._tasks] == expected


def test_direct_failed_put_keeps_exception_and_does_not_deploy():
    """A failed intent update must not be converted into success or deployment."""
    rest_send = _build_rest_send(
        [
            _resp(
                {"error": "Rejected update"},
                method="PUT",
                return_code=400,
                message="Bad Request",
            )
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=True, results=results)
    instance._raw_cache = [_current()]

    with pytest.raises(Exception, match="Update policy group failed"):
        instance.update_direct(_desired(priority=600))

    assert all("switchActions/deploy" not in task.path for task in results._tasks)


def test_direct_split_failure_preserves_accepted_first_request_and_stops_deployment():
    """The no-op wrapper preserves the existing first-PUT/second-PUT boundary."""
    rest_send = _build_rest_send(
        [
            _resp({"policyId": POLICY_ID}, method="PUT"),
            _resp(
                {"error": "Rejected intent"},
                method="PUT",
                return_code=400,
                message="Bad Request",
            ),
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=True, results=results)
    current = _current()
    instance._raw_cache = [current]
    model = _desired(switch_ids=["SN2", "SN3"], template_inputs={"featureName": "lldp"}, priority=725)

    with pytest.raises(Exception, match="Update policy group failed"):
        instance.update_direct(model)

    expected = PolicyGroupOrchestrator._build_update_payloads(current, model.to_payload())
    assert [task.payload for task in results._tasks] == expected
    assert results._tasks[0].failed is False
    assert results._tasks[1].failed is True


def test_direct_noop_uses_exact_id_when_duplicate_siblings_exist():
    """A newer sibling cannot introduce a false diff for the requested ID."""
    rest_send = _build_rest_send([])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [
        _current(policyId="POLICY-GROUP-102", priority=500, updateTimestamp=200),
        _current(priority=725, updateTimestamp=100),
    ]

    assert instance.update_direct(_desired()) is False
    assert results._tasks == []


def test_direct_source_difference_remains_an_effective_payload_change():
    """Source is currently writable, so this guard must not change its meaning."""
    rest_send = _build_rest_send([_resp({"policyId": POLICY_ID}, method="PUT")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [_current(source="controller-marker")]

    assert instance.update_direct(_desired()) is True
    assert len(results._tasks) == 1
    assert results._tasks[0].payload["source"] == ""


@pytest.mark.parametrize("check_mode", [False, True])
def test_direct_lookup_failure_keeps_existing_fallback(monkeypatch, check_mode):
    """A current-state read failure remains an update attempt, never a no-op."""

    def fail_lookup(self, policy_group_id):
        assert policy_group_id == POLICY_ID
        raise RuntimeError("simulated read failure")

    monkeypatch.setattr(PolicyGroupOrchestrator, "query_by_id", fail_lookup)
    responses = [] if check_mode else [_resp({"policyId": POLICY_ID}, method="PUT")]
    rest_send = _build_rest_send(responses)
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)

    assert instance.update_direct(_desired(), check_mode=check_mode) is True
    assert len(results._tasks) == int(not check_mode)


def test_direct_comparison_does_not_mutate_config_or_cached_controller_data():
    """Preserving priority for comparison must not rewrite proposed output."""
    rest_send = _build_rest_send([])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    current = _current()
    model = _desired()
    before_model = deepcopy(model.model_dump())
    before_current = deepcopy(current)
    instance._raw_cache = [current]

    assert instance.update_direct(model) is False
    assert model.model_dump() == before_model
    assert current == before_current
    assert model.priority is None


@pytest.mark.parametrize(
    "empty_shape",
    [
        {},
        {"description": None, "source": None, "templateInputs": None},
        {"description": "", "source": "", "templateInputs": {}},
        {"source": None, "templateInputs": {}},
        {"description": "", "templateInputs": None},
        {"description": None, "source": ""},
    ],
)
def test_direct_noop_accepts_equivalent_absent_and_empty_optional_values(empty_shape):
    """Missing/null/empty optional controller values retain their empty meaning."""
    current = _current()
    for field in ("description", "source", "templateInputs"):
        current.pop(field, None)
    current.update(empty_shape)
    rest_send = _build_rest_send([])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [current]

    assert instance.update_direct(_desired(template_inputs=None)) is False
    assert results._tasks == []


@pytest.mark.parametrize("current_value,desired_value", [("005", "5"), ("5", "005")])
def test_direct_template_input_strings_keep_exact_meaning(current_value, desired_value):
    """Template strings must not receive numeric coercion during comparison."""
    rest_send = _build_rest_send([_resp({"policyId": POLICY_ID}, method="PUT")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [_current(templateInputs={"value": current_value})]

    assert instance.update_direct(_desired(template_inputs={"value": desired_value})) is True
    assert len(results._tasks) == 1
    assert results._tasks[0].payload["templateInputs"] == {"value": desired_value}


def test_direct_noop_deploy_failure_remains_failure_without_put():
    """An explicit deployment error must retain the public update error prefix."""
    rest_send = _build_rest_send(
        [
            _resp(
                {"error": "Deploy rejected"},
                method="POST",
                return_code=400,
                message="Bad Request",
            )
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=True, results=results)
    instance._raw_cache = [_current()]

    with pytest.raises(Exception, match="^Update policy group failed"):
        instance.update_direct(_desired())

    assert len(results._tasks) == 1
    assert results._tasks[0].verb == "POST"
    assert "switchActions/deploy" in results._tasks[0].path
    assert results._tasks[0].failed is True


@pytest.mark.parametrize(
    "field,value",
    [("priority", None), ("switchIds", None), ("switchIds", []), ("switchIds", [""])],
)
def test_direct_unknown_required_state_cannot_prove_noop(field, value):
    """An unknown/empty required value is conservative even if defaults align."""
    current = _current()
    current[field] = value
    rest_send = _build_rest_send([_resp({"policyId": POLICY_ID}, method="PUT")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [current]

    assert instance.update_direct(_desired(priority=500 if field == "priority" else 725)) is True
    assert len(results._tasks) == 1
    assert results._tasks[0].verb == "PUT"


@pytest.mark.parametrize("field", ["priority", "switchIds"])
def test_direct_absent_required_state_cannot_prove_noop(field):
    """Absent priority/membership must not be mistaken for known default state."""
    current = _current()
    del current[field]
    rest_send = _build_rest_send([_resp({"policyId": POLICY_ID}, method="PUT")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = [current]

    assert instance.update_direct(_desired(priority=500 if field == "priority" else 725)) is True
    assert len(results._tasks) == 1
    assert results._tasks[0].verb == "PUT"


@pytest.mark.parametrize("deploy", [False, True])
def test_direct_noop_retains_query_caches(deploy):
    """Skipping a PUT must not discard the still-valid current intent cache."""
    responses = [_resp({"switchIds": []}, method="POST")] if deploy else []
    rest_send = _build_rest_send(responses)
    instance = _make_orchestrator(rest_send, deploy=deploy)
    raw = [_current()]
    summary = [deepcopy(raw[0])]
    instance._raw_cache = raw
    instance._policy_summary_cache = summary

    assert instance.update_direct(_desired()) is False
    assert instance._raw_cache is raw
    assert instance._policy_summary_cache is summary


def test_direct_real_update_invalidates_query_caches():
    """A successful mutation retains the existing broad-read invalidation."""
    rest_send = _build_rest_send([_resp({"policyId": POLICY_ID}, method="PUT")])
    instance = _make_orchestrator(rest_send, deploy=False)
    instance._raw_cache = [_current()]
    instance._policy_summary_cache = [_current()]

    assert instance.update_direct(_desired(priority=600)) is True
    assert instance._raw_cache is None
    assert instance._policy_summary_cache is None


@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_direct_freeform_metadata_noop_preserves_payloads_and_explicit_deploy(deploy, check_mode):
    """Controller bookkeeping must not make identical anonymous intent change."""
    responses = [_resp({"switchIds": []}, method="POST")] if deploy and not check_mode else []
    results = _make_results()
    instance = _make_orchestrator(_build_rest_send(responses), deploy=deploy, results=results)
    current = _freeform_current()
    model = _freeform_desired()
    before_current = deepcopy(current)
    before_model = deepcopy(model.model_dump())
    instance._raw_cache = [current]

    assert instance.update_direct(model, check_mode=check_mode) is False
    assert current == before_current
    assert model.model_dump() == before_model
    assert model.priority is None
    assert len(results._tasks) == int(deploy and not check_mode)
    if results._tasks:
        assert "switchActions/deploy" in results._tasks[0].path
        assert results._tasks[0].payload == {"switchIds": ["SN1"]}


def test_direct_freeform_metadata_is_ignored_symmetrically():
    """Reserved echoes on the desired side are comparison-only metadata too."""
    current = _freeform_current()
    inputs = {
        "CONF": "! audit marker",
        "FABRIC_ID": "another-id",
        "FABRIC_NAME": "another-fabric",
        "MARK_DELETED": "false",
        "POLICY_DESC": "another-description",
        "POLICY_GROUP_ID": "another-group",
        "POLICY_ID": "another-policy",
        "PRIORITY": "510",
        "SECENTITY": "another-entity",
        "SECENTTYPE": "another-type",
        "SERIAL_NUMBER": "another-serial",
        "SOURCE": "another-source",
        "SWITCH_DB_ID": "another-switch-id",
    }
    model = _freeform_desired(template_inputs=inputs)
    before_current = deepcopy(current)
    before_model = deepcopy(model.model_dump())
    results = _make_results()
    instance = _make_orchestrator(_build_rest_send([]), deploy=False, results=results)
    instance._raw_cache = [current]

    assert instance.update_direct(model) is False
    assert results._tasks == []
    assert current == before_current
    assert model.model_dump() == before_model


def test_direct_metadata_only_inputs_match_omitted_inputs():
    """A map containing bookkeeping alone has the existing empty-input meaning."""
    current = _freeform_current()
    del current["templateInputs"]["CONF"]
    results = _make_results()
    instance = _make_orchestrator(_build_rest_send([]), deploy=False, results=results)
    instance._raw_cache = [current]

    assert instance.update_direct(_freeform_desired(template_inputs=None)) is False
    assert results._tasks == []


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize(
    "overrides",
    [
        {"template_inputs": {"CONF": "! changed marker"}},
        {"template_inputs": {"CONF": "! audit marker", "CUSTOM_INPUT": "new value"}},
        {"priority": 600, "template_inputs": {"CONF": "! audit marker", "PRIORITY": "510"}},
        {"switch_ids": ["SN1", "SN2"]},
        {"description": "new description"},
        {"entity_name": "Ethernet1/1"},
        {"entity_type": "interface"},
        {"secondary_entity_name": "overlay"},
        {"secondary_entity_type": "configProfile"},
    ],
)
def test_direct_freeform_real_changes_keep_existing_wire_payloads(overrides, check_mode):
    """Ignoring known echoes must retain actual field changes and PUT sequencing."""
    current = _freeform_current()
    model = _freeform_desired(**{"priority": 510, **overrides})
    before_current = deepcopy(current)
    before_model = deepcopy(model.model_dump())
    expected = PolicyGroupOrchestrator._build_update_payloads(current, model.to_payload())
    responses = [] if check_mode else [_resp({"policyId": POLICY_ID}, method="PUT") for _ in expected]
    results = _make_results()
    instance = _make_orchestrator(_build_rest_send(responses), deploy=False, results=results)
    instance._raw_cache = [current]

    assert instance.update_direct(model, check_mode=check_mode) is True
    assert current == before_current
    assert model.model_dump() == before_model
    assert [task.payload for task in results._tasks] == ([] if check_mode else expected)
    if not check_mode:
        assert all(task.verb == "PUT" for task in results._tasks)
        assert results._tasks[-1].payload == model.to_payload()
        if "priority" in overrides:
            assert results._tasks[-1].payload["priority"] == 600


def test_direct_metadata_priority_fallback_still_recovers_top_level_priority():
    """Filtering PRIORITY must happen after the established echo normalization."""
    current = _freeform_current()
    del current["priority"]
    results = _make_results()
    instance = _make_orchestrator(_build_rest_send([]), deploy=False, results=results)
    instance._raw_cache = [current]

    assert instance.update_direct(_freeform_desired(priority=510)) is False
    assert results._tasks == []


@pytest.mark.parametrize("key", ["CUSTOM_INPUT", "fabric_id"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_direct_nonreserved_current_inputs_are_still_compared(key, check_mode):
    """Only the exact reserved names are ignored, including when input is removed."""
    current = _freeform_current()
    current["templateInputs"][key] = "existing value"
    responses = [] if check_mode else [_resp({"policyId": POLICY_ID}, method="PUT")]
    results = _make_results()
    instance = _make_orchestrator(_build_rest_send(responses), deploy=False, results=results)
    instance._raw_cache = [current]

    assert instance.update_direct(_freeform_desired(), check_mode=check_mode) is True
    assert len(results._tasks) == int(not check_mode)
    if results._tasks:
        assert results._tasks[0].payload["templateInputs"] == {"CONF": "! audit marker"}
