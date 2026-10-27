# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Exercise policy reporting through real planning, execution, and module exit.

Only Ansible process boundaries and NDModule's HTTP boundary are replaced.
The actual configuration validation, policy matching, diff computation, endpoint
models, operation execution, Results, and NDOutput all run normally.
"""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModuleError
from ansible_collections.cisco.nd.plugins.modules import nd_manage_policy

POLICY_ID = "POLICY-101"
SECOND_ID = "POLICY-102"
SWITCH_ID = "SERIAL_A"


class ModuleResult(BaseException):
    """Stop execution at the Ansible process boundary, outside exception handling."""

    def __init__(self, result):
        self.result = result


def policy(pid=POLICY_ID, **overrides):
    """Return a controller record with complete writable fields and metadata."""
    return {
        "policyId": pid,
        "switchId": SWITCH_ID,
        "templateName": "feature_enable",
        "description": "feature intent",
        "priority": 725,
        "source": "",
        "entityType": "switch",
        "entityName": "SWITCH",
        "templateInputs": {"featureName": "lacp", "FABRIC_NAME": "FABRIC_A"},
        **overrides,
    }


def config(name=POLICY_ID, **overrides):
    """Use the public single-policy embedded-switch shape."""
    return {"name": name, "switch": [{"serial_number": SWITCH_ID}], **overrides}


class Controller:
    """A stateful ND HTTP boundary with controlled per-entry and HTTP failures."""

    def __init__(self, policies=None):
        self.policies = {entry["policyId"]: deepcopy(entry) for entry in policies or []}
        self.calls = []
        self.reject_updates = set()
        self.crash_updates = set()
        self.reject_creates = set()
        self.crash_creates = set()
        self.reject_deletes = set()
        self.reject_push = set()
        self.reject_switch_deploy = False
        self.next_id = 200

    def request(self, verb, path, payload=None):
        self.calls.append((verb, path, deepcopy(payload)))
        resource = urlsplit(path).path
        if verb == "GET" and resource.endswith("/policies"):
            return {"policies": deepcopy(list(self.policies.values()))}
        if verb == "GET" and resource.endswith("/parameters"):
            return {"parameters": [{"name": "featureName", "parameterType": "string", "optional": True}]}
        if verb == "PUT" and "/policies/" in resource:
            pid = resource.rsplit("/", 1)[-1]
            if pid in self.crash_updates:
                raise RuntimeError("simulated unexpected update failure")
            if pid in self.reject_updates:
                raise NDModuleError(
                    msg="simulated rejected update",
                    status=400,
                    response_payload={"policyId": pid, "message": "rejected"},
                )
            self.policies[pid] = {**deepcopy(payload), "policyId": pid}
            return {"policyId": pid, "status": "success"}
        if verb == "POST" and resource.endswith("/policies"):
            entries = []
            for desired in payload["policies"]:
                if desired["templateName"] in self.crash_creates:
                    raise RuntimeError("simulated unexpected create failure")
                if desired["templateName"] in self.reject_creates:
                    entries.append({"status": "failed", "message": "simulated rejected create"})
                    continue
                pid = f"POLICY-{self.next_id}"
                self.next_id += 1
                self.policies[pid] = {**deepcopy(desired), "policyId": pid}
                entries.append({"policyId": pid, "status": "success"})
            return {"policies": entries}
        if verb == "POST" and resource.endswith("/markDelete"):
            entries = []
            for pid in payload["policyIds"]:
                rejected = pid in self.reject_deletes
                entries.append(
                    {
                        "policyId": pid,
                        "status": "failed" if rejected else "success",
                        "message": "rejected" if rejected else "OK",
                    }
                )
                if not rejected and pid in self.policies:
                    self.policies[pid]["markDeleted"] = True
            return {"policies": entries}
        if verb == "POST" and resource.endswith("/pushConfig"):
            return {
                "policies": [
                    {
                        "policyId": pid,
                        "status": "failed" if pid in self.reject_push else "success",
                        "message": "push rejected" if pid in self.reject_push else "OK",
                    }
                    for pid in payload["policyIds"]
                ]
            }
        if verb == "POST" and resource.endswith("/switchActions/deploy"):
            if self.reject_switch_deploy:
                raise NDModuleError(
                    msg="simulated rejected switch deployment",
                    status=400,
                    response_payload={"message": "deploy rejected"},
                )
            return {"switchIds": [{"switchId": sid, "status": "success"} for sid in payload["switchIds"]]}
        if verb == "DELETE" and "/policies/" in resource:
            self.policies.pop(resource.rsplit("/", 1)[-1], None)
            return {}
        raise AssertionError(f"Unexpected HTTP request: {verb} {path}: {payload!r}")

    def writes(self):
        return [call for call in self.calls if call[0] != "GET"]


@pytest.fixture
def invoke(monkeypatch):
    """Drive actual main() with a reusable stateful controller."""

    class Module:
        def __init__(self, params, check_mode, verbosity):
            self.params = deepcopy(params)
            self.check_mode = check_mode
            self._verbosity = verbosity
            self.warnings = []
            self.no_log_values = set()

        def exit_json(self, **kwargs):
            raise ModuleResult(kwargs)

        def fail_json(self, **kwargs):
            raise ModuleResult({"failed": True, **kwargs})

        def warn(self, message):
            self.warnings.append(message)

    class FakeND:
        def __init__(self, module, controller):
            self.module = module
            self.controller = controller
            self.rest_send = SimpleNamespace(response_current={}, result_current={})

        def request(self, path, verb, payload=None):
            method = verb.value if hasattr(verb, "value") else verb
            try:
                data = self.controller.request(method, path, payload)
            except NDModuleError as error:
                self.rest_send.response_current = {
                    "RETURN_CODE": error.status,
                    "METHOD": method,
                    "REQUEST_PATH": path,
                    "MESSAGE": error.msg,
                    "DATA": error.response_payload,
                }
                self.rest_send.result_current = {
                    "success": False,
                    "found": False,
                    "changed": False,
                }
                raise
            self.rest_send.response_current = {
                "RETURN_CODE": 200,
                "METHOD": method,
                "REQUEST_PATH": path,
                "MESSAGE": "OK",
                "DATA": data,
            }
            self.rest_send.result_current = {
                "success": True,
                "found": True,
                "changed": False,
            }
            return data

    monkeypatch.setattr(nd_manage_policy, "Log", lambda: SimpleNamespace(commit=lambda: None))

    def run(
        controller,
        entries,
        *,
        state="merged",
        deploy=False,
        check_mode=False,
        use_description_as_key=False,
        output_level="normal",
        verbosity=0,
    ):
        module = Module(
            {
                "fabric_name": "FABRIC_A",
                "state": state,
                "deploy": deploy,
                "config": entries,
                "use_description_as_key": use_description_as_key,
                "ticket_id": None,
                "cluster_name": None,
                "output_level": output_level,
            },
            check_mode,
            verbosity,
        )
        monkeypatch.setattr(nd_manage_policy, "AnsibleModule", lambda **_kwargs: module)
        monkeypatch.setattr(nd_manage_policy, "NDModule", lambda _module: FakeND(module, controller))
        with pytest.raises(ModuleResult) as captured:
            nd_manage_policy.main()
        return captured.value.result

    return run


@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("action", ["create", "update", "replace", "delete"])
def test_check_mode_reports_validated_planned_mutations(invoke, deploy, action):
    """Every mutation preview reports changed without HTTP writes or deployment."""
    controller = Controller([] if action == "create" else [policy()])
    before = deepcopy(controller.policies)
    if action == "create":
        entry = config(
            "feature_enable",
            description="new feature",
            template_inputs={"featureName": "lacp"},
        )
    elif action == "replace":
        entry = config(
            "feature_disable",
            description="feature intent",
            template_inputs={"featureName": "lldp"},
        )
    elif action == "update":
        entry = config(priority=600)
    else:
        entry = config()

    result = invoke(
        controller,
        [entry],
        state="deleted" if action == "delete" else "merged",
        check_mode=True,
        deploy=deploy,
        use_description_as_key=action == "replace",
        verbosity=3,
    )

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert controller.writes() == []
    assert controller.policies == before
    if action == "create":
        assert result["before"] == []
        assert result["after"][0]["priority"] == 500
        assert "policyId" not in result["after"][0]
    elif action == "delete":
        assert result["before"] == [policy()]
        assert result["after"] == []
    elif action == "replace":
        assert result["before"] == [policy()]
        assert result["after"][0]["templateName"] == "feature_disable"
        assert "policyId" not in result["after"][0]


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("deploy", [False, True])
def test_unchanged_policy_and_deploy_only_report_no_change(invoke, check_mode, deploy):
    controller = Controller([policy()])
    result = invoke(controller, [config()], check_mode=check_mode, deploy=deploy)

    assert not result.get("failed"), result
    assert result["changed"] is False
    assert result["before"] == result["after"] == [policy()]
    assert len(controller.writes()) == int(deploy and not check_mode)
    assert all("/pushConfig" in path for _verb, path, _payload in controller.writes())


@pytest.mark.parametrize("check_mode", [False, True])
def test_absent_delete_without_cleanup_reports_no_change(invoke, check_mode):
    controller = Controller()
    result = invoke(controller, [config()], state="deleted", check_mode=check_mode)

    assert not result.get("failed"), result
    assert result["changed"] is False
    assert result["before"] == result["after"] == []
    assert controller.writes() == []


@pytest.mark.parametrize("check_mode", [False, True])
def test_empty_gathered_always_reports_an_empty_list(invoke, check_mode):
    controller = Controller()
    result = invoke(controller, [config()], state="gathered", check_mode=check_mode)

    assert not result.get("failed"), result
    assert result["changed"] is False
    assert result["gathered"] == []
    assert controller.writes() == []


@pytest.mark.parametrize("check_mode", [False, True])
def test_sparse_update_after_preserves_omitted_priority_and_existing_inputs(invoke, check_mode):
    controller = Controller([policy()])
    result = invoke(controller, [config(description="new description")], check_mode=check_mode)

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert result["after"][0]["priority"] == 725
    assert result["after"][0]["templateInputs"] == policy()["templateInputs"]
    assert result["after"][0]["description"] == "new description"
    if not check_mode:
        payload = controller.writes()[0][2]
        for key in payload:
            assert result["after"][0][key] == payload[key]


@pytest.mark.parametrize("unexpected", [False, True])
def test_second_update_failure_reports_accepted_progress_and_unchanged_rejection(invoke, unexpected):
    third_id = "POLICY-103"
    original = [policy(), policy(SECOND_ID, description="second feature"), policy(third_id, description="third feature")]
    controller = Controller(original)
    (controller.crash_updates if unexpected else controller.reject_updates).add(SECOND_ID)

    result = invoke(
        controller,
        [config(priority=600), config(SECOND_ID, priority=650), config(third_id, priority=700)],
        verbosity=3,
    )

    assert result["failed"] is True
    assert result["changed"] is True
    assert result["before"] == original
    expected_third_priority = 725 if unexpected else 700
    assert {entry["policyId"]: entry["priority"] for entry in result["after"]} == {
        POLICY_ID: 600,
        SECOND_ID: 725,
        third_id: expected_third_priority,
    }
    assert controller.policies[POLICY_ID]["priority"] == 600
    assert controller.policies[SECOND_ID] == original[1]
    assert controller.policies[third_id]["priority"] == expected_third_priority
    if unexpected:
        assert controller.policies[third_id] == original[2]
    expected_targets = [POLICY_ID, SECOND_ID] if unexpected else [POLICY_ID, SECOND_ID, third_id]
    assert [(verb, urlsplit(path).path.rsplit("/", 1)[-1]) for verb, path, _payload in controller.writes()] == [
        ("PUT", policy_id) for policy_id in expected_targets
    ]


def test_failed_update_only_reports_no_accepted_change_and_retains_original(invoke):
    controller = Controller([policy()])
    controller.reject_updates.add(POLICY_ID)
    result = invoke(controller, [config(priority=600)], verbosity=3)

    assert result["failed"] is True
    assert result["changed"] is False
    assert result["before"] == result["after"] == [policy()]
    assert controller.policies[POLICY_ID] == policy()


def test_replacement_removed_but_create_failed_reports_change(invoke):
    """Accepted removal remains a change when the replacement create is rejected."""
    controller = Controller([policy()])
    controller.reject_creates.add("feature_disable")
    result = invoke(
        controller,
        [config("feature_disable", description="feature intent")],
        use_description_as_key=True,
        verbosity=3,
    )

    assert result["failed"] is True
    assert result["changed"] is True
    assert result["before"] == [policy()]
    assert result["after"] == []
    assert controller.policies[POLICY_ID]["markDeleted"] is True
    assert [call[0] for call in controller.writes()] == ["POST", "POST"]


@pytest.mark.parametrize("check_mode", [False, True])
def test_invalid_only_request_does_not_report_a_change(invoke, check_mode):
    controller = Controller()
    result = invoke(controller, [config("POLICY-999")], check_mode=check_mode)

    assert result["failed"] is True
    assert result["changed"] is False
    assert result["before"] == result["after"] == []
    assert controller.writes() == []


def test_check_mode_mixed_valid_and_invalid_reports_valid_planned_change(invoke):
    controller = Controller()
    result = invoke(
        controller,
        [config("feature_enable", description="new feature"), config("POLICY-999")],
        check_mode=True,
    )

    assert result["failed"] is True
    assert result["changed"] is True
    assert len(result["after"]) == 1
    assert result["after"][0]["templateName"] == "feature_enable"
    assert "policyId" not in result["after"][0]
    assert controller.writes() == []


@pytest.mark.parametrize("formatter_fails", [False, True])
def test_check_mode_later_preview_error_retains_earlier_plan(invoke, monkeypatch, formatter_fails):
    """The upstream change calculation also applies to both failure formatters."""
    controller = Controller()
    create_model = nd_manage_policy.NDPolicyModule._create_policy_model

    def fail_second_preview(self, want):
        if want["templateName"] == "feature_disable":
            raise RuntimeError("simulated second preview failure")
        return create_model(self, want)

    monkeypatch.setattr(nd_manage_policy.NDPolicyModule, "_create_policy_model", fail_second_preview)
    if formatter_fails:

        def fail_formatter(*_args, **_kwargs):
            raise RuntimeError("simulated formatter failure")

        monkeypatch.setattr(nd_manage_policy, "_format_module_result", fail_formatter)

    result = invoke(
        controller,
        [
            config("feature_enable", description="first feature"),
            config("feature_disable", description="second feature"),
        ],
        check_mode=True,
    )

    assert result["failed"] is True
    assert result["changed"] is True
    assert result["msg"] == "RuntimeError: simulated second preview failure"
    assert result["before"] == []
    assert len(result["after"]) == 1
    assert result["after"][0]["templateName"] == "feature_enable"
    assert "policyId" not in result["after"][0]
    assert controller.writes() == []


@pytest.mark.parametrize("check_mode", [False, True])
def test_absent_delete_cleanup_reports_planned_or_executed_change(invoke, check_mode):
    """Cleanup is a change in both modes, with no writes during check mode."""
    controller = Controller()
    result = invoke(controller, [config()], state="deleted", deploy=True, check_mode=check_mode)

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert result["before"] == result["after"] == []
    assert len(controller.writes()) == int(not check_mode)
    assert all("/switchActions/deploy" in path for _verb, path, _payload in controller.writes())


@pytest.mark.parametrize("check_mode", [False, True])
def test_successful_create_reports_effective_default_and_preserves_wire_contract(invoke, check_mode):
    controller = Controller()
    result = invoke(
        controller,
        [
            config(
                "feature_enable",
                description="new feature",
                template_inputs={"featureName": "lacp"},
            )
        ],
        check_mode=check_mode,
    )

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert result["before"] == []
    assert result["after"][0]["priority"] == 500
    expected_body = {
        "switchId": SWITCH_ID,
        "templateName": "feature_enable",
        "entityType": "switch",
        "entityName": "SWITCH",
        "description": "new feature",
        "priority": 500,
        "source": "",
        "templateInputs": {"featureName": "lacp"},
    }
    if check_mode:
        assert controller.writes() == []
        assert "policyId" not in result["after"][0]
        assert result["after"] == [expected_body]
    else:
        assert len(controller.writes()) == 1
        verb, path, payload = controller.writes()[0]
        assert verb == "POST" and urlsplit(path).path.endswith("/policies")
        assert payload == {
            "policies": [
                {
                    "switchId": SWITCH_ID,
                    "templateName": "feature_enable",
                    "entityType": "switch",
                    "entityName": "SWITCH",
                    "description": "new feature",
                    "priority": 500,
                    "source": "",
                    "templateInputs": {"featureName": "lacp"},
                }
            ]
        }
        assert result["after"][0]["policyId"] == "POLICY-200"
        assert result["after"] == [{**payload["policies"][0], "policyId": "POLICY-200"}]


def test_bulk_create_partial_failure_keeps_successful_sibling_only(invoke):
    controller = Controller()
    controller.reject_creates.add("feature_disable")
    result = invoke(
        controller,
        [
            config("feature_enable", description="first feature"),
            config("feature_disable", description="second feature"),
        ],
        verbosity=3,
    )

    assert result["failed"] is True
    assert result["changed"] is True
    assert result["before"] == []
    assert [entry["templateName"] for entry in result["after"]] == ["feature_enable"]
    assert list(controller.policies) == ["POLICY-200"]
    assert len(controller.writes()) == 1


def test_update_accepted_but_push_rejected_keeps_accepted_after(invoke):
    controller = Controller([policy()])
    controller.reject_push.add(POLICY_ID)
    result = invoke(controller, [config(priority=600)], deploy=True, verbosity=3)

    assert result["failed"] is True
    assert result["changed"] is True
    assert result["before"] == [policy()]
    assert result["after"][0]["priority"] == controller.policies[POLICY_ID]["priority"] == 600
    assert result["after"][0]["templateInputs"] == controller.policies[POLICY_ID]["templateInputs"]
    assert [call[0] for call in controller.writes()] == ["PUT", "POST"]


def test_replacement_remove_rejected_preserves_original_and_skips_create(invoke):
    controller = Controller([policy()])
    controller.reject_deletes.add(POLICY_ID)
    result = invoke(
        controller,
        [config("feature_disable", description="feature intent")],
        use_description_as_key=True,
    )

    assert result["failed"] is True
    assert result["changed"] is False
    assert result["before"] == result["after"] == [policy()]
    assert controller.policies[POLICY_ID] == policy()
    assert len(controller.writes()) == 1
    assert controller.writes()[0][1].endswith("/markDelete")


def test_replacement_removed_then_unexpected_create_error_preserves_accepted_change(
    invoke,
):
    controller = Controller([policy()])
    controller.crash_creates.add("feature_disable")
    result = invoke(
        controller,
        [config("feature_disable", description="feature intent")],
        use_description_as_key=True,
        verbosity=3,
    )

    assert result["failed"] is True
    assert result["changed"] is True
    assert result["before"] == [policy()]
    assert result["after"] == []
    assert controller.policies[POLICY_ID]["markDeleted"] is True
    assert [call[0] for call in controller.writes()] == ["POST", "POST"]


@pytest.mark.parametrize("reject_all", [False, True])
def test_delete_rejection_keeps_unremoved_records_in_after(invoke, reject_all):
    original = [policy(), policy(SECOND_ID, description="second feature")]
    controller = Controller(original)
    controller.reject_deletes.add(SECOND_ID)
    if reject_all:
        controller.reject_deletes.add(POLICY_ID)
    result = invoke(controller, [config(), config(SECOND_ID)], state="deleted", verbosity=3)

    assert result["failed"] is True
    assert result["changed"] is (not reject_all)
    assert result["before"] == original
    assert result["after"] == (original if reject_all else [original[1]])
    assert bool(controller.policies[POLICY_ID].get("markDeleted")) is (not reject_all)
    assert not controller.policies[SECOND_ID].get("markDeleted")
    assert controller.writes()[0][2] == {"policyIds": [POLICY_ID, SECOND_ID]}


def test_replacement_removal_then_deploy_failure_preserves_original_error_and_change(
    invoke,
):
    controller = Controller([policy()])
    controller.reject_switch_deploy = True
    result = invoke(
        controller,
        [config("feature_disable", description="feature intent")],
        use_description_as_key=True,
        deploy=True,
        verbosity=3,
    )

    assert result["failed"] is True
    assert result["changed"] is True
    assert result["msg"] == "simulated rejected switch deployment"
    assert result["before"] == [policy()]
    assert result["after"] == []
    assert controller.policies[POLICY_ID]["markDeleted"] is True
    assert len(controller.writes()) == 2
    assert controller.writes()[0][1].endswith("/markDelete")
    assert controller.writes()[1][1].endswith("/switchActions/deploy")


@pytest.mark.parametrize("check_mode", [False, True])
def test_failed_entry_and_unchanged_deploy_do_not_report_an_accepted_change(invoke, check_mode):
    controller = Controller([policy()])
    result = invoke(controller, [config(), config("POLICY-999")], deploy=True, check_mode=check_mode)

    assert result["failed"] is True
    assert result["changed"] is False
    assert result["before"] == result["after"] == [policy()]
    assert len(controller.writes()) == int(not check_mode)
    assert all("/pushConfig" in path for _verb, path, _payload in controller.writes())


@pytest.mark.parametrize("unexpected", [False, True])
def test_failure_formatter_error_cannot_mask_original_error_or_known_change(invoke, monkeypatch, unexpected):
    controller = Controller([policy(), policy(SECOND_ID, description="second feature")])
    (controller.crash_updates if unexpected else controller.reject_updates).add(SECOND_ID)

    def fail_formatter(*_args, **_kwargs):
        raise RuntimeError("simulated formatter failure")

    monkeypatch.setattr(nd_manage_policy, "_format_module_result", fail_formatter)
    # A caught per-policy rejection normally exits through NDPolicyModule's
    # standard formatter. An unexpected error invokes main's failure formatter.
    # For the caught case, fail the deployment after the accepted first update
    # so both variants reach the public top-level exception path.
    if not unexpected:
        controller.reject_updates.clear()
        controller.reject_switch_deploy = True
        result = invoke(
            controller,
            [config("feature_disable", description="feature intent")],
            use_description_as_key=True,
            deploy=True,
        )
        assert result["msg"] == "simulated rejected switch deployment"
    else:
        result = invoke(controller, [config(priority=600), config(SECOND_ID, priority=650)])
        assert result["msg"] == "RuntimeError: simulated unexpected update failure"

    assert result["failed"] is True
    assert result["changed"] is True
    assert "formatter failure" not in result["msg"]


@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
@pytest.mark.parametrize("verbosity", [0, 2, 3])
@pytest.mark.parametrize("failure", [False, True])
def test_output_level_and_api_diagnostic_gates_are_consistent(invoke, output_level, verbosity, failure):
    controller = Controller([policy(), policy(SECOND_ID, description="second feature")])
    entries = [config(priority=600)]
    if failure:
        controller.crash_updates.add(SECOND_ID)
        entries.append(config(SECOND_ID, priority=650))
    result = invoke(controller, entries, output_level=output_level, verbosity=verbosity)

    assert bool(result.get("failed")) is failure
    assert result["changed"] is True
    assert result["output_level"] == output_level
    assert ("proposed" in result) is (output_level in {"info", "debug"})
    assert ("api_paths" in result) is (verbosity >= 2)
    assert ("api_diff" in result) is (verbosity >= 3)
    if failure:
        assert ("traceback" in result) is (output_level == "debug")
        assert result["msg"] == "RuntimeError: simulated unexpected update failure"
    if output_level in {"info", "debug"}:
        assert len(result["proposed"]) == len(entries)


@pytest.mark.parametrize("input_value", [5, True, "005"])
def test_update_after_preserves_existing_template_value_types(invoke, input_value):
    controller = Controller([policy()])
    result = invoke(controller, [config(template_inputs={"featureName": input_value})])

    assert not result.get("failed"), result
    assert result["changed"] is True
    payload = controller.writes()[0][2]
    assert payload["templateInputs"]["featureName"] == input_value
    assert result["after"][0]["templateInputs"] == payload["templateInputs"]
    assert result["after"][0]["priority"] == payload["priority"] == 725
