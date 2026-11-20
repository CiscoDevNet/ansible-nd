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

from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule, NDModuleError
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


class ControllerSender:
    """Fake only HTTP delivery, leaving request and response handling real."""

    def __init__(self, controller):
        self.controller = controller
        self.path = ""
        self.verb = None
        self.payload = None
        self.response = {}

    def commit(self):
        method = self.verb.value
        data = self.controller.request(method, self.path, self.payload)
        deployment = method == "POST" and urlsplit(self.path).path.endswith("/switchActions/deploy")
        self.response = {
            "RETURN_CODE": 207 if deployment else 200,
            "METHOD": method,
            "REQUEST_PATH": self.path,
            "MESSAGE": "Multi-Status" if deployment else "OK",
            "DATA": data,
        }


@pytest.fixture
def invoke(monkeypatch):
    """Drive actual main() with a reusable stateful controller."""

    class Module:
        def __init__(self, params, check_mode, verbosity):
            self.params = deepcopy(params)
            self.check_mode = check_mode
            self._debug = False
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
                "RETURN_CODE": getattr(self.controller, "delete_return_code", 200) if method == "DELETE" else 200,
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
        cluster_name=None,
        ticket_id=None,
        real_http=False,
    ):
        module = Module(
            {
                "fabric_name": "FABRIC_A",
                "state": state,
                "deploy": deploy,
                "config": entries,
                "use_description_as_key": use_description_as_key,
                "ticket_id": ticket_id,
                "cluster_name": cluster_name,
                "output_level": output_level,
            },
            check_mode,
            verbosity,
        )
        monkeypatch.setattr(nd_manage_policy, "AnsibleModule", lambda **_kwargs: module)
        if real_http:
            nd = NDModule(module)
            rest_send = nd.get_rest_send()
            rest_send.sender = ControllerSender(controller)
            rest_send.unit_test = True
            rest_send.timeout = 1
            monkeypatch.setattr(nd_manage_policy, "NDModule", lambda _module: nd)
        else:
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


def test_update_accepted_but_switch_deploy_rejected_keeps_accepted_after(invoke):
    controller = Controller([policy()])
    controller.reject_switch_deploy = True
    result = invoke(controller, [config(priority=600)], deploy=True, verbosity=3)

    assert result["failed"] is True
    assert result["changed"] is True
    assert result["before"] == [policy()]
    assert result["after"][0]["priority"] == controller.policies[POLICY_ID]["priority"] == 600
    assert result["after"][0]["templateInputs"] == controller.policies[POLICY_ID]["templateInputs"]
    assert [call[0] for call in controller.writes()] == ["PUT", "POST"]
    assert controller.writes()[-1][1].endswith("/switchActions/deploy")


@pytest.mark.parametrize(
    "switch_statuses",
    [
        pytest.param({SWITCH_ID: "failed"}, id="failed-switch"),
        pytest.param({SWITCH_ID: "success", "SERIAL_B": "failed"}, id="mixed-switches"),
        pytest.param({SWITCH_ID: "success", "SERIAL_B": "success"}, id="successful-switches"),
    ],
)
def test_accepted_updates_retain_real_207_switch_deployment_outcomes(invoke, switch_statuses):
    """Real 207 classification preserves accepted PUTs without false deploy success."""

    class Deployment207Controller(Controller):
        def request(self, verb, path, payload=None):
            data = super().request(verb, path, payload)
            if verb == "POST" and urlsplit(path).path.endswith("/switchActions/deploy"):
                for row in data["switchIds"]:
                    row["status"] = switch_statuses[row["switchId"]]
                    row["message"] = "Deployment rejected" if row["status"] == "failed" else "Deployment completed"
            return data

    originals = [policy(pid, switchId=switch) for pid, switch in zip((POLICY_ID, SECOND_ID), switch_statuses)]
    controller = Deployment207Controller(originals)
    entries = [config(row["policyId"], switch=[{"serial_number": row["switchId"]}], priority=600) for row in originals]

    result = invoke(controller, entries, deploy=True, verbosity=3, real_http=True)

    failed_switches = [switch for switch, status in switch_statuses.items() if status == "failed"]
    assert bool(result.get("failed")) is bool(failed_switches)
    assert result["changed"] is True
    assert result["before"] == originals
    after = {row["policyId"]: row for row in result["after"]}
    assert set(after) == set(controller.policies)
    for original in originals:
        policy_id = original["policyId"]
        assert after[policy_id] == controller.policies[policy_id]
        assert after[policy_id]["priority"] == 600
        assert original["priority"] == 725

    writes = controller.writes()
    assert [call[0] for call in writes] == ["PUT"] * len(originals) + ["POST"]
    deploy_path = writes[-1][1]
    assert urlsplit(deploy_path).path.endswith("/switchActions/deploy")
    assert writes[-1][2] == {"switchIds": sorted(switch_statuses)}
    contexts = [
        (response, outcome, diff)
        for path, response, outcome, diff in zip(result["api_paths"], result["api_response"], result["api_result"], result["api_diff"])
        if path == deploy_path
    ]
    assert len(contexts) == 1
    response, outcome, diff = contexts[0]
    assert {key: value for key, value in response.items() if key != "sequence_number"} == {
        "RETURN_CODE": 207,
        "METHOD": "POST",
        "REQUEST_PATH": deploy_path,
        "MESSAGE": "Multi-Status",
        "DATA": {
            "switchIds": [
                {
                    "switchId": switch,
                    "status": switch_statuses[switch],
                    "message": "Deployment rejected" if switch_statuses[switch] == "failed" else "Deployment completed",
                }
                for switch in sorted(switch_statuses)
            ]
        },
    }
    assert outcome["success"] is (not failed_switches)
    assert diff["action"] == ("deploy_failed" if failed_switches else "switch_deploy")
    if failed_switches:
        assert "Deployment rejected" in result["msg"]
        assert all(switch in result["msg"] for switch in failed_switches)
        assert "deploy_success" not in diff
    else:
        assert diff["deploy_success"] is True


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


class TemplateValidationController(Controller):
    """Expose required and typed parameters through the real schema fetch path."""

    def request(self, verb, path, payload=None):
        if verb == "GET" and urlsplit(path).path.endswith("/parameters"):
            self.calls.append((verb, path, deepcopy(payload)))
            return {
                "parameters": [
                    {"name": "featureName", "parameterType": "string", "optional": False},
                    {"name": "EXISTING_REQUIRED", "parameterType": "string", "optional": False},
                    {"name": "RETRIES", "parameterType": "integer", "optional": True},
                ]
            }
        return super().request(verb, path, payload)


@pytest.mark.parametrize("separate_id", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize(
    "invalid_inputs,missing_existing,expected_error",
    [
        ({"BOGUS_TEMPLATE_KEY": "x"}, False, "Unknown templateInput key 'BOGUS_TEMPLATE_KEY'"),
        ({"RETRIES": "not-a-number"}, False, "expects integer"),
        ({"featureName": "lldp"}, True, "Required templateInput 'EXISTING_REQUIRED'"),
    ],
)
def test_policy_id_update_validates_effective_template_inputs(invoke, caplog, separate_id, check_mode, invalid_inputs, missing_existing, expected_error):
    inputs = {"featureName": "lacp", "FABRIC_NAME": "FABRIC_A"}
    if not missing_existing:
        inputs["EXISTING_REQUIRED"] = "retained"
    controller = TemplateValidationController([policy(templateInputs=inputs)])
    original = deepcopy(controller.policies)
    entry = config(template_inputs=invalid_inputs)
    if separate_id:
        entry.update(name="feature_enable", policy_id=POLICY_ID)

    result = invoke(controller, [entry], check_mode=check_mode)

    assert result.get("failed") is True, result
    assert result["changed"] is False
    assert expected_error in caplog.text
    assert controller.writes() == []
    assert controller.policies == original
    assert result["before"] == result["after"]
    assert result["before"][0]["policyId"] == POLICY_ID
    assert [call[1] for call in controller.calls if "/parameters" in call[1]] == ["/api/v1/manage/configTemplates/feature_enable/parameters"]


@pytest.mark.parametrize("separate_id", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("feature_name", ["lacp", "lldp"])
def test_policy_id_validation_preserves_sparse_inputs_and_metadata(invoke, separate_id, check_mode, feature_name):
    inputs = {"featureName": "lacp", "EXISTING_REQUIRED": "retained", "FABRIC_NAME": "FABRIC_A", "POLICY_ID": POLICY_ID}
    controller = TemplateValidationController([policy(templateInputs=inputs)])
    entry = config(template_inputs={"featureName": feature_name})
    if separate_id:
        entry.update(name="feature_enable", policy_id=POLICY_ID)

    result = invoke(controller, [entry], check_mode=check_mode)

    assert not result.get("failed"), result
    assert result["changed"] is (feature_name != "lacp")
    assert len([call for call in controller.calls if "/parameters" in call[1]]) == int(feature_name != "lacp")
    expected_inputs = {**inputs, "featureName": feature_name}
    assert result["after"][0]["templateInputs"] == expected_inputs
    assert result["after"][0]["priority"] == 725
    if check_mode or feature_name == "lacp":
        assert controller.writes() == []
    else:
        assert controller.writes()[0][2]["templateInputs"] == expected_inputs


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("template_inputs", [None, {}])
def test_priority_only_policy_id_update_does_not_fetch_template_schema(invoke, check_mode, template_inputs):
    controller = TemplateValidationController([policy()])
    entry = config(priority=600)
    if template_inputs is not None:
        entry["template_inputs"] = template_inputs

    result = invoke(controller, [entry], check_mode=check_mode)

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert not any("/parameters" in call[1] for call in controller.calls)


@pytest.mark.parametrize("check_mode", [False, True])
def test_policy_id_validation_caches_schema_and_preserves_valid_batch_progress(invoke, caplog, check_mode):
    inputs = {"featureName": "lacp", "EXISTING_REQUIRED": "retained"}
    controller = TemplateValidationController([policy(templateInputs=inputs), policy(SECOND_ID, templateInputs=inputs)])
    original = deepcopy(controller.policies[SECOND_ID])

    result = invoke(
        controller,
        [config(template_inputs={"featureName": "lldp"}), config(SECOND_ID, template_inputs={"BOGUS_TEMPLATE_KEY": "x"})],
        check_mode=check_mode,
    )

    assert result.get("failed") is True
    assert result["changed"] is True
    assert "Unknown templateInput key 'BOGUS_TEMPLATE_KEY'" in caplog.text
    assert len([call for call in controller.calls if "/parameters" in call[1]]) == 1
    assert controller.policies[SECOND_ID] == original
    assert [call[1].rsplit("/", 1)[-1] for call in controller.writes()] == ([] if check_mode else [POLICY_ID])


class MarkDeleteResponseController(Controller):
    """Keep actual accepted effects independent of an injected acknowledgement."""

    def __init__(self, policies, response, *, accepted_ids=(), failed_direct_ids=()):
        super().__init__(policies)
        self.mark_delete_response = response
        self.accepted_ids = set(accepted_ids)
        self.failed_direct_ids = set(failed_direct_ids)
        self.delete_return_code = 204

    def request(self, verb, path, payload=None):
        resource = urlsplit(path).path
        if verb == "POST" and resource.endswith("/markDelete"):
            self.calls.append((verb, path, deepcopy(payload)))
            for pid in self.accepted_ids.intersection(payload["policyIds"]):
                self.policies[pid]["markDeleted"] = True
            return deepcopy(self.mark_delete_response)
        if verb == "DELETE" and resource.rsplit("/", 1)[-1] in self.failed_direct_ids:
            self.calls.append((verb, path, deepcopy(payload)))
            raise NDModuleError(msg="simulated direct deletion rejection", status=400, response_payload={"message": "direct rejection"})
        return super().request(verb, path, payload)


@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("response", [None, [], {}, {"policies": []}, {"policies": None}, {"policies": {}}, {"policies": [None]}])
def test_delete_acknowledgement_rejects_unconfirmed_batch_without_followup(invoke, deploy, response):
    """An unconfirmed request cannot erase snapshots or trigger fallback/deployment."""
    originals = [policy(), policy(SECOND_ID, description="second feature")]
    controller = MarkDeleteResponseController(originals, response)

    result = invoke(controller, [config(), config(SECOND_ID)], state="deleted", deploy=deploy, verbosity=3)

    assert result.get("failed") is True
    assert result["changed"] is False
    assert "unconfirmed" in result["msg"]
    assert result["before"] == result["after"] == originals
    assert controller.policies == {entry["policyId"]: entry for entry in originals}
    assert [call[1].rsplit("/", 1)[-1] for call in controller.writes()] == ["markDelete"]


@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("replacement", [False, True])
@pytest.mark.parametrize("bad_case", ["missing", "missing_id", "foreign", "python_and_missing", "conflicting"])
def test_delete_acknowledgement_preserves_confirmed_progress_and_blocks_replacement(invoke, deploy, replacement, bad_case):
    """Accepted A remains removed; unconfirmed B/C retain their original values."""
    third_id = "POLICY-103"
    originals = [policy(), policy(SECOND_ID, description="second feature"), policy(third_id, description="third feature")]
    rows = [{"policyId": POLICY_ID, "status": "success"}]
    rows.extend(
        {
            "missing": [],
            "missing_id": [{"status": "failed", "message": "content type PYTHON"}],
            "foreign": [{"policyId": "POLICY-FOREIGN", "status": "failed", "message": "content type PYTHON"}],
            "python_and_missing": [{"policyId": SECOND_ID, "status": "failed", "message": "content type PYTHON"}],
            "conflicting": [{"policyId": SECOND_ID, "status": "success"}, {"policyId": SECOND_ID, "status": "failed"}],
        }[bad_case]
    )
    controller = MarkDeleteResponseController(originals, {"policies": rows}, accepted_ids=[POLICY_ID])
    entries = (
        [config("feature_disable", description=entry["description"]) for entry in originals]
        if replacement
        else [config(entry["policyId"]) for entry in originals]
    )

    result = invoke(controller, entries, state="merged" if replacement else "deleted", deploy=deploy, use_description_as_key=replacement, verbosity=3)

    assert result.get("failed") is True
    assert result["changed"] is True
    assert "unconfirmed" in result["msg"]
    assert result["before"] == originals
    assert result["after"] == originals[1:]
    assert controller.policies[POLICY_ID]["markDeleted"] is True
    assert controller.policies[SECOND_ID] == originals[1]
    assert controller.policies[third_id] == originals[2]
    assert [call[1].rsplit("/", 1)[-1] for call in controller.writes()] == ["markDelete"]


@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("acknowledge_requested", [False, True])
def test_delete_acknowledgement_never_deletes_a_foreign_python_failure(invoke, deploy, acknowledge_requested):
    """An unexpected response ID must never become a direct-DELETE target."""
    originals = [policy(), policy(SECOND_ID, description="unrelated policy")]
    rows = [{"policyId": SECOND_ID, "status": "failed", "message": "content type PYTHON"}]
    if acknowledge_requested:
        rows.append({"policyId": POLICY_ID, "status": "success"})
    controller = MarkDeleteResponseController(originals, {"policies": rows}, accepted_ids=[POLICY_ID] if acknowledge_requested else [])

    result = invoke(controller, [config()], state="deleted", deploy=deploy)

    assert result.get("failed") is True
    assert result["changed"] is acknowledge_requested
    assert result["before"] == originals[:1]
    assert result["after"] == ([] if acknowledge_requested else originals[:1])
    assert controller.policies[SECOND_ID] == originals[1]
    assert [call[1].rsplit("/", 1)[-1] for call in controller.writes()] == ["markDelete"]


@pytest.mark.parametrize("deploy", [False, True])
def test_delete_acknowledgement_preserves_explicit_warning_and_consistent_success_echo(invoke, deploy):
    rows = [
        {"policyId": POLICY_ID, "status": " WARNING ", "message": "already in markDeleted state"},
        {"policyId": POLICY_ID, "status": "success"},
    ]
    controller = MarkDeleteResponseController([policy()], {"policies": rows}, accepted_ids=[POLICY_ID])

    result = invoke(controller, [config()], state="deleted", deploy=deploy)

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert result["after"] == []
    assert len(result["warnings_nd"]) == 1
    assert "already in markDeleted state" in result["warnings_nd"][0]
    assert [call[1].rsplit("/", 1)[-1] for call in controller.writes()] == ["markDelete", *(["deploy"] if deploy else [])]


@pytest.mark.parametrize("deploy", [False, True])
def test_delete_acknowledgement_coalesces_valid_python_fallback_and_accepts_empty_204(invoke, deploy):
    rows = [
        {"policyId": POLICY_ID, "status": "success"},
        {"policyId": SECOND_ID, "status": "failed", "message": "content type PYTHON"},
    ]
    controller = MarkDeleteResponseController(
        [policy(), policy(SECOND_ID, description="second feature")], {"policies": [*rows, *rows]}, accepted_ids=[POLICY_ID]
    )

    result = invoke(controller, [config(), config(SECOND_ID)], state="deleted", deploy=deploy, verbosity=3)

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert result["after"] == []
    assert SECOND_ID not in controller.policies
    assert controller.policies[POLICY_ID]["markDeleted"] is True
    assert [call[1].rsplit("/", 1)[-1] for call in controller.writes()] == ["markDelete", SECOND_ID, *(["deploy"] if deploy else [])]


@pytest.mark.parametrize("deploy", [False, True])
def test_delete_acknowledgement_keeps_accepted_sibling_when_python_fallback_fails(invoke, deploy):
    originals = [policy(), policy(SECOND_ID, description="second feature")]
    rows = [
        {"policyId": POLICY_ID, "status": "success"},
        {"policyId": SECOND_ID, "status": "failed", "message": "content type PYTHON"},
    ]
    controller = MarkDeleteResponseController(originals, {"policies": rows}, accepted_ids=[POLICY_ID], failed_direct_ids=[SECOND_ID])

    result = invoke(controller, [config(), config(SECOND_ID)], state="deleted", deploy=deploy)

    assert result.get("failed") is True
    assert result["changed"] is True
    assert result["before"] == originals
    assert result["after"] == originals[1:]
    assert controller.policies[SECOND_ID] == originals[1]
    assert [call[1].rsplit("/", 1)[-1] for call in controller.writes()] == ["markDelete", SECOND_ID, *(["deploy"] if deploy else [])]


@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("replacement", [False, True])
def test_delete_acknowledgement_validation_leaves_check_mode_read_only(invoke, deploy, replacement):
    originals = [policy()]
    controller = MarkDeleteResponseController(originals, {"policies": []})
    entries = [config("feature_disable", description="feature intent")] if replacement else [config()]

    result = invoke(controller, entries, state="merged" if replacement else "deleted", deploy=deploy, check_mode=True, use_description_as_key=replacement)

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert controller.writes() == []
    assert controller.policies == {entry["policyId"]: entry for entry in originals}


# Policy-ID no-ops must not validate a PUT payload that will never be sent.


def _stored_template_inputs_for_validation(kind):
    """Build stored inputs with the selected schema defect, or valid inputs."""
    inputs = {"featureName": "lacp", "EXISTING_REQUIRED": "retained", "FABRIC_NAME": "FABRIC_A", "POLICY_ID": POLICY_ID}
    if kind == "unknown":
        inputs["LEGACY_KEY"] = "controller-value"
    elif kind == "missing_required":
        inputs.pop("EXISTING_REQUIRED")
    elif kind == "invalid_integer":
        inputs["RETRIES"] = "not-a-number"
    return inputs


def _policy_id_entry(pid, separate_id, **overrides):
    """Build either supported policy-ID selector with the desired fields."""
    entry = config(pid, **overrides)
    if separate_id:
        entry.update(name="feature_enable", policy_id=pid)
    return entry


@pytest.mark.parametrize("separate_id", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("stored_kind", ["unknown", "missing_required", "invalid_integer"])
def test_policy_id_noop_ignores_invalid_stored_inputs(invoke, separate_id, check_mode, deploy, stored_kind):
    controller = TemplateValidationController([policy(templateInputs=_stored_template_inputs_for_validation(stored_kind))])
    original = deepcopy(controller.policies)
    entry = _policy_id_entry(POLICY_ID, separate_id, template_inputs={"featureName": "lacp"})
    result = invoke(controller, [entry], check_mode=check_mode, deploy=deploy)
    assert not result.get("failed"), result
    assert result["changed"] is False
    assert result["before"] == result["after"] == list(original.values())
    assert controller.policies == original
    assert not any("/parameters" in call[1] for call in controller.calls)
    assert len(controller.writes()) == int(deploy and not check_mode)
    assert all(verb == "POST" and path.endswith("/pushConfig") for verb, path, _payload in controller.writes())


@pytest.mark.parametrize("separate_id", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("change", ["priority", "input"])
@pytest.mark.parametrize(
    "stored_kind,expected_error",
    [
        ("unknown", "Unknown templateInput key 'LEGACY_KEY'"),
        ("missing_required", "Required templateInput 'EXISTING_REQUIRED'"),
        ("invalid_integer", "expects integer"),
    ],
)
def test_policy_id_update_rejects_invalid_effective_inputs(invoke, caplog, separate_id, check_mode, change, stored_kind, expected_error):
    controller = TemplateValidationController([policy(templateInputs=_stored_template_inputs_for_validation(stored_kind))])
    original = deepcopy(controller.policies)
    desired = {"template_inputs": {"featureName": "lldp" if change == "input" else "lacp"}}
    if change == "priority":
        desired["priority"] = 600
    entry = _policy_id_entry(POLICY_ID, separate_id, **desired)
    result = invoke(controller, [entry], check_mode=check_mode)
    assert result.get("failed") is True
    assert result["changed"] is False
    assert expected_error in caplog.text
    assert controller.writes() == []
    assert controller.policies == original
    assert result["before"] == result["after"] == list(original.values())
    assert len([call for call in controller.calls if "/parameters" in call[1]]) == 1


@pytest.mark.parametrize("separate_id", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("deploy", [False, True])
def test_policy_id_noop_and_valid_update_preserve_progress(invoke, separate_id, check_mode, deploy):
    bad = policy(templateInputs=_stored_template_inputs_for_validation("unknown"))
    good = policy(SECOND_ID, description="second feature", templateInputs={"featureName": "lacp", "EXISTING_REQUIRED": "retained", "FABRIC_NAME": "FABRIC_A"})
    controller = TemplateValidationController([bad, good])
    original = deepcopy(controller.policies)
    result = invoke(
        controller,
        [
            _policy_id_entry(POLICY_ID, separate_id, template_inputs={"featureName": "lacp"}),
            _policy_id_entry(SECOND_ID, separate_id, template_inputs={"featureName": "lldp"}),
        ],
        check_mode=check_mode,
        deploy=deploy,
    )
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert controller.policies[POLICY_ID] == original[POLICY_ID]
    after = {row["policyId"]: row for row in result["after"]}
    assert after[POLICY_ID] == original[POLICY_ID]
    assert after[SECOND_ID]["templateInputs"]["featureName"] == "lldp"
    assert after[SECOND_ID]["templateInputs"]["EXISTING_REQUIRED"] == "retained"
    assert after[SECOND_ID]["priority"] == 725
    assert len([call for call in controller.calls if "/parameters" in call[1]]) == 1
    puts = [call for call in controller.writes() if call[0] == "PUT"]
    pushes = [call for call in controller.writes() if call[1].endswith("/pushConfig")]
    switch_deploys = [call for call in controller.writes() if call[1].endswith("/switchActions/deploy")]
    assert [path.rsplit("/", 1)[-1] for _verb, path, _payload in puts] == ([] if check_mode else [SECOND_ID])
    assert pushes == []
    assert len(switch_deploys) == int(deploy and not check_mode)
    if switch_deploys:
        assert switch_deploys[0][2] == {"switchIds": [SWITCH_ID]}
    if check_mode:
        assert controller.writes() == []
        assert controller.policies == original


@pytest.mark.parametrize("separate_id", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("deploy", [False, True])
def test_policy_id_failed_sibling_preserves_noop_deployment(invoke, separate_id, check_mode, deploy):
    controller = TemplateValidationController([policy(templateInputs=_stored_template_inputs_for_validation("unknown"))])
    original = deepcopy(controller.policies)
    result = invoke(
        controller,
        [_policy_id_entry(POLICY_ID, separate_id, template_inputs={"featureName": "lacp"}), _policy_id_entry("POLICY-999", separate_id)],
        check_mode=check_mode,
        deploy=deploy,
        verbosity=3,
    )
    assert result.get("failed") is True
    assert result["changed"] is False
    assert result["before"] == result["after"] == list(original.values())
    assert controller.policies == original
    assert "POLICY-999" in str(result)
    assert not any("/parameters" in call[1] for call in controller.calls)
    assert len(controller.writes()) == int(deploy and not check_mode)
    assert all(verb == "POST" and path.endswith("/pushConfig") for verb, path, _payload in controller.writes())


@pytest.mark.parametrize("separate_id", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_policy_id_validation_preserves_original_classification_error(invoke, monkeypatch, separate_id, check_mode):
    controller = TemplateValidationController([policy(templateInputs=_stored_template_inputs_for_validation("unknown"))])
    original = deepcopy(controller.policies)
    original_diff = nd_manage_policy.NDPolicyModule._get_diff_merged_single
    sentinel = "original classification rejection"

    def classify_failure(self, want, have_list):
        entry = original_diff(self, want, have_list)
        if entry.get("have"):
            entry.update(action="fail", error_msg=sentinel)
        return entry

    monkeypatch.setattr(nd_manage_policy.NDPolicyModule, "_get_diff_merged_single", classify_failure)
    result = invoke(controller, [_policy_id_entry(POLICY_ID, separate_id, template_inputs={"featureName": "lacp"})], check_mode=check_mode, verbosity=3)
    assert result.get("failed") is True
    assert result["changed"] is False
    assert sentinel in str(result)
    assert not any("/parameters" in call[1] for call in controller.calls)
    assert controller.writes() == []
    assert controller.policies == original


@pytest.mark.parametrize("separate_id", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize(
    "stored_kind,supplied",
    [
        pytest.param("valid", {"NEW_UNKNOWN": ""}, id="unknown-blank-missing"),
        pytest.param("valid", {"NEW_UNKNOWN": "   "}, id="unknown-whitespace-missing"),
        pytest.param("unknown", {"LEGACY_KEY": "controller-value"}, id="unknown-matching-stored"),
        pytest.param("invalid_integer", {"RETRIES": "not-a-number"}, id="invalid-integer-matching-stored"),
    ],
)
def test_policy_id_noop_skips_schema_validation_for_equal_inputs(invoke, separate_id, check_mode, stored_kind, supplied):
    controller = TemplateValidationController([policy(templateInputs=_stored_template_inputs_for_validation(stored_kind))])
    original = deepcopy(controller.policies)
    result = invoke(controller, [_policy_id_entry(POLICY_ID, separate_id, template_inputs=supplied)], check_mode=check_mode)
    assert not result.get("failed"), result
    assert result["changed"] is False
    assert result["before"] == result["after"] == list(original.values())
    assert controller.policies == original
    assert controller.writes() == []
    assert not any("/parameters" in call[1] for call in controller.calls)


@pytest.mark.parametrize("separate_id", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_policy_id_noop_deployment_failure_preserves_unchanged_state(invoke, separate_id, check_mode):
    controller = TemplateValidationController([policy(templateInputs=_stored_template_inputs_for_validation("unknown"))])
    controller.reject_push.add(POLICY_ID)
    original = deepcopy(controller.policies)
    result = invoke(controller, [_policy_id_entry(POLICY_ID, separate_id, template_inputs={"featureName": "lacp"})], check_mode=check_mode, deploy=True)
    assert bool(result.get("failed")) is (not check_mode)
    assert result["changed"] is False
    assert result["before"] == result["after"] == list(original.values())
    assert controller.policies == original
    assert not any("/parameters" in call[1] for call in controller.calls)
    assert len(controller.writes()) == int(not check_mode)
    assert all(verb == "POST" and path.endswith("/pushConfig") for verb, path, _payload in controller.writes())


# Merged deployment routing reuses the initial raw inventory.


_UNSET = object()


class RoutingController(Controller):
    """Expose inventory and deployment variants at the existing HTTP boundary."""

    def __init__(self, policies=None):
        super().__init__(policies)
        self.inventory_response = _UNSET
        self.inventory_error = None
        self.switch_response = _UNSET
        self.push_transport_error = False

    def request(self, verb, path, payload=None):
        resource = urlsplit(path).path
        if verb == "GET" and resource.endswith("/policies") and self.inventory_error is not None:
            self.calls.append((verb, path, deepcopy(payload)))
            raise self.inventory_error
        if verb == "GET" and resource.endswith("/policies") and self.inventory_response is not _UNSET:
            self.calls.append((verb, path, deepcopy(payload)))
            return deepcopy(self.inventory_response)
        if verb == "POST" and resource.endswith("/pushConfig") and self.push_transport_error:
            self.calls.append((verb, path, deepcopy(payload)))
            raise NDModuleError(msg="simulated push transport failure", status=502, response_payload={"message": "push transport rejected"})
        if verb == "POST" and resource.endswith("/switchActions/deploy") and self.switch_response is not _UNSET:
            self.calls.append((verb, path, deepcopy(payload)))
            return deepcopy(self.switch_response)
        return super().request(verb, path, payload)


def pending_policy(pid="POLICY-901", owner=None, **overrides):
    """Return a standalone staged deletion or a removal clone of its owner."""
    inputs = {"featureName": "bfd"}
    if owner is not None:
        inputs["ORIG_POLICY_ID"] = owner
    return policy(pid, markDeleted=True, priority=-725, templateInputs=inputs, **overrides)


def deployment_calls(controller, suffix):
    """Select actual requests to one deployment endpoint."""
    return [call for call in controller.writes() if urlsplit(call[1]).path.endswith(suffix)]


def assert_one_initial_policy_read(controller):
    """Deployment routing must not add a refresh or a policy-specific GET."""
    reads = [call for call in controller.calls if call[0] == "GET" and "/policies" in urlsplit(call[1]).path]
    assert len(reads) == 1
    assert urlsplit(reads[0][1]).path.endswith("/policies")
    assert controller.calls.index(reads[0]) < min(
        (i for i, call in enumerate(controller.calls) if call[0] != "GET"),
        default=len(controller.calls),
    )


@pytest.mark.parametrize("separate_id", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("change", ["priority", "description", "inputs"])
def test_accepted_update_switch_deploys_without_pending_record_or_refresh(invoke, separate_id, check_mode, deploy, change):
    controller = RoutingController([policy()])
    original = deepcopy(controller.policies)
    desired = {
        "priority": {"priority": 600},
        "description": {"description": "renamed"},
        "inputs": {"template_inputs": {"featureName": "lldp"}},
    }[change]
    result = invoke(controller, [_policy_id_entry(POLICY_ID, separate_id, **desired)], deploy=deploy, check_mode=check_mode)

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert result["before"] == list(original.values())
    assert result["after"][0]["policyId"] == POLICY_ID
    assert result["after"][0]["priority"] == (600 if change == "priority" else 725)
    assert result["after"][0]["description"] == ("renamed" if change == "description" else "feature intent")
    assert result["after"][0]["templateInputs"]["featureName"] == ("lldp" if change == "inputs" else "lacp")
    assert deployment_calls(controller, "/pushConfig") == []
    switches = deployment_calls(controller, "/switchActions/deploy")
    assert len(switches) == int(deploy and not check_mode)
    if switches:
        assert switches[0][2] == {"switchIds": [SWITCH_ID]}
    assert_one_initial_policy_read(controller)
    if check_mode:
        assert controller.writes() == []
        assert controller.policies == original


@pytest.mark.parametrize("separate_id", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("has_pending", [False, True])
def test_noop_routes_only_from_initial_pending_owner_and_preserves_snapshots(invoke, separate_id, check_mode, deploy, has_pending):
    original = policy()
    rows = [original]
    if has_pending:
        rows.append(pending_policy(owner=POLICY_ID, description="old description"))
    controller = RoutingController(rows)
    result = invoke(controller, [_policy_id_entry(POLICY_ID, separate_id)], deploy=deploy, check_mode=check_mode)

    assert not result.get("failed"), result
    assert result["changed"] is False
    assert result["before"] == result["after"] == [original]
    assert all(call[0] != "PUT" for call in controller.writes())
    expected = int(deploy and not check_mode)
    switches = deployment_calls(controller, "/switchActions/deploy")
    pushes = deployment_calls(controller, "/pushConfig")
    assert len(switches) == (expected if has_pending else 0)
    assert len(pushes) == (0 if has_pending else expected)
    if switches:
        assert switches[0][2] == {"switchIds": [SWITCH_ID]}
    if pushes:
        assert pushes[0][2] == {"policyIds": [POLICY_ID]}
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("separate_id", [False, True])
@pytest.mark.parametrize("unrelated", ["owner", "switch", "active", "description_only", "group_child"])
def test_noop_does_not_inherit_unrelated_pending_deletions(invoke, separate_id, unrelated):
    row = pending_policy(owner=POLICY_ID)
    if unrelated == "owner":
        row["templateInputs"]["ORIG_POLICY_ID"] = SECOND_ID
    elif unrelated == "switch":
        row["switchId"] = "SERIAL_B"
    elif unrelated == "active":
        row["markDeleted"] = False
    elif unrelated == "description_only":
        row["templateInputs"].pop("ORIG_POLICY_ID")
    else:
        row.update(source="POLICY-GROUP-999")
        row["templateInputs"]["ORIG_POLICY_ID"] = "POLICY-GROUP-999"
    controller = RoutingController([policy(), row])
    result = invoke(controller, [_policy_id_entry(POLICY_ID, separate_id)], deploy=True)

    assert not result.get("failed"), result
    assert result["changed"] is False
    assert result["before"] == result["after"] == [policy()]
    assert deployment_calls(controller, "/switchActions/deploy") == []
    assert deployment_calls(controller, "/pushConfig")[0][2] == {"policyIds": [POLICY_ID]}
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("separate_id", [False, True])
def test_pending_noop_uses_resolved_owner_instead_of_caller_switch(invoke, separate_id):
    controller = RoutingController([policy(), pending_policy(owner=POLICY_ID)])
    entry = _policy_id_entry(POLICY_ID, separate_id, switch=[{"serial_number": "SERIAL_B"}])
    result = invoke(controller, [entry], deploy=True)

    assert not result.get("failed"), result
    assert result["changed"] is False
    assert result["after"] == [policy()]
    assert deployment_calls(controller, "/switchActions/deploy")[0][2] == {"switchIds": [SWITCH_ID]}
    assert deployment_calls(controller, "/pushConfig") == []
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("use_description_as_key", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("deploy", [False, True])
@pytest.mark.parametrize("old_shape", ["root", "two_clones"])
def test_unique_recreation_deploys_old_removal_and_new_policy_together(invoke, use_description_as_key, check_mode, deploy, old_shape):
    old = [pending_policy()]
    if old_shape == "two_clones":
        old = [pending_policy("POLICY-902", owner="POLICY-900"), pending_policy("POLICY-903", owner="POLICY-900")]
    controller = RoutingController(old)
    original = deepcopy(controller.policies)
    result = invoke(
        controller,
        [config("feature_enable", description="feature intent", priority=600, template_inputs={"featureName": "lldp"})],
        use_description_as_key=use_description_as_key,
        check_mode=check_mode,
        deploy=deploy,
    )

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert result["before"] == []
    assert len(result["after"]) == 1
    assert result["after"][0]["templateInputs"]["featureName"] == "lldp"
    assert result["after"][0]["priority"] == 600
    assert all(row.get("policyId") not in {"POLICY-901", "POLICY-902", "POLICY-903"} for row in result["after"])
    assert deployment_calls(controller, "/pushConfig") == []
    switches = deployment_calls(controller, "/switchActions/deploy")
    assert len(switches) == int(deploy and not check_mode)
    if switches:
        assert switches[0][2] == {"switchIds": [SWITCH_ID]}
    assert_one_initial_policy_read(controller)
    if check_mode:
        assert controller.writes() == []
        assert controller.policies == original
        assert "policyId" not in result["after"][0]


@pytest.mark.parametrize(
    "mismatch",
    ["switch", "template", "missing_description", "empty_description", "internal", "active_owner_renamed", "active_owner_other_template", "multiple_owners"],
)
def test_nonunique_or_unrelated_creation_keeps_policy_push(invoke, mismatch):
    row = pending_policy()
    rows = [row]
    entry = config("feature_enable", description="feature intent", template_inputs={"featureName": "lldp"})
    if mismatch == "switch":
        row["switchId"] = "SERIAL_B"
    elif mismatch == "template":
        row["templateName"] = "feature_disable"
    elif mismatch == "missing_description":
        entry.pop("description")
    elif mismatch == "empty_description":
        entry["description"] = row["description"] = ""
    elif mismatch == "internal":
        row["source"] = "POLICY-GROUP-900"
    elif mismatch.startswith("active_owner"):
        row["templateInputs"]["ORIG_POLICY_ID"] = POLICY_ID
        active = policy(description="renamed")
        if mismatch == "active_owner_other_template":
            active["templateName"] = "feature_disable"
        rows.append(active)
    else:
        rows.append(pending_policy("POLICY-902"))
    controller = RoutingController(rows)
    result = invoke(controller, [entry], deploy=True)

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert deployment_calls(controller, "/switchActions/deploy") == []
    assert deployment_calls(controller, "/pushConfig")[0][2] == {"policyIds": ["POLICY-200"]}
    assert_one_initial_policy_read(controller)
    if mismatch == "multiple_owners":
        assert result.get("warnings_nd"), result


@pytest.mark.parametrize("active_count", [1, 2])
@pytest.mark.parametrize("additional", [None, False, True])
def test_creation_beside_active_matches_never_inherits_their_pending_identity(invoke, active_count, additional):
    active = [policy()]
    if active_count == 2:
        active.append(policy(SECOND_ID))
    rows = [*active, pending_policy(owner=POLICY_ID)]
    controller = RoutingController(rows)
    entry = config("feature_enable", description="feature intent", template_inputs={"featureName": "lldp"})
    if additional is not None:
        entry["create_additional_policy"] = additional
    result = invoke(controller, [entry], deploy=True)

    assert not result.get("failed"), result
    assert_one_initial_policy_read(controller)
    assert deployment_calls(controller, "/switchActions/deploy") == []
    if active_count == 2 and additional is False:
        assert result["changed"] is False
        assert controller.writes() == []
    else:
        assert result["changed"] is True
        assert deployment_calls(controller, "/pushConfig")[0][2] == {"policyIds": ["POLICY-200"]}


@pytest.mark.parametrize("separate_id", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_missing_active_id_remains_failure_even_when_marked_record_exists(invoke, separate_id, check_mode):
    controller = RoutingController([pending_policy(POLICY_ID)])
    result = invoke(controller, [_policy_id_entry(POLICY_ID, separate_id)], deploy=True, check_mode=check_mode)

    assert result["failed"] is True
    assert result["changed"] is False
    assert result["before"] == result["after"] == []
    assert controller.writes() == []
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("same_switch", [False, True])
@pytest.mark.parametrize("reject_update", [False, True])
def test_mixed_create_update_batches_only_accepted_switch_owners(invoke, same_switch, reject_update):
    controller = RoutingController([policy()])
    if reject_update:
        controller.reject_updates.add(POLICY_ID)
    created_switch = SWITCH_ID if same_switch else "SERIAL_B"
    result = invoke(
        controller,
        [
            config(priority=600),
            config("feature_disable", description="new feature", switch=[{"serial_number": created_switch}]),
        ],
        deploy=True,
        verbosity=3,
    )

    assert bool(result.get("failed")) is reject_update
    assert result["changed"] is True
    after = {row["policyId"]: row for row in result["after"]}
    assert after[POLICY_ID]["priority"] == (725 if reject_update else 600)
    assert after["POLICY-200"]["switchId"] == created_switch
    switches = deployment_calls(controller, "/switchActions/deploy")
    pushes = deployment_calls(controller, "/pushConfig")
    assert len(switches) == int(not reject_update)
    if switches:
        assert switches[0][2] == {"switchIds": [SWITCH_ID]}
    assert len(pushes) == int(reject_update or not same_switch)
    if pushes:
        assert pushes[0][2] == {"policyIds": ["POLICY-200"]}
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("reject_switch", [False, True])
@pytest.mark.parametrize("reject_push", [False, True])
@pytest.mark.parametrize("push_transport", [False, True])
def test_independent_deploy_batches_preserve_each_error_context_and_accepted_state(invoke, reject_switch, reject_push, push_transport):
    controller = RoutingController([policy()])
    controller.reject_switch_deploy = reject_switch
    if reject_push:
        if push_transport:
            controller.push_transport_error = True
        else:
            controller.reject_push.add("POLICY-200")
    result = invoke(
        controller,
        [config(priority=600), config("feature_disable", description="new feature", switch=[{"serial_number": "SERIAL_B"}])],
        deploy=True,
        verbosity=3,
    )

    assert bool(result.get("failed")) is (reject_switch or reject_push)
    assert result["changed"] is True
    after = {row["policyId"]: row for row in result["after"]}
    assert after[POLICY_ID]["priority"] == 600
    assert after["POLICY-200"]["switchId"] == "SERIAL_B"
    assert len(deployment_calls(controller, "/switchActions/deploy")) == 1
    assert len(deployment_calls(controller, "/pushConfig")) == 1
    contexts = list(zip(result["api_paths"], result["api_response"]))
    switch_responses = [response for path, response in contexts if "/switchActions/deploy" in str(path)]
    push_responses = [response for path, response in contexts if "/pushConfig" in str(path)]
    if reject_switch:
        assert "deploy rejected" in str(switch_responses)
        assert "push transport rejected" not in str(switch_responses)
        assert "push rejected" not in str(switch_responses)
    if reject_push:
        assert ("push transport rejected" if push_transport else "push rejected") in str(push_responses)
        assert "deploy rejected" not in str(push_responses)
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("check_mode", [False, True])
def test_pending_noop_switch_deploy_failure_keeps_unchanged_state(invoke, check_mode):
    controller = RoutingController([policy(), pending_policy(owner=POLICY_ID)])
    controller.reject_switch_deploy = True
    result = invoke(controller, [config()], deploy=True, check_mode=check_mode, verbosity=3)

    assert bool(result.get("failed")) is (not check_mode)
    assert result["changed"] is False
    assert result["before"] == result["after"] == [policy()]
    assert deployment_calls(controller, "/pushConfig") == []
    assert len(deployment_calls(controller, "/switchActions/deploy")) == int(not check_mode)
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("response", [{}, {"status": "Configuration deployment completed"}, None])
@pytest.mark.parametrize("noop", [False, True])
def test_switch_routing_preserves_existing_aggregate_and_empty_success_responses(invoke, response, noop):
    rows = [policy(), pending_policy(owner=POLICY_ID)] if noop else [policy()]
    controller = RoutingController(rows)
    controller.switch_response = response
    result = invoke(controller, [config() if noop else config(priority=600)], deploy=True)

    assert not result.get("failed"), result
    assert result["changed"] is (not noop)
    if noop:
        assert result["before"] == result["after"] == [policy()]
    else:
        assert result["after"][0]["priority"] == 600
    assert len(deployment_calls(controller, "/switchActions/deploy")) == 1
    assert deployment_calls(controller, "/pushConfig") == []
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("same_switch", [False, True])
def test_replacement_precreate_deploy_does_not_cover_the_new_replacement(invoke, same_switch):
    update_switch = SWITCH_ID if same_switch else "SERIAL_B"
    second = policy(SECOND_ID, switchId=update_switch, description="second feature")
    controller = RoutingController([policy(), second])
    result = invoke(
        controller,
        [
            config("feature_disable", description="feature intent"),
            config(SECOND_ID, priority=600, switch=[{"serial_number": update_switch}]),
        ],
        deploy=True,
        use_description_as_key=True,
    )

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert {row["policyId"] for row in result["after"]} == {SECOND_ID, "POLICY-200"}
    writes = controller.writes()
    mark_index = next(i for i, call in enumerate(writes) if urlsplit(call[1]).path.endswith("/markDelete"))
    switch_indexes = [i for i, call in enumerate(writes) if urlsplit(call[1]).path.endswith("/switchActions/deploy")]
    create_index = next(i for i, call in enumerate(writes) if call[0] == "POST" and urlsplit(call[1]).path.endswith("/policies"))
    assert len(switch_indexes) == 2
    assert mark_index < switch_indexes[0] < create_index < switch_indexes[1]
    assert writes[switch_indexes[0]][2] == {"switchIds": [SWITCH_ID]}
    assert writes[switch_indexes[1]][2] == {"switchIds": [update_switch]}
    pushes = deployment_calls(controller, "/pushConfig")
    assert len(pushes) == int(not same_switch)
    if pushes:
        assert pushes[0][2] == {"policyIds": ["POLICY-200"]}
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize(
    "counts",
    [
        {"remaining": 1, "total": 2},
        {"remaining": 0, "total": 2},
    ],
)
@pytest.mark.parametrize("check_mode", [False, True])
def test_known_incomplete_inventory_cannot_decide_noop_absence(invoke, counts, check_mode):
    controller = RoutingController([policy()])
    controller.inventory_response = {"policies": [policy()], "meta": {"counts": counts}}
    result = invoke(controller, [config()], deploy=True, check_mode=check_mode, verbosity=3)

    assert result.get("failed") is True
    assert result["changed"] is False
    assert result["before"] == result["after"] == [policy()]
    assert result["api_result"] and all(row.get("success") is False for row in result["api_result"])
    assert controller.writes() == []
    assert controller.policies == {POLICY_ID: policy()}
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("response", [None, {}, {"policies": [], "meta": {"counts": {"remaining": 1, "total": 1}}}])
def test_untrusted_initial_inventory_cannot_establish_unique_recreation(invoke, response):
    controller = RoutingController()
    controller.inventory_response = response
    result = invoke(controller, [config("feature_enable", description="recreation")], deploy=True)

    assert result.get("failed") is True
    assert result["changed"] is False
    assert controller.writes() == []
    assert controller.policies == {}
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("deploy", [False, True])
def test_accepted_update_does_not_need_complete_pending_discovery(invoke, deploy):
    controller = RoutingController([policy()])
    controller.inventory_response = {"policies": [policy()], "meta": {"counts": {"remaining": 5, "total": 6}}}
    result = invoke(controller, [config(priority=600)], deploy=deploy)

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert result["after"][0]["priority"] == 600
    assert len(deployment_calls(controller, "/switchActions/deploy")) == int(deploy)
    assert deployment_calls(controller, "/pushConfig") == []
    assert_one_initial_policy_read(controller)


def test_many_accepted_updates_use_one_initial_read_and_one_switch_deployment(invoke):
    originals = [policy(f"POLICY-{1000 + i}", description=f"feature {i}") for i in range(50)]
    controller = RoutingController(originals)
    result = invoke(controller, [config(row["policyId"], priority=600) for row in originals], deploy=True)

    assert not result.get("failed"), result
    assert result["changed"] is True
    assert len(result["before"]) == len(result["after"]) == 50
    assert {row["policyId"] for row in result["after"]} == {row["policyId"] for row in originals}
    assert all(row["priority"] == 600 for row in result["after"])
    assert len([call for call in controller.writes() if call[0] == "PUT"]) == 50
    assert len(deployment_calls(controller, "/switchActions/deploy")) == 1
    assert deployment_calls(controller, "/pushConfig") == []
    assert_one_initial_policy_read(controller)
    assert len([call for call in controller.calls if call[0] == "GET"]) == 1


def test_routed_update_preserves_cluster_and_ticket_scope(invoke):
    controller = RoutingController([policy()])
    result = invoke(controller, [config(priority=600)], deploy=True, cluster_name="CLUSTER_A", ticket_id="CHG-1")

    assert not result.get("failed"), result
    puts = [call for call in controller.writes() if call[0] == "PUT"]
    switches = deployment_calls(controller, "/switchActions/deploy")
    assert len(puts) == len(switches) == 1
    assert "CLUSTER_A" in puts[0][1]
    assert "CHG-1" in puts[0][1]
    assert "CLUSTER_A" in switches[0][1]
    assert "CHG-1" not in switches[0][1]
    assert_one_initial_policy_read(controller)


def test_retained_pending_inventory_does_not_leak_into_gathered_results(invoke):
    controller = RoutingController([policy(), pending_policy(owner=POLICY_ID), policy("POLICY-950", source="POLICY-GROUP-900")])
    result = invoke(controller, [config("feature_enable")], state="gathered")

    assert not result.get("failed"), result
    assert result["changed"] is False
    assert [row["policy_id"] for row in result["gathered"]] == [POLICY_ID]
    assert controller.writes() == []
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("source", ["", POLICY_ID, "POLICY-999", "POLICY-GROUP-999"])
def test_pending_source_must_not_contradict_original_owner(invoke, source):
    controller = RoutingController([policy(), pending_policy(owner=POLICY_ID, source=source)])
    result = invoke(controller, [config()], deploy=True)

    assert not result.get("failed"), result
    assert result["changed"] is False
    related = source in {"", POLICY_ID}
    assert len(deployment_calls(controller, "/switchActions/deploy")) == int(related)
    assert len(deployment_calls(controller, "/pushConfig")) == int(not related)
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("followup", ["identical", "priority", "description"])
def test_staged_input_update_is_recovered_by_a_later_merged_task(invoke, followup):
    class PendingOnUpdateController(RoutingController):
        """Persist a linked old-config clone when an input update is accepted."""

        def request(self, verb, path, payload=None):
            resource = urlsplit(path).path
            if verb != "PUT" or "/policies/" not in resource:
                return super().request(verb, path, payload)
            pid = resource.rsplit("/", 1)[-1]
            before = deepcopy(self.policies[pid])
            data = super().request(verb, path, payload)
            if before["templateInputs"] != payload["templateInputs"]:
                self.policies["POLICY-901"] = {
                    **before,
                    "policyId": "POLICY-901",
                    "markDeleted": True,
                    "templateInputs": {**before["templateInputs"], "ORIG_POLICY_ID": pid},
                }
            return data

    controller = PendingOnUpdateController([policy()])
    staged = invoke(controller, [config(template_inputs={"featureName": "lldp"})], deploy=False)
    assert not staged.get("failed"), staged
    assert staged["changed"] is True
    assert len(controller.writes()) == 1
    assert controller.writes()[0][0] == "PUT"
    assert controller.policies["POLICY-901"]["templateInputs"]["ORIG_POLICY_ID"] == POLICY_ID
    assert_one_initial_policy_read(controller)
    controller.calls.clear()

    desired = {
        "identical": {"template_inputs": {"featureName": "lldp"}},
        "priority": {"priority": 600},
        "description": {"description": "renamed"},
    }[followup]
    result = invoke(controller, [config(**desired)], deploy=True)
    assert not result.get("failed"), result
    assert result["changed"] is (followup != "identical")
    assert result["after"][0]["templateInputs"]["featureName"] == "lldp"
    assert len([call for call in controller.writes() if call[0] == "PUT"]) == int(followup != "identical")
    assert len(deployment_calls(controller, "/switchActions/deploy")) == 1
    assert deployment_calls(controller, "/pushConfig") == []
    assert_one_initial_policy_read(controller)
    if followup == "identical":
        assert result["after"] == result["before"]


@pytest.mark.parametrize("check_mode", [False, True])
def test_invalid_sibling_does_not_mark_pending_noop_deployment_changed(invoke, check_mode):
    controller = RoutingController([policy(), pending_policy(owner=POLICY_ID)])
    result = invoke(controller, [config(), config("POLICY-999")], deploy=True, check_mode=check_mode)

    assert result["failed"] is True
    assert result["changed"] is False
    assert result["before"] == result["after"] == [policy()]
    assert len(deployment_calls(controller, "/switchActions/deploy")) == int(not check_mode)
    assert deployment_calls(controller, "/pushConfig") == []
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("verbosity", [0, 2, 3])
@pytest.mark.parametrize("noop", [False, True])
def test_switch_deployment_preserves_api_diagnostic_gates(invoke, verbosity, noop):
    controller = RoutingController([policy(), pending_policy(owner=POLICY_ID)] if noop else [policy()])
    result = invoke(controller, [config() if noop else config(priority=600)], deploy=True, verbosity=verbosity, output_level="info")

    assert not result.get("failed"), result
    assert result["changed"] is (not noop)
    assert ("api_paths" in result) is (verbosity >= 2)
    assert ("api_diff" in result) is (verbosity >= 3)
    assert "proposed" in result
    if verbosity >= 2:
        assert any("/switchActions/deploy" in path for path in result["api_paths"])
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize(
    "meta",
    [
        None,
        [],
        "unexpected metadata",
        {"counts": None},
        {"counts": []},
        {"counts": "unexpected counts"},
        {"counts": {"remaining": "unknown", "total": 1}},
        {"counts": {"remaining": 0, "total": "unknown"}},
    ],
)
def test_malformed_present_metadata_cannot_establish_absence(invoke, meta):
    controller = RoutingController([policy()])
    controller.inventory_response = {"policies": [policy()], "meta": meta}
    result = invoke(controller, [config()], deploy=True, verbosity=3)

    assert result.get("failed") is True
    assert result["changed"] is False
    assert result["before"] == result["after"] == [policy()]
    assert result["api_result"] and all(row.get("success") is False for row in result["api_result"])
    assert controller.writes() == []
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("include_empty_counts", [False, True])
def test_at_limit_inventory_needs_completion_evidence_without_extra_get(invoke, include_empty_counts):
    controller = RoutingController([policy()])
    rows = [policy(f"POLICY-{i + 1}") for i in range(10000)]
    controller.inventory_response = {"policies": rows}
    if include_empty_counts:
        controller.inventory_response["meta"] = {"counts": {}}
    result = invoke(controller, [config()], deploy=True, verbosity=3)

    assert result.get("failed") is True
    assert result["changed"] is False
    assert result["before"] == result["after"] == [policy()]
    assert result["api_result"] and all(row.get("success") is False for row in result["api_result"])
    assert controller.writes() == []
    assert_one_initial_policy_read(controller)


def test_positive_pending_owner_match_does_not_require_negative_discovery_proof(invoke):
    controller = RoutingController([policy(), pending_policy(owner=POLICY_ID)])
    controller.inventory_response = {
        "policies": list(controller.policies.values()),
        "meta": {"counts": {"remaining": 2, "total": 4}},
    }
    result = invoke(controller, [config()], deploy=True)

    assert not result.get("failed"), result
    assert result["changed"] is False
    assert result["before"] == result["after"] == [policy()]
    assert len(deployment_calls(controller, "/switchActions/deploy")) == 1
    assert deployment_calls(controller, "/pushConfig") == []
    assert_one_initial_policy_read(controller)


def test_mixed_stale_noop_and_new_create_report_batch_local_changes(invoke):
    controller = RoutingController([policy(), pending_policy(owner=POLICY_ID)])
    result = invoke(
        controller,
        [config(), config("feature_disable", description="new feature", switch=[{"serial_number": "SERIAL_B"}])],
        deploy=True,
        verbosity=3,
    )

    assert not result.get("failed"), result
    assert result["changed"] is True
    after = {row["policyId"]: row for row in result["after"]}
    assert after[POLICY_ID] == policy()
    assert after["POLICY-200"]["switchId"] == "SERIAL_B"
    deployment_results = [
        (path, api_result)
        for path, api_result in zip(result["api_paths"], result["api_result"])
        if "/switchActions/deploy" in str(path) or "/pushConfig" in str(path)
    ]
    switch_results = [api_result for path, api_result in deployment_results if "/switchActions/deploy" in path]
    push_results = [api_result for path, api_result in deployment_results if "/pushConfig" in path]
    assert len(switch_results) == len(push_results) == 1
    assert switch_results[0]["changed"] is False
    assert push_results[0]["changed"] is True
    assert_one_initial_policy_read(controller)


def test_failed_initial_inventory_is_not_reported_as_a_successful_api_result(invoke):
    controller = RoutingController([policy()])
    controller.inventory_error = NDModuleError(
        msg="simulated policy inventory failure",
        status=503,
        response_payload={"message": "inventory rejected"},
    )
    result = invoke(controller, [config()], deploy=True, verbosity=3)

    assert result.get("failed") is True
    assert result["changed"] is False
    assert result["before"] == result["after"] == []
    assert "simulated policy inventory failure" in str(result)
    assert "inventory rejected" in str(result["api_response"])
    assert result["api_result"] and all(row.get("success") is False for row in result["api_result"])
    assert controller.writes() == []
    assert_one_initial_policy_read(controller)


class DeploymentExceptionController(RoutingController):
    """Raise distinct deployment errors while retaining real request context."""

    def __init__(self, policies=None, *, errors):
        super().__init__(policies)
        self.error_statuses = errors
        self.deployment_errors = {}

    def request(self, verb, path, payload=None):
        resource = urlsplit(path).path
        kind = None
        if verb == "POST" and resource.endswith("/switchActions/deploy"):
            kind = "switch"
        elif verb == "POST" and resource.endswith("/pushConfig"):
            kind = "policy"
        if kind in self.error_statuses:
            self.calls.append((verb, path, deepcopy(payload)))
            error = NDModuleError(
                msg=f"original {kind} deployment transport error",
                status=self.error_statuses[kind],
                request_payload=deepcopy(payload),
                response_payload={"message": f"{kind} endpoint unavailable", "endpoint": kind},
                raw=f"raw {kind} endpoint response",
            )
            self.deployment_errors[kind] = error
            raise error
        return super().request(verb, path, payload)


@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
@pytest.mark.parametrize("status", [502, None])
@pytest.mark.parametrize("operation", ["create", "update", "noop"])
def test_deployment_exception_preserves_original_failure_contract(invoke, output_level, status, operation):
    """Local batch handling retains the previous top-level NDModuleError output."""
    kind = "policy" if operation == "create" else "switch"
    originals = [] if operation == "create" else [policy()]
    if operation == "noop":
        originals.append(pending_policy(owner=POLICY_ID))
    controller = DeploymentExceptionController(originals, errors={kind: status})
    entry = {
        "create": config("feature_disable", description="new policy"),
        "update": config(priority=600),
        "noop": config(),
    }[operation]
    result = invoke(controller, [entry], deploy=True, output_level=output_level, verbosity=3)

    assert result["failed"] is True
    assert result["msg"] == f"original {kind} deployment transport error"
    assert result["changed"] is (operation != "noop")
    assert ("error_details" in result) is (output_level == "debug")
    if output_level == "debug":
        assert result["error_details"] == controller.deployment_errors[kind].to_dict()
    if operation == "create":
        assert result["before"] == []
        assert [row["policyId"] for row in result["after"]] == ["POLICY-200"]
        assert result["after"][0] == controller.policies["POLICY-200"]
    elif operation == "update":
        assert result["before"] == [policy()]
        assert result["after"][0]["policyId"] == POLICY_ID
        assert result["after"][0]["priority"] == 600
        assert controller.policies[POLICY_ID]["priority"] == 600
    else:
        assert result["before"] == result["after"] == [policy()]

    suffix = "/pushConfig" if kind == "policy" else "/switchActions/deploy"
    requests = deployment_calls(controller, suffix)
    assert len(requests) == 1
    contexts = [(path, response) for path, response in zip(result["api_paths"], result["api_response"]) if suffix in str(path)]
    assert len(contexts) == 1
    path, response = contexts[0]
    assert path == requests[0][1]
    assert response["METHOD"] == requests[0][0] == "POST"
    assert response["REQUEST_PATH"] == requests[0][1]
    assert response["RETURN_CODE"] == status
    assert response["MESSAGE"] == result["msg"]
    assert response["DATA"] == controller.deployment_errors[kind].response_payload
    assert_one_initial_policy_read(controller)


@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
@pytest.mark.parametrize(
    "errors",
    [
        pytest.param({"switch": 502}, id="switch-502-policy-success"),
        pytest.param({"switch": None}, id="switch-no-status-policy-success"),
        pytest.param({"policy": 502}, id="switch-success-policy-502"),
        pytest.param({"policy": None}, id="switch-success-policy-no-status"),
        pytest.param({"switch": 502, "policy": 502}, id="both-502"),
        pytest.param({"switch": None, "policy": None}, id="both-no-status"),
        pytest.param({"switch": None, "policy": 502}, id="first-no-status-second-502"),
        pytest.param({"switch": 502, "policy": None}, id="first-502-second-no-status"),
    ],
)
def test_mixed_deployment_exceptions_keep_first_error_and_each_response(invoke, output_level, errors):
    """Later success or failure cannot replace an earlier failed batch's context."""
    controller = DeploymentExceptionController([policy()], errors=errors)
    result = invoke(
        controller,
        [config(priority=600), config("feature_disable", description="new feature", switch=[{"serial_number": "SERIAL_B"}])],
        deploy=True,
        verbosity=3,
        output_level=output_level,
    )

    first_kind = "switch" if "switch" in errors else "policy"
    first_error = controller.deployment_errors[first_kind]
    assert result["failed"] is True
    assert result["msg"] == first_error.msg
    assert result["changed"] is True
    assert ("error_details" in result) is (output_level == "debug")
    if output_level == "debug":
        assert result["error_details"] == first_error.to_dict()
    assert result["before"] == [policy()]
    after = {row["policyId"]: row for row in result["after"]}
    assert set(after) == {POLICY_ID, "POLICY-200"}
    assert after[POLICY_ID]["priority"] == controller.policies[POLICY_ID]["priority"] == 600
    assert after["POLICY-200"] == controller.policies["POLICY-200"]
    assert after["POLICY-200"]["switchId"] == "SERIAL_B"

    contexts = list(zip(result["api_paths"], result["api_response"], result["api_result"]))
    for kind, suffix in [("switch", "/switchActions/deploy"), ("policy", "/pushConfig")]:
        requests = deployment_calls(controller, suffix)
        assert len(requests) == 1
        matching = [(path, response, outcome) for path, response, outcome in contexts if suffix in str(path)]
        assert len(matching) == 1
        path, response, outcome = matching[0]
        assert path == response["REQUEST_PATH"] == requests[0][1]
        assert response["METHOD"] == requests[0][0] == "POST"
        assert outcome["success"] is (kind not in errors)
        if kind in errors:
            error = controller.deployment_errors[kind]
            assert response["RETURN_CODE"] == errors[kind]
            assert response["MESSAGE"] == error.msg
            assert response["DATA"] == error.response_payload
            assert outcome["changed"] is False
        else:
            assert response["RETURN_CODE"] == 200
            assert response["MESSAGE"] == "OK"
            assert outcome["changed"] is True
    assert_one_initial_policy_read(controller)
