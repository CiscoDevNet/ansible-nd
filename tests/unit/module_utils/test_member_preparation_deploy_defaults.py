# Copyright: (c) 2026, Cisco Systems, Inc.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Honor deployment defaults through real public-workflow argument parsing."""

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.modules import nd_interfaces_workflow
from ansible_collections.cisco.nd.tests.unit.module_utils.member_review_fakes import Controller, explicit_request, run_module, wire


class PreProvisionedController(Controller):
    """Serve configured switch identities while their physical hardware is absent."""

    def _switches(self):
        rows = super()._switches()
        for row in rows:
            row["isPreProvisioned"] = True
            row["status"] = "offline"
            row["additionalData"]["discoveryStatus"] = "notReachable"
        return rows


def _controller(kind, pre_provisioned=False):
    controller = PreProvisionedController() if pre_provisioned else Controller()
    if kind == "host_conversion":
        controller.rows["S1"]["ethernet1/10"] = wire("Ethernet1/10", "accessHost", mode="access", accessVlan=100)
    return controller


def _request(option, *, check_mode=False):
    params = explicit_request()
    if option == "omitted":
        del params["config_actions"]
    elif option == "empty":
        params["config_actions"] = {}
    else:
        params["config_actions"] = {"deploy": option == "true"}
    if check_mode:
        params["_ansible_check_mode"] = True
    return params


def _invoke(monkeypatch, params, controller):
    """Capture normalized arguments without replacing their Ansible validation."""
    parsed = []
    original_module = nd_interfaces_workflow.AnsibleModule

    def capture(*args, **kwargs):
        module = original_module(*args, **kwargs)
        parsed.append(deepcopy(module.params.get("config_actions")))
        return module

    with monkeypatch.context() as scoped:
        scoped.setattr(nd_interfaces_workflow, "AnsibleModule", capture)
        outcome = run_module(scoped, params, controller)
    assert len(parsed) == 1
    return outcome, parsed[0]


def _assert_member_ownership(result):
    proof = result["member_verifications"]
    assert proof["observed"] is True
    assert proof["complete"] is True
    assert proof["request_sha256"] == result["workflow_contract"]["request_sha256"]
    assert [(row["switch_id"], row["interface_name"], row["owner_switch_id"], row["parent_interface_name"]) for row in proof["members"]] == [
        ("S1", "Ethernet1/10", "S1", "port-channel10")
    ]


@pytest.mark.parametrize("kind", ["missing_inventory", "host_conversion"])
@pytest.mark.parametrize("pre_provisioned", [False, True], ids=["physical", "pre-provisioned"])
def test_public_preparation_omitted_empty_and_false_have_identical_effects(monkeypatch, kind, pre_provisioned):
    reference = None
    for option in ("false", "empty", "omitted"):
        controller = _controller(kind, pre_provisioned)
        outcome, parsed = _invoke(monkeypatch, _request(option), controller)

        assert parsed == (None if option == "omitted" else {"deploy": False})
        assert outcome.failed is False, outcome.result.get("msg")
        assert outcome.result["changed"] is True
        assert len(controller.writes) == 2
        assert all("/interfaces" in call["path"] for call in controller.writes)
        _assert_member_ownership(outcome.result)
        actual = (outcome.result, controller.calls, controller.rows)
        if reference is None:
            reference = deepcopy(actual)
        else:
            assert actual == reference


@pytest.mark.parametrize("kind", ["missing_inventory", "host_conversion"])
def test_public_preparation_still_rejects_explicit_deployment_before_writes(monkeypatch, kind):
    controller = _controller(kind)
    before = deepcopy(controller.rows)

    outcome, parsed = _invoke(monkeypatch, _request("true"), controller)

    assert parsed == {"deploy": True}
    assert outcome.failed is True
    assert outcome.result["msg"] == "Explicit member preparation requires config_actions.deploy=false"
    assert controller.writes == []
    assert controller.rows == before


@pytest.mark.parametrize("kind", ["missing_inventory", "host_conversion"])
def test_public_preparation_still_requires_ownership_verification(monkeypatch, kind):
    controller = _controller(kind)
    before = deepcopy(controller.rows)
    params = _request("false")
    params["verify"] = {"enabled": False}

    outcome, parsed = _invoke(monkeypatch, params, controller)

    assert parsed == {"deploy": False}
    assert outcome.failed is True
    assert outcome.result["msg"] == "Explicit member preparation requires verify.enabled=true"
    assert controller.writes == []
    assert controller.rows == before


@pytest.mark.parametrize("kind", ["missing_inventory", "host_conversion"])
def test_public_check_mode_omitted_deployment_matches_explicit_false(monkeypatch, kind):
    reference = None
    for option in ("false", "omitted"):
        controller = _controller(kind)
        before = deepcopy(controller.rows)

        outcome, parsed = _invoke(monkeypatch, _request(option, check_mode=True), controller)

        assert parsed == (None if option == "omitted" else {"deploy": False})
        assert outcome.failed is False, outcome.result.get("msg")
        assert outcome.result["changed"] is True
        assert outcome.result["planned_changed"] is True
        assert outcome.result["mutation_count"] > 0
        assert "member_verifications" not in outcome.result
        assert controller.writes == []
        assert controller.rows == before
        if reference is None:
            reference = deepcopy(outcome.result)
        else:
            assert outcome.result == reference


@pytest.mark.parametrize("pre_provisioned", [False, True], ids=["physical", "pre-provisioned"])
def test_public_ready_member_replay_accepts_omission_without_mutation(monkeypatch, pre_provisioned):
    controller = _controller("missing_inventory", pre_provisioned)
    seeded, _parsed = _invoke(monkeypatch, _request("false"), controller)
    assert seeded.failed is False, seeded.result.get("msg")
    before = deepcopy(controller.rows)
    controller.calls.clear()

    outcome, parsed = _invoke(monkeypatch, _request("omitted"), controller)

    assert parsed is None
    assert outcome.failed is False, outcome.result.get("msg")
    assert outcome.result["changed"] is False
    assert outcome.result["mutation_count"] == 0
    _assert_member_ownership(outcome.result)
    assert controller.writes == []
    assert controller.rows == before
