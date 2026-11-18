# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Controller-owned release defaults affect comparison without entering payloads."""

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_base import (
    FabricBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import (
    FabricAiIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import (
    FabricIbgpModel,
    VxlanIbgpManagementModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ibgp_vxlan import (
    ManageAiIbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ibgp_vxlan import (
    ManageIbgpFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_release_validation import (
    NO_ND_CONTROLLER_DEFAULT,
    ManageFabricReleaseValidationMixin,
    parse_controller_product_version,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import (
    MockAnsibleModule,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import (
    ResponseGenerator,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

FAMILIES = (
    pytest.param(FabricIbgpModel, ManageIbgpFabricOrchestrator, "vxlanIbgp", id="ibgp"),
    pytest.param(
        FabricAiIbgpVxlanModel,
        ManageAiIbgpVxlanFabricOrchestrator,
        "aimlVxlanIbgp",
        id="ai-ibgp",
    ),
)
POLICY_PATH = ("management", "roce_v2")


def _rest(version, state="replaced"):
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(iter(()))
    rest = RestSend({"check_mode": False, "state": state})
    rest.sender = sender
    rest.response_handler = ResponseHandler()
    rest.unit_test = True
    rest.controller_product_version = version
    return rest


def _config(roce=None, policy="User-defined"):
    management = {"bgp_asn": "65001", "aiml_qos_policy": policy}
    if roce is not None:
        management["roce_v2"] = roce
    return {"fabric_name": "fabric1", "management": management}


def _response(fabric_type, roce):
    return {
        "name": "fabric1",
        "category": "fabric",
        "licenseTier": "essentials",
        "management": {
            "type": fabric_type,
            "bgpAsn": "65001",
            "aimlQosPolicy": "User-defined",
            "roceV2": roce,
        },
    }


def _preflight(model, orchestrator, version, state="replaced"):
    orchestrator(rest_send=_rest(version, state)).preflight([model])
    return model


def _run(orchestrator, backend, version, config, state="replaced"):
    class RecordingOrchestrator(orchestrator):
        def query_all(self, **kwargs):
            return [deepcopy(backend["response"])]

        def update(self, model_instance, **kwargs):
            payload = model_instance.to_payload()
            backend["updates"].append(deepcopy(payload))
            backend["response"] = deepcopy(payload)
            if "roceV2" not in backend["response"]["management"]:
                backend["response"]["management"]["roceV2"] = "26" if version in ("4.2.1", "4.2(1)") else "24-31"
            return {}

    module = MockAnsibleModule()
    module.no_log_values = set()
    module.params = {
        "state": state,
        "config": [deepcopy(config)],
        "output_level": "normal",
        "ignore_errors": False,
        "config_actions": {"save": False, "deploy": False},
    }
    machine = NDStateMachine(
        module=module,
        model_orchestrator=RecordingOrchestrator(rest_send=_rest(version, state)),
    )
    machine.manage_state()
    return machine


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize("version,default", (("4.2.1", "26"), ("4.2(1)", "26"), ("4.3.1", "24-31")))
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_controller_default_echo_is_unchanged_without_outbound_default(model, orchestrator, fabric_type, version, default, state):
    """An omitted effective default must not schedule any state-machine update."""
    backend = {"response": _response(fabric_type, default), "updates": []}
    machine = _run(orchestrator, backend, version, _config(), state)
    assert machine.output.format()["changed"] is False
    assert backend["updates"] == []
    proposed = next(iter(machine.proposed))
    assert proposed.management.roce_v2 is None
    assert "roce_v2" not in proposed.management.model_fields_set
    assert "roceV2" not in proposed.to_payload()["management"]
    assert proposed._nd_controller_default_comparisons[POLICY_PATH] == default


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize(
    "version,nondefault,default",
    (("4.2.1", "25", "26"), ("4.3.1", "25", "24-31"), ("4.3.1", "26", "24-31")),
)
@pytest.mark.parametrize("state", ("replaced", "overridden"))
def test_nondefault_omission_resets_once_then_controller_default_is_unchanged(model, orchestrator, fabric_type, version, nondefault, default, state):
    """In particular, 26 is not silently treated as a default on ND4.3."""
    backend = {"response": _response(fabric_type, nondefault), "updates": []}
    assert _run(orchestrator, backend, version, _config(), state).output.format()["changed"] is True
    assert "roceV2" not in backend["updates"][0]["management"]
    assert backend["response"]["management"]["roceV2"] == default
    assert _run(orchestrator, backend, version, _config(), state).output.format()["changed"] is False
    assert len(backend["updates"]) == 1


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize(
    "version,existing,desired",
    (("4.2.1", "26", "25"), ("4.3.1", "24-31", "26"), ("4.3.1", "26", "24-31")),
)
def test_explicit_values_remain_authoritative(model, orchestrator, fabric_type, version, existing, desired):
    """An explicit current default or nondefault follows ordinary value comparison."""
    backend = {"response": _response(fabric_type, existing), "updates": []}
    assert _run(orchestrator, backend, version, _config(desired)).output.format()["changed"] is True
    assert backend["updates"][0]["management"]["roceV2"] == desired
    assert _run(orchestrator, backend, version, _config(desired)).output.format()["changed"] is False
    assert len(backend["updates"]) == 1


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
def test_merged_omission_preserves_nondefault(model, orchestrator, fabric_type):
    """The controller-default policy never changes merged omission semantics."""
    backend = {"response": _response(fabric_type, "26"), "updates": []}
    assert _run(orchestrator, backend, "4.3.1", _config(), "merged").output.format()["changed"] is False
    assert backend["response"]["management"]["roceV2"] == "26"
    assert backend["updates"] == []


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
def test_predefined_policy_never_receives_a_roce_default(model, orchestrator, fabric_type):
    """Controller-default metadata cannot materialize a field in predefined QoS payloads."""
    proposed = _preflight(model.from_config(_config(policy="400G")), orchestrator, "4.3.1")
    existing = model.from_response(_response(fabric_type, "24-31"))
    assert not existing.get_diff(proposed, exclude_unset=False)
    assert proposed.management.roce_v2 is None
    assert "roceV2" not in proposed.to_payload()["management"]
    assert "roce_v2" not in proposed.to_gathered_config()["management"]
    assert "default" not in model.get_argument_spec()["config"]["options"]["management"]["options"]["roce_v2"]


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
def test_comparison_leaves_models_payloads_gathered_and_suppliedness_unchanged(model, orchestrator, fabric_type):
    """Only the ephemeral existing-model comparison view can lose a default echo."""
    existing = model.from_response(_response(fabric_type, "24-31"))
    proposed = _preflight(model.from_config(_config()), orchestrator, "4.3.1")

    def snapshot(item):
        return deepcopy(
            (
                item.to_payload(),
                item.to_gathered_config(),
                item.model_dump(),
                item.model_fields_set,
                item.management.model_fields_set,
            )
        )

    before_existing, before_proposed = snapshot(existing), snapshot(proposed)
    assert existing.get_diff(proposed, exclude_unset=False)
    assert snapshot(existing) == before_existing
    assert snapshot(proposed) == before_proposed
    assert "_nd_controller_default_comparisons" not in str(proposed.to_payload())
    assert "nd_controller_defaults" not in str(proposed.to_gathered_config())


@pytest.mark.parametrize("version", (None, "unknown", "4.3.1.175", "4.1.1"))
def test_unknown_or_unmatched_product_version_does_not_ignore_an_echo(version):
    """Product-version uncertainty and older unmatched releases retain the discrepancy."""
    proposed = _preflight(FabricIbgpModel.from_config(_config()), ManageIbgpFabricOrchestrator, version)
    existing = FabricIbgpModel.from_response(_response("vxlanIbgp", "24-31"))
    assert proposed._nd_controller_default_comparisons == {}
    assert not existing.get_diff(proposed, exclude_unset=False)


def test_private_decisions_are_per_instance_and_cleared_on_repreflight():
    """Changing controller contexts cannot reuse another release's selected default."""
    first = FabricIbgpModel.from_config(_config())
    second = FabricIbgpModel.from_config(_config())
    _preflight(first, ManageIbgpFabricOrchestrator, "4.2.1")
    _preflight(second, ManageIbgpFabricOrchestrator, "4.3.1")
    assert first._nd_controller_default_comparisons[POLICY_PATH] == "26"
    assert second._nd_controller_default_comparisons[POLICY_PATH] == "24-31"
    shallow_copy = first.model_copy()
    _preflight(shallow_copy, ManageIbgpFabricOrchestrator, "4.3.1")
    assert first._nd_controller_default_comparisons[POLICY_PATH] == "26"
    assert shallow_copy._nd_controller_default_comparisons[POLICY_PATH] == "24-31"
    _preflight(first, ManageIbgpFabricOrchestrator, "4.3.1")
    assert first._nd_controller_default_comparisons[POLICY_PATH] == "24-31"
    _preflight(first, ManageIbgpFabricOrchestrator, None)
    assert first._nd_controller_default_comparisons == {}
    assert second._nd_controller_default_comparisons[POLICY_PATH] == "24-31"


def test_newly_supplied_value_overrides_previously_cached_omission():
    """Preparing or editing a proposal after preflight cannot make explicit values ignorable."""
    proposed = _preflight(FabricIbgpModel.from_config(_config()), ManageIbgpFabricOrchestrator, "4.3.1")
    proposed.management.roce_v2 = "26"
    existing = FabricIbgpModel.from_response(_response("vxlanIbgp", "24-31"))
    assert not existing.get_diff(proposed, exclude_unset=False)


@pytest.mark.parametrize(
    "mode,version,existing,explicit,copies",
    (
        ("merged", "4.3.1", "24-31", None, 0),
        ("replaced", "4.3.1", "26", None, 0),
        ("replaced", "4.3.1", "24-31", "24-31", 0),
        ("replaced", None, "24-31", None, 0),
        ("replaced", "4.3.1", "24-31", None, 1),
    ),
)
def test_deep_copy_is_lazy_and_only_used_for_matching_default(monkeypatch, mode, version, existing, explicit, copies):
    """The common merge/nondefault/explicit paths do not copy a full fabric model."""
    proposed = _preflight(
        FabricIbgpModel.from_config(_config(explicit)),
        ManageIbgpFabricOrchestrator,
        version,
        mode,
    )
    current = FabricIbgpModel.from_response(_response("vxlanIbgp", existing))
    original = FabricBaseModel.model_copy
    calls = []

    def recording_copy(self, **kwargs):
        calls.append(kwargs.get("deep", False))
        return original(self, **kwargs)

    monkeypatch.setattr(FabricBaseModel, "model_copy", recording_copy)
    current.get_diff(proposed, exclude_unset=mode == "merged")
    assert calls.count(True) == copies
    assert calls.count(False) == 2  # Root-only views exclude out-of-band source keys.


def _resolve(rules, version, path="management.roce_v2", field=None, extra=None):
    return ManageFabricReleaseValidationMixin._controller_default(
        rules,
        field or VxlanIbgpManagementModel.model_fields["roce_v2"],
        extra or {},
        parse_controller_product_version(version),
        path,
    )


@pytest.mark.parametrize(
    "version,expected",
    (("4.3.1", "base"), ("4.3.1a", "a"), ("4.3.1b", "a"), ("4.4.1", "next")),
)
def test_controller_default_intervals_support_future_lettered_bug_fix_releases(version, expected):
    """Future rule boundaries use the existing product parser and exclusive upper bound."""
    rules = [
        {
            "minimum_version": "4.3.1",
            "maximum_exclusive_version": "4.3.1a",
            "value": "base",
        },
        {
            "minimum_version": "4.3.1a",
            "maximum_exclusive_version": "4.4.1",
            "value": "a",
        },
        {"minimum_version": "4.4.1", "value": "next"},
    ]
    assert _resolve(rules, version) == expected


@pytest.mark.parametrize("value", (False, 0, ""))
def test_false_zero_and_empty_controller_defaults_are_not_treated_as_missing(value):
    assert _resolve([{"minimum_version": "4.2.1", "value": value}], "4.3.1") == value


@pytest.mark.parametrize(
    "rules,message",
    (
        ([], "nonempty list"),
        ({}, "nonempty list"),
        ([None], "contain mappings"),
        ([{"minimum_version": "4.2.1"}], "non-null scalar"),
        ([{"minimum_version": "4.2.1", "value": None}], "non-null scalar"),
        ([{"minimum_version": "4.2.1", "value": {}}], "non-null scalar"),
        ([{"minimum_version": "4.2.1", "value": float("inf")}], "finite"),
        ([{"minimum_version": "4.3.1.175", "value": "x"}], "minimum_version"),
        (
            [{"maximum_exclusive_version": "invalid", "value": "x"}],
            "maximum_exclusive_version",
        ),
        ([{"value": "x"}], "version boundary"),
        (
            [
                {
                    "minimum_version": "4.3.1",
                    "maximum_exclusive_version": "4.2.1",
                    "value": "x",
                }
            ],
            "invalid version interval",
        ),
        (
            [
                {"minimum_version": "4.3.1", "value": "x"},
                {"minimum_version": "4.3.1a", "value": "y"},
            ],
            "Overlapping",
        ),
        (
            [
                {"maximum_exclusive_version": "4.3.1a", "value": "x"},
                {"minimum_version": "4.3.1", "value": "y"},
            ],
            "Overlapping",
        ),
    ),
)
def test_invalid_controller_default_declarations_fail_clearly(rules, message):
    with pytest.raises(ValueError, match=message):
        _resolve(rules, "4.3.1")


@pytest.mark.parametrize(
    "path,field,extra,message",
    (
        ("management.keys[0].value", None, {}, "indexed collection"),
        ("management.roce_v2", None, {"secret": True}, "secret field"),
        (
            "management.ntp_auth_key",
            VxlanIbgpManagementModel.model_fields["ntp_auth_key"],
            {},
            "secret field",
        ),
        (
            "management.fabric_mtu",
            VxlanIbgpManagementModel.model_fields["fabric_mtu"],
            {},
            "nullable default=None",
        ),
    ),
)
def test_unsafe_controller_default_field_scopes_are_rejected(path, field, extra, message):
    with pytest.raises(ValueError, match=message):
        _resolve([{"minimum_version": "4.2.1", "value": "x"}], "4.3.1", path, field, extra)


def test_actual_preflight_validates_metadata_not_only_direct_resolver(monkeypatch):
    field = VxlanIbgpManagementModel.model_fields["roce_v2"]
    monkeypatch.setattr(field, "json_schema_extra", {"nd_controller_defaults": []})
    with pytest.raises(ValueError, match="nonempty list"):
        _preflight(
            FabricIbgpModel.from_config(_config()),
            ManageIbgpFabricOrchestrator,
            "4.3.1",
        )


def test_no_rule_match_returns_a_distinct_missing_sentinel():
    assert _resolve([{"minimum_version": "4.4.1", "value": "x"}], "4.3.1") is NO_ND_CONTROLLER_DEFAULT
