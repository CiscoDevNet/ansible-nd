# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Release and state regressions for observed iBGP NTP default echoes."""

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import (
    FabricAiIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import (
    FabricIbgpModel,
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
NTP_DEFAULTS = (
    ("ntp_auth_key_id", "ntpAuthKeyId", 1),
    ("ntp_auth_key_type", "ntpAuthKeyType", "7"),
)


def _rest_send(version: str, state: str) -> RestSend:
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(iter(()))
    rest = RestSend({"check_mode": False, "state": state})
    rest.sender = sender
    rest.response_handler = ResponseHandler()
    rest.unit_test = True
    rest.controller_product_version = version
    return rest


def _response(fabric_type: str, ntp: dict | None = None) -> dict:
    return {
        "name": "fabric1",
        "category": "fabric",
        "licenseTier": "essentials",
        "management": {"type": fabric_type, "bgpAsn": "65001", **(ntp or {})},
    }


def _machine(orchestrator_class, response: dict, state: str, management: dict | None = None):
    class RecordingOrchestrator(orchestrator_class):
        def model_post_init(self, __context) -> None:
            super().model_post_init(__context)
            self._updates: list[dict] = []

        def query_all(self, **kwargs):
            return [deepcopy(response)]

        def update(self, model_instance, **kwargs):
            self._updates.append(model_instance.to_payload())
            return {}

    module = MockAnsibleModule()
    module.check_mode = False
    module.no_log_values = set()
    module.params = {
        "state": state,
        "config": [
            {
                "fabric_name": "fabric1",
                "management": {"bgp_asn": "65001", **(management or {})},
            }
        ],
        "ignore_errors": False,
        "output_level": "normal",
        "config_actions": {"save": False, "deploy": False},
    }
    orchestrator = RecordingOrchestrator(rest_send=_rest_send("4.3.1", state))
    machine = NDStateMachine(module=module, model_orchestrator=orchestrator)
    machine.manage_state()
    return machine, orchestrator._updates


@pytest.mark.parametrize(("model_class", "orchestrator_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize("version", ("4.2.1", "4.2(1)"))
def test_ntp_model_defaults_are_omitted_before_their_release(model_class, orchestrator_class, fabric_type, version):
    """Omitted 4.3 NTP defaults never enter 4.2 payloads or Ansible input defaults."""
    model = model_class.from_config({"fabric_name": "fabric1", "management": {"bgp_asn": "65001"}})
    orchestrator_class(rest_send=_rest_send(version, "replaced")).preflight([model])
    payload = model.to_payload()["management"]
    argspec = model_class.get_argument_spec()["config"]["options"]["management"]["options"]
    for name, alias, _ in NTP_DEFAULTS:
        assert alias not in payload
        assert name not in model.management.model_fields_set
        assert "default" not in argspec[name]


@pytest.mark.parametrize(("model_class", "orchestrator_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize("version", ("4.2.1", "4.2(1)"))
@pytest.mark.parametrize(("name", "alias", "value"), NTP_DEFAULTS)
def test_explicit_ntp_default_is_still_rejected_before_its_release(model_class, orchestrator_class, fabric_type, version, name, alias, value):
    """A supplied value equal to the model default must not evade the release gate."""
    model = model_class.from_config({"fabric_name": "fabric1", "management": {"bgp_asn": "65001", name: value}})
    with pytest.raises(RuntimeError, match=rf"management\.{name}.*requires ND 4\.3\.1"):
        orchestrator_class(rest_send=_rest_send(version, "merged")).preflight([model])


@pytest.mark.parametrize(("model_class", "orchestrator_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
@pytest.mark.parametrize(
    "echoed",
    (
        {"ntpAuthKeyId": 1},
        {"ntpAuthKeyType": "7"},
        {"ntpAuthKeyId": 1, "ntpAuthKeyType": "7"},
    ),
)
def test_controller_ntp_default_echo_does_not_cause_repeated_updates(model_class, orchestrator_class, fabric_type, state, echoed):
    """Each observed default echo and their combination compare unchanged."""
    machine, updates = _machine(orchestrator_class, _response(fabric_type, echoed), state)
    assert updates == []
    assert machine.output.format()["changed"] is False


@pytest.mark.parametrize(("model_class", "orchestrator_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_omitted_ntp_values_preserve_merge_and_reset_exact_states(model_class, orchestrator_class, fabric_type, state):
    """Nondefault NTP configuration remains visible to the normal state semantics."""
    existing = _response(fabric_type, {"ntpAuthEnable": True, "ntpAuthKeyId": 17, "ntpAuthKeyType": "6"})
    machine, updates = _machine(orchestrator_class, existing, state)
    assert machine.output.format()["changed"] is (state != "merged")
    if state == "merged":
        assert updates == []
        current = machine.existing.get("fabric1").to_payload()["management"]
        assert current["ntpAuthKeyId"] == 17
        assert current["ntpAuthKeyType"] == "6"
    else:
        assert len(updates) == 1
        assert updates[0]["management"]["ntpAuthKeyId"] == 1
        assert updates[0]["management"]["ntpAuthKeyType"] == "7"


@pytest.mark.parametrize(("model_class", "orchestrator_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_explicit_ntp_nondefaults_change_once_and_reapply_unchanged(model_class, orchestrator_class, fabric_type, state):
    """Concrete defaults do not suppress explicit nondefault changes or comparisons."""
    desired = {"ntp_auth_enable": True, "ntp_auth_key_id": 17, "ntp_auth_key_type": "6"}
    machine, updates = _machine(
        orchestrator_class,
        _response(fabric_type, {"ntpAuthKeyId": 1, "ntpAuthKeyType": "7"}),
        state,
        desired,
    )
    assert machine.output.format()["changed"] is True
    assert len(updates) == 1
    assert updates[0]["management"]["ntpAuthKeyId"] == 17
    assert updates[0]["management"]["ntpAuthKeyType"] == "6"
    reapplied, subsequent_updates = _machine(orchestrator_class, updates[0], state, desired)
    assert subsequent_updates == []
    assert reapplied.output.format()["changed"] is False


@pytest.mark.parametrize(("model_class", "orchestrator_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize("construction", ("from_config", "direct_validation"))
@pytest.mark.parametrize(
    ("key_type", "length", "accepted", "maximum"),
    (
        (None, 32, True, 32),
        (None, 33, False, 32),
        ("7", 32, True, 32),
        ("7", 33, False, 32),
        ("6", 128, True, 128),
        ("6", 129, False, 128),
    ),
    ids=(
        "default7-max",
        "default7-over",
        "type7-max",
        "type7-over",
        "type6-max",
        "type6-over",
    ),
)
def test_ntp_key_input_bounds_follow_the_selected_key_type(
    model_class,
    orchestrator_class,
    fabric_type,
    construction,
    key_type,
    length,
    accepted,
    maximum,
):
    """API prose limits type-7 input to 32 characters and type-6 input to 128."""
    management = {"bgp_asn": "65001", "ntp_auth_key": "K" * length}
    if key_type is not None:
        management["ntp_auth_key_type"] = key_type
    config = {"fabric_name": "fabric1", "management": management}
    construct = model_class.from_config if construction == "from_config" else model_class.model_validate
    if not accepted:
        with pytest.raises(ValueError, match=rf"ntp_auth_key must contain at most {maximum} characters"):
            construct(config)
        return
    model = construct(config)
    assert model.management.ntp_auth_key_type == (key_type or "7")
    assert len(model.management.ntp_auth_key.get_secret_value()) == length
    orchestrator_class(rest_send=_rest_send("4.3.1", "merged")).preflight([model])
    assert len(model.to_payload()["management"]["ntpAuthKey"]) == length


@pytest.mark.parametrize(("model_class", "orchestrator_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize("construction", ("from_response", "response_context"))
def test_ntp_returned_ciphertext_is_not_checked_as_type7_plaintext(model_class, orchestrator_class, fabric_type, construction):
    """A response representation longer than 32 characters remains readable and preservable."""
    ciphertext = "C" * 64
    response = _response(fabric_type, {"ntpAuthKey": ciphertext, "ntpAuthKeyType": "7"})
    model = (
        model_class.from_response(response)
        if construction == "from_response"
        else model_class.model_validate(response, context={"mode": "response", "source": "response"})
    )
    # Full fabric parsing propagates management.name through assignment after
    # response validation, where Pydantic no longer carries response context.
    assert model.management.name == "fabric1"
    model.management.performance_monitoring = True
    assert model.management.ntp_auth_key.get_secret_value() == ciphertext
    assert model.to_payload()["management"]["ntpAuthKey"] == ciphertext
    assert model.to_config()["management"]["ntp_auth_key"] != ciphertext


@pytest.mark.parametrize(("model_class", "orchestrator_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize(("key_type", "length"), (("7", 32), ("6", 128)))
def test_ntp_key_input_bounds_do_not_replace_the_release_gate(model_class, orchestrator_class, fabric_type, key_type, length):
    """An otherwise valid NTP key remains unsupported on an older controller."""
    model = model_class.from_config(
        {
            "fabric_name": "fabric1",
            "management": {
                "bgp_asn": "65001",
                "ntp_auth_key": "K" * length,
                "ntp_auth_key_type": key_type,
            },
        }
    )
    with pytest.raises(RuntimeError, match=r"ntp_auth_key.*requires ND 4\.3\.1"):
        orchestrator_class(rest_send=_rest_send("4.2.1", "merged")).preflight([model])


@pytest.mark.parametrize(("model_class", "orchestrator_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize("explicit_type", (False, True), ids=("inherit-type6", "change-type7-to6"))
def test_real_merged_ntp_key_update_uses_the_final_type_pair(model_class, orchestrator_class, fabric_type, explicit_type):
    """Partial updates inherit type6 and explicit pair changes ignore assignment order."""
    response = _response(
        fabric_type,
        {"ntpAuthKey": "C" * 16, "ntpAuthKeyType": "7" if explicit_type else "6"},
    )
    management = {"ntp_auth_key": "K" * 64, "performance_monitoring": True}
    if explicit_type:
        management["ntp_auth_key_type"] = "6"
    machine, updates = _machine(orchestrator_class, response, "merged", management)
    assert machine.output.format()["changed"] is True
    assert len(updates) == 1
    assert updates[0]["management"]["ntpAuthKeyType"] == "6"
    assert updates[0]["management"]["ntpAuthKey"] == "K" * 64
    proposed = machine.proposed.get("fabric1").management
    assert ("ntp_auth_key_type" in proposed.model_fields_set) is explicit_type


@pytest.mark.parametrize(("model_class", "orchestrator_class", "fabric_type"), FAMILIES)
def test_real_unrelated_merge_does_not_revalidate_returned_ciphertext_as_input(model_class, orchestrator_class, fabric_type):
    """An unrelated PUT preserves a long response representation without a new input check."""
    response = _response(fabric_type, {"ntpAuthKey": "C" * 64, "ntpAuthKeyType": "7"})
    machine, updates = _machine(orchestrator_class, response, "merged", {"performance_monitoring": True})
    assert machine.output.format()["changed"] is True
    assert len(updates) == 1
    assert updates[0]["management"]["ntpAuthKey"] == "C" * 64


@pytest.mark.parametrize(("model_class", "orchestrator_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize("state", ("replaced", "overridden"))
def test_exact_ntp_input_omission_uses_default_type7_for_its_limit(model_class, orchestrator_class, fabric_type, state):
    """Exact-state input has a known default counterpart and rejects an overlong type7 key."""
    with pytest.raises(ValueError, match="at most 32 characters"):
        model_class.from_config(
            {
                "fabric_name": "fabric1",
                "management": {"bgp_asn": "65001", "ntp_auth_key": "K" * 33},
            },
            context={"state": state},
        )


@pytest.mark.parametrize(("model_class", "orchestrator_class", "fabric_type"), FAMILIES)
@pytest.mark.parametrize(("key_type", "length", "maximum"), (("7", 33, 32), ("6", 129, 128)))
def test_merged_explicit_ntp_pair_still_enforces_its_bound(model_class, orchestrator_class, fabric_type, key_type, length, maximum):
    """Explicit merged pairs remain fully checkable before any state or API operation."""
    with pytest.raises(ValueError, match=f"at most {maximum} characters"):
        model_class.from_config(
            {
                "fabric_name": "fabric1",
                "management": {
                    "bgp_asn": "65001",
                    "ntp_auth_key": "K" * length,
                    "ntp_auth_key_type": key_type,
                },
            },
            context={"state": "merged"},
        )


@pytest.mark.parametrize(("model_class", "orchestrator_class", "fabric_type"), FAMILIES)
def test_merged_type_omission_defers_the_implicit_create_pair_to_the_api(model_class, orchestrator_class, fabric_type):
    """Construction cannot identify implicit creates; omitted merged type is API-validated there."""
    model = model_class.from_config(
        {
            "fabric_name": "fabric1",
            "management": {"bgp_asn": "65001", "ntp_auth_key": "K" * 64},
        },
        context={"state": "merged"},
    )
    orchestrator = orchestrator_class(rest_send=_rest_send("4.3.1", "merged"))
    orchestrator.preflight_create([model])
    orchestrator.preflight([model])
    assert "ntp_auth_key_type" not in model.management.model_fields_set
    assert model.management.ntp_auth_key_type == "7"
    assert len(model.to_payload()["management"]["ntpAuthKey"]) == 64
    # The same partial-input exception must not relax the generic absolute cap.
    with pytest.raises(ValueError, match="at most 128 characters"):
        model_class.from_config(
            {
                "fabric_name": "fabric1",
                "management": {"bgp_asn": "65001", "ntp_auth_key": "K" * 129},
            },
            context={"state": "merged"},
        )
