# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Offline regressions for the audited iBGP VXLAN VRF input and output paths."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator
from ansible.module_utils.common.parameters import remove_values

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.config_models import VrfChildConfigModel, VrfConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.vrf_data_models import TrmData, VrfDataModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import StandaloneVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_argument_specs import vrf_parent_argument_spec, vrf_standalone_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import VrfWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrfs import NDVrfOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


def _validated_entry(entry):
    options = {**vrf_parent_argument_spec(), **vrf_standalone_argument_spec()}
    validation = ModuleArgumentSpecValidator({"config": {"type": "list", "elements": "dict", "required": True, "options": options}}).validate(
        {"config": [entry]}
    )
    assert not validation.error_messages
    return validation.validated_parameters["config"][0]


@pytest.mark.parametrize("release", ["4.2.1", "4.3.1"])
@pytest.mark.parametrize("group", ["224.0.0.1", "239.1.1.7/24", "239.1.1.1/32", "224.0.0.0/4"])
def test_ipv4_overlay_group_survives_actual_argspec_prepare_payload_and_gathered_replay(release, group):
    """IPv4 prefix values must survive the complete offline public/wire round trip."""
    public = VrfConfigModel.from_config(_validated_entry({"vrf_name": "BLUE", "trm_enable": True, "overlay_mcast_group": group, "deploy": False}))
    runtime = RestSend({"state": "merged"})
    runtime.controller_product_version = release
    orchestrator = NDVrfOrchestrator(rest_send=runtime, strategy=StandaloneVrfStrategy(fabric_name="FAB", fabric_data={"managementType": "vxlanIbgp"}))
    data = orchestrator.prepare_config_data([public.to_config(exclude_unset=True)])[0]
    wire = VrfDataModel.from_config(data).to_payload()
    assert wire["fabricData"]["trmData"]["v4MulticastGroup"] == group
    gathered = VrfDataModel.from_response(wire).to_gathered_config()
    assert gathered["overlay_mcast_group"] == group
    replay = VrfConfigModel.from_config(_validated_entry(gathered))
    assert replay.overlay_mcast_group == group


@pytest.mark.parametrize("group", ["192.0.2.1/24", "239.1.1.1/3", "ff05::/64", "239.1.1.1/33", "invalid"])
def test_overlay_group_rejects_unicast_wrong_family_and_invalid_or_overbroad_prefixes(group):
    """The supplied IPv4 range must lie wholly within the multicast pool."""
    with pytest.raises(ValidationError):
        VrfConfigModel.from_config({"vrf_name": "BLUE", "trm_enable": True, "overlay_mcast_group": group})
    with pytest.raises(ValidationError):
        TrmData(v4MulticastGroup=group)


def test_overlay_prefix_support_does_not_broaden_underlay_host_address_input():
    """Underlay multicast and RP fields remain address inputs."""
    with pytest.raises(ValidationError):
        VrfConfigModel.from_config({"vrf_name": "BLUE", "trm_enable": True, "underlay_mcast_ip": "239.1.1.0/24"})
    with pytest.raises(ValidationError):
        TrmData(l3VniMulticastGroup="239.1.1.0/24")
    child = VrfChildConfigModel.from_config({"fabric_name": "CHILD", "trm_enable": True, "overlay_mcast_group": "239.1.1.0/24"})
    assert child.overlay_mcast_group == "239.1.1.0/24"


@pytest.mark.parametrize("section", ["fabric_data", "fabricData"])
def test_controller_password_is_registered_for_no_log_when_user_omits_password(monkeypatch, section):
    """Existing opaque BGP values must reach the real state-machine scrubber."""
    secret = "synthetic-controller-ciphertext-value"
    observed = {"fabricName": "FAB", "vrfName": "BLUE", "vrfType": "vxlanIbgp", "fabricData": {"bgpPassword": secret}}
    model = VrfDataModel.from_response(observed)
    assert secret in model.collect_replacement_secret_values()
    assert VrfDataModel.collect_secret_values({section: {"bgpPassword": secret}}) == {secret}
    assert VrfDataModel.collect_secret_values({"bgp_password": secret}) == {secret}

    monkeypatch.setattr(NDVrfOrchestrator, "_request", lambda *_args, **_kwargs: {"vrfs": [observed]})
    strategy = StandaloneVrfStrategy(fabric_name="FAB", fabric_data={"managementType": "vxlanIbgp"})
    module = SimpleNamespace(
        params={"fabric_name": "FAB", "state": "gathered", "config": [], "output_level": "normal"},
        no_log_values=set(),
        check_mode=False,
        _verbosity=0,
    )
    coordinator = VrfWorkflowCoordinator(module, strategy)
    sm, original_config, original_state = coordinator._new_state_machine(dict(module.params))
    try:
        assert secret in module.no_log_values
        output = {"gathered": model.to_gathered_config(), "workflow_trace": [{"payload": observed}]}
        scrubbed = remove_values(output, module.no_log_values)
        assert secret not in str(scrubbed)
        assert secret in model.to_payload()["fabricData"]["bgpPassword"]
        assert sm.existing.get(("BLUE", "FAB")) is not None
    finally:
        coordinator._restore_state_machine_params(original_config, original_state)
